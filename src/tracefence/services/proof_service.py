from __future__ import annotations

import asyncio
import threading
import time
from collections import Counter
from concurrent.futures import Future
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from tracefence.config import settings
from tracefence.db.models import (
    ActionAttempt,
    ActionCommandMatch,
    CommandAcknowledgement,
    ControlCommand,
    Node,
    Run,
    ServiceState,
)
from tracefence.domain.enums import (
    ActionDecision,
    CommandType,
    NodeStatus,
    ProofVerdict,
)
from tracefence.domain.errors import NotFoundError
from tracefence.domain.schemas import ProofResponse, ReplacementManifest
from tracefence.security import payload_digest
from tracefence.services.action_gateway import STALE_REASONS
from tracefence.services.common import descendants_including_self, evaluate_scopes, utcnow
from tracefence.services.invariant_service import InvariantService
from tracefence.signoz.mcp_client import (
    RuntimeBlockedAction,
    SigNozMCPClient,
    TelemetryVerificationContext,
)
from tracefence.telemetry.instruments import telemetry
from tracefence.telemetry.setup import (
    force_flush_telemetry,
    telemetry_export_context,
    telemetry_export_watermark,
    telemetry_process_identity,
)

_MAX_PROOF_STABILITY_ATTEMPTS = 3
_VERDICT_SEVERITY = (
    ProofVerdict.INCONSISTENT,
    ProofVerdict.STATE_CHANGED_DURING_PROOF,
    ProofVerdict.INCOMPLETE,
    ProofVerdict.PARTIAL,
    ProofVerdict.UNAVAILABLE,
    ProofVerdict.VERIFIED,
)


def combine_proof_verdicts(*verdicts: ProofVerdict) -> ProofVerdict:
    """Combine proof dimensions using the one authoritative severity lattice.

    Contradictory evidence is INCONSISTENT. A proof that could not observe one
    stable authoritative revision is STATE_CHANGED_DURING_PROOF. INCOMPLETE
    means required runtime evidence is missing; PARTIAL means available
    evidence verified only part of the contract; UNAVAILABLE means a mandatory
    evidence provider could not be consulted. VERIFIED is possible only when
    every applicable mandatory dimension is VERIFIED. NOT_APPLICABLE
    dimensions are ignored unless every dimension is NOT_APPLICABLE.
    """

    applicable = [
        verdict for verdict in verdicts if verdict != ProofVerdict.NOT_APPLICABLE
    ]
    if not applicable:
        return ProofVerdict.NOT_APPLICABLE
    return min(applicable, key=_VERDICT_SEVERITY.index)


@dataclass(frozen=True, slots=True)
class _ProofContext:
    run_id: str
    revision: int
    nearest_lease_expiry: datetime | None


@dataclass(frozen=True, slots=True)
class _CacheKey:
    command_id: str
    revision: int
    export_watermark: str
    nearest_lease_expiry: datetime | None


@dataclass(slots=True)
class _CacheEntry:
    expires_at: float
    response: ProofResponse


class ProofService:
    def __init__(
        self,
        session_factory: sessionmaker,
        mcp_client: SigNozMCPClient | None = None,
    ) -> None:
        self.session_factory = session_factory
        self.mcp_client = mcp_client or SigNozMCPClient()
        self._cache: dict[_CacheKey, _CacheEntry] = {}
        self._state_lock = threading.RLock()
        self._inflight: dict[str, Future[ProofResponse]] = {}
        self.invariants = InvariantService(session_factory)

    async def build(self, command_id: str) -> ProofResponse:
        """Build a loop-independent, single-flight proof for one command.

        API requests execute on a bounded worker pool, so the same singleton
        service may be called from different event loops. A concurrent Future is
        safe to coordinate across those loops: one caller builds while all other
        callers await the identical immutable result.
        """
        initial_context = self._current_context(command_id)
        initial_watermark = telemetry_export_watermark()
        initial_key = (
            self._cache_key(command_id, initial_context, initial_watermark)
            if initial_watermark is not None
            else None
        )
        now_mono = time.monotonic()
        with self._state_lock:
            self._prune_cache_locked(now_mono)
            for key in [
                key
                for key in self._cache
                if key.command_id == command_id and key != initial_key
            ]:
                self._cache.pop(key, None)
            cached = self._cache.get(initial_key) if initial_key is not None else None
            if cached is not None and cached.expires_at > now_mono:
                return cached.response.model_copy(deep=True)

            inflight = self._inflight.get(command_id)
            if inflight is None:
                inflight = Future()
                self._inflight[command_id] = inflight
                owner = True
            else:
                owner = False

        if not owner:
            response = await asyncio.shield(asyncio.wrap_future(inflight))
            return response.model_copy(deep=True)

        try:
            last_response: ProofResponse | None = None
            for _attempt in range(_MAX_PROOF_STABILITY_ATTEMPTS):
                response, context = await self._build_uncached(command_id)
                last_response = response
                if self._read_revision(context.run_id) != context.revision:
                    continue

                watermark = telemetry_export_watermark()
                expires_at = self._cache_expiry(context.nearest_lease_expiry)
                stored = response.model_copy(deep=True)
                with self._state_lock:
                    if watermark is not None and expires_at > time.monotonic():
                        key = self._cache_key(command_id, context, watermark)
                        self._cache[key] = _CacheEntry(
                            expires_at=expires_at,
                            response=stored,
                        )
                    self._inflight.pop(command_id, None)
                    if not inflight.done():
                        inflight.set_result(stored.model_copy(deep=True))
                return response

            if last_response is None:
                raise RuntimeError("Proof stability loop did not execute")
            unstable = last_response.model_copy(
                update={
                    "runtime_verdict": ProofVerdict.STATE_CHANGED_DURING_PROOF,
                    "overall_verdict": ProofVerdict.STATE_CHANGED_DURING_PROOF,
                    "discrepancies": [
                        *last_response.discrepancies,
                        "STATE_CHANGED_DURING_PROOF",
                    ],
                }
            )
            stored = unstable.model_copy(deep=True)
            with self._state_lock:
                self._inflight.pop(command_id, None)
                if not inflight.done():
                    inflight.set_result(stored.model_copy(deep=True))
            return unstable
        except BaseException as exc:
            with self._state_lock:
                self._inflight.pop(command_id, None)
                if not inflight.done():
                    inflight.set_exception(exc)
            raise

    def _prune_cache_locked(self, now_mono: float) -> None:
        for key in [
            key for key, entry in self._cache.items() if entry.expires_at <= now_mono
        ]:
            self._cache.pop(key, None)

    def _current_context(self, command_id: str) -> _ProofContext:
        with self.session_factory() as session:
            command = session.get(ControlCommand, command_id)
            if command is None:
                raise NotFoundError(f"Command {command_id} was not found")
            run = session.get(Run, command.run_id)
            if run is None:
                raise NotFoundError(f"Run {command.run_id} was not found")
            now = utcnow()
            lease_expiries = session.execute(
                select(Node.lease_expires_at).where(
                    Node.run_id == run.id,
                    Node.lease_expires_at.is_not(None),
                    Node.lease_expires_at > now,
                )
            ).scalars()
            return _ProofContext(
                run_id=run.id,
                revision=run.proof_revision,
                nearest_lease_expiry=min(lease_expiries, default=None),
            )

    def _read_revision(self, run_id: str) -> int:
        with self.session_factory() as session:
            revision = session.scalar(
                select(Run.proof_revision).where(Run.id == run_id)
            )
            if revision is None:
                raise NotFoundError(f"Run {run_id} was not found")
            return int(revision)

    @staticmethod
    def _cache_key(
        command_id: str,
        context: _ProofContext,
        watermark: str,
    ) -> _CacheKey:
        return _CacheKey(
            command_id=command_id,
            revision=context.revision,
            export_watermark=watermark,
            nearest_lease_expiry=context.nearest_lease_expiry,
        )

    @staticmethod
    def _cache_expiry(nearest_lease_expiry: datetime | None) -> float:
        ttl = float(settings.proof_cache_seconds)
        if nearest_lease_expiry is not None:
            ttl = min(
                ttl,
                max(0.0, (nearest_lease_expiry - utcnow()).total_seconds()),
            )
        return time.monotonic() + max(0.0, ttl)

    async def _build_uncached(
        self,
        command_id: str,
    ) -> tuple[ProofResponse, _ProofContext]:
        started = time.perf_counter()
        discrepancies: list[str] = []

        with self.session_factory() as session:
            command = session.get(ControlCommand, command_id)
            if command is None:
                raise NotFoundError(f"Command {command_id} was not found")
            run = session.get(Run, command.run_id)
            if run is None:
                raise NotFoundError(f"Run {command.run_id} was not found")
            proof_revision = run.proof_revision
            target = session.get(Node, command.target_node_id)
            if target is None:
                raise NotFoundError("Command target node was not found")

            if command.command_type == CommandType.CANCEL_RUN:
                affected = session.execute(
                    select(Node).where(
                        Node.run_id == command.run_id,
                        Node.registered_at <= command.created_at,
                    )
                ).scalars().all()
            else:
                affected = await descendants_including_self(
                    session,
                    run_id=command.run_id,
                    root_node_id=target.id,
                    registered_before=command.created_at,
                )
            affected_ids = {node.id for node in affected}

            acknowledgements = session.execute(
                select(CommandAcknowledgement).where(
                    CommandAcknowledgement.command_id == command.id
                )
            ).scalars().all()
            ack_by_node: dict[str, list[str]] = {}
            for ack in acknowledgements:
                ack_by_node.setdefault(ack.node_id, []).append(ack.ack_type)

            prior_ack_nodes = set(
                session.execute(
                    select(CommandAcknowledgement.node_id).where(
                        CommandAcknowledgement.run_id == command.run_id,
                        CommandAcknowledgement.node_id.in_(affected_ids),
                        CommandAcknowledgement.observed_at <= command.created_at,
                        CommandAcknowledgement.command_id != command.id,
                    )
                ).scalars().all()
            ) if affected_ids else set()
            matched_action_ids = set(
                session.execute(
                    select(ActionCommandMatch.action_id).where(
                        ActionCommandMatch.run_id == command.run_id,
                        ActionCommandMatch.command_id == command.id,
                    )
                ).scalars().all()
            )

            actions = []
            if affected_ids:
                actions = session.execute(
                    select(ActionAttempt).where(
                        ActionAttempt.node_id.in_(affected_ids),
                        ActionAttempt.attempted_at >= command.created_at,
                    )
                ).scalars().all()
            actions_by_node: dict[str, list[ActionAttempt]] = {}
            for action in actions:
                actions_by_node.setdefault(action.node_id, []).append(action)

            classifications: Counter[str] = Counter()
            unclassified: list[str] = []
            now = utcnow()
            for node in affected:
                node_acks = ack_by_node.get(node.id, [])
                node_actions = actions_by_node.get(node.id, [])
                if node.completed_at is not None and node.completed_at <= command.created_at:
                    classifications["COMPLETED_BEFORE_COMMAND"] += 1
                elif node.id in prior_ack_nodes and node.status in {
                    NodeStatus.CANCELLED,
                    NodeStatus.SUPERSEDED,
                    NodeStatus.LEASE_EXPIRED,
                    NodeStatus.COMPLETED,
                }:
                    classifications["CONVERGED_BEFORE_COMMAND"] += 1
                elif "COOPERATIVE" in node_acks:
                    classifications["ACKNOWLEDGED"] += 1
                elif "GATEWAY_BLOCK" in node_acks or any(
                    action.decision == ActionDecision.DENY
                    and action.denial_reason in STALE_REASONS
                    and action.id in matched_action_ids
                    for action in node_actions
                ):
                    classifications["BLOCKED_AT_GATEWAY"] += 1
                elif "LEASE_EXPIRED" in node_acks or node.status == NodeStatus.LEASE_EXPIRED or (
                    node.lease_expires_at is not None and node.lease_expires_at <= now
                ):
                    classifications["LEASE_EXPIRED"] += 1
                else:
                    evaluation = await evaluate_scopes(session, node)
                    # An affected node cannot legitimately remain scope-valid after
                    # the command. Treat that impossible state as unclassified so a
                    # corrupted registry can never yield a VERIFIED proof.
                    if evaluation.allowed:
                        discrepancies.append(
                            f"Affected node {node.id} remained scope-valid after command"
                        )
                    unclassified.append(node.id)

            stale_attempts = sum(
                1
                for action in actions
                if action.side_effecting
                and action.decision == ActionDecision.DENY
                and action.denial_reason in STALE_REASONS
                and action.id in matched_action_ids
            )
            stale_committed_actions = [
                action
                for action in actions
                if action.side_effecting
                and action.decision == ActionDecision.ALLOW
                and action.committed_at is not None
            ]
            stale_committed = len(stale_committed_actions)
            runtime_blocked_actions = tuple(
                RuntimeBlockedAction(
                    action_id=action.id,
                    node_id=action.node_id,
                    target_scope_id=action.matched_scope_id or "",
                    snapshot_version=action.matched_snapshot_version or 0,
                    live_version=action.matched_live_version or 0,
                    live_status=action.matched_live_status or "",
                    denial_reason=action.denial_reason or "",
                )
                for action in actions
                if action.side_effecting
                and action.decision == ActionDecision.DENY
                and action.denial_reason in STALE_REASONS
                and action.id in matched_action_ids
            )

            all_nodes = session.execute(
                select(Node).where(Node.run_id == command.run_id)
            ).scalars().all()
            nearest_lease_expiry = min(
                (
                    node.lease_expires_at
                    for node in all_nodes
                    if node.lease_expires_at is not None
                    and node.lease_expires_at > now
                ),
                default=None,
            )
            unrelated_interrupted = 0
            if command.command_type != CommandType.CANCEL_RUN:
                for node in all_nodes:
                    if node.id in affected_ids:
                        continue
                    evaluation = await evaluate_scopes(session, node)
                    if not evaluation.allowed and any(
                        mismatch.scope_id == command.target_scope_id
                        for mismatch in evaluation.mismatches
                    ):
                        unrelated_interrupted += 1

            (
                replacement_verdict,
                recovery_action_verdict,
                recovery_postcondition_verdict,
                recovery_stability_verdict,
            ) = await self._replacement_verdicts(
                session, command, target, discrepancies
            )
            recovery_verdict = self._combine_recovery_verdicts(
                recovery_action_verdict,
                recovery_postcondition_verdict,
                recovery_stability_verdict,
            )

        await self.invariants.scan(command.run_id)

        if stale_committed > 0:
            control_verdict = ProofVerdict.INCONSISTENT
        elif unclassified or unrelated_interrupted > 0:
            control_verdict = ProofVerdict.INCOMPLETE
        else:
            control_verdict = ProofVerdict.VERIFIED
        runtime_verdict = self._combine_runtime_verdicts(
            control_verdict, replacement_verdict, recovery_verdict
        )

        command_started_ms = int(
            command.created_at.replace(tzinfo=UTC).timestamp() * 1000
        )
        # Flush the batch exporters before querying SigNoz so proof generation
        # cannot race the SDK export timers. Failure is surfaced through MCP
        # reconciliation rather than silently upgrading evidence.
        flush_ok = await asyncio.to_thread(
            force_flush_telemetry,
            run_id=command.run_id,
            command_id=command.id,
            command_created_ms=command_started_ms,
        )
        export_watermark = (
            telemetry_export_context(command.run_id, command.id)
            if flush_ok
            else None
        )
        telemetry_identity = telemetry_process_identity()
        telemetry_proof = await self.mcp_client.verify_command(
            context=TelemetryVerificationContext(
                command_id=command.id,
                run_id=command.run_id,
                command_created_ms=command_started_ms,
                start_ms=max(0, command_started_ms - 5_000),
                end_ms=int(utcnow().replace(tzinfo=UTC).timestamp() * 1000)
                + 5_000,
                command_operation="tracefence.control.command_issue",
                service_name=str(telemetry_identity["service_name"]),
                service_instance_id=str(
                    telemetry_identity["service_instance_id"]
                ),
                process_instance_id=str(
                    telemetry_identity["process_instance_id"]
                ),
                build_commit=str(telemetry_identity["build_commit"]),
                schema_version=int(telemetry_identity["schema_version"]),
                blocked_actions=runtime_blocked_actions,
                export_watermark=export_watermark,
            ),
        )

        overall = combine_proof_verdicts(
            runtime_verdict,
            telemetry_proof.verdict,
        )

        discrepancies.extend(telemetry_proof.discrepancies)
        if unclassified:
            discrepancies.append(f"Unclassified live affected nodes: {', '.join(unclassified)}")

        telemetry.proof_duration_ms.record((time.perf_counter() - started) * 1000)
        with telemetry.tracer.start_as_current_span("tracefence.proof.finalize") as span:
            span.set_attribute("tracefence.command.id", command.id)
            span.set_attribute("tracefence.proof.status", overall.value)

        return (
            ProofResponse(
                command_id=command.id,
                command_type=command.command_type,
                affected_registered_nodes=len(affected),
                classifications=dict(classifications),
                stale_action_attempts=stale_attempts,
                stale_actions_committed=stale_committed,
                unrelated_branches_interrupted=unrelated_interrupted,
                control_convergence_verdict=control_verdict,
                replacement_lineage_verdict=replacement_verdict,
                recovery_action_verdict=recovery_action_verdict,
                recovery_postcondition_verdict=recovery_postcondition_verdict,
                recovery_stability_verdict=recovery_stability_verdict,
                recovery_outcome_verdict=recovery_verdict,
                runtime_verdict=runtime_verdict,
                telemetry_verdict=telemetry_proof.verdict,
                overall_verdict=overall,
                trace_ids=telemetry_proof.trace_ids,
                discrepancies=discrepancies,
            ),
            _ProofContext(
                run_id=command.run_id,
                revision=proof_revision,
                nearest_lease_expiry=nearest_lease_expiry,
            ),
        )

    @staticmethod
    async def _replacement_verdicts(
        session: Session,
        command: ControlCommand,
        target: Node,
        discrepancies: list[str],
    ) -> tuple[ProofVerdict, ProofVerdict, ProofVerdict, ProofVerdict]:
        not_applicable = (
            ProofVerdict.NOT_APPLICABLE,
            ProofVerdict.NOT_APPLICABLE,
            ProofVerdict.NOT_APPLICABLE,
            ProofVerdict.NOT_APPLICABLE,
        )
        if command.command_type != CommandType.CORRECT_SUBTREE:
            return not_applicable

        manifest = command.replacement_manifest_json
        if (
            manifest is None
            or command.replacement_manifest_digest is None
            or command.replacement_manifest_digest != payload_digest(manifest)
        ):
            discrepancies.append("Correction replacement manifest is missing or corrupted")
            return (
                ProofVerdict.INCONSISTENT,
                ProofVerdict.INCONSISTENT,
                ProofVerdict.INCONSISTENT,
                ProofVerdict.INCONSISTENT,
            )
        try:
            manifest_model = ReplacementManifest.model_validate(manifest)
        except ValidationError as exc:
            discrepancies.append(
                f"Correction replacement manifest violates its schema: {exc.errors()[0]['msg']}"
            )
            return (
                ProofVerdict.INCONSISTENT,
                ProofVerdict.INCONSISTENT,
                ProofVerdict.INCONSISTENT,
                ProofVerdict.INCONSISTENT,
            )
        manifest = manifest_model.model_dump(mode="json")
        if command.replacement_node_id is None:
            discrepancies.append("Correction has no registered replacement node")
            return (
                ProofVerdict.INCOMPLETE,
                ProofVerdict.INCOMPLETE,
                ProofVerdict.INCOMPLETE,
                ProofVerdict.INCOMPLETE,
            )

        replacement = session.get(Node, command.replacement_node_id)
        if replacement is None:
            discrepancies.append("Correction references a missing replacement node")
            return (
                ProofVerdict.INCONSISTENT,
                ProofVerdict.INCONSISTENT,
                ProofVerdict.INCONSISTENT,
                ProofVerdict.INCONSISTENT,
            )

        expected_capabilities = manifest_model.capabilities_exact
        lineage_ok = (
            replacement.run_id == command.run_id
            and replacement.parent_id == command.replacement_parent_id
            and replacement.supersedes_node_id == target.id
            and replacement.caused_by_command_id == command.id
            and replacement.role == manifest.get("role")
            and replacement.behavior == manifest.get("behavior")
            and sorted(set(replacement.capabilities_json or [])) == expected_capabilities
            and payload_digest(replacement.instruction_json)
            == manifest.get("instruction_digest")
            and replacement.instruction_version == manifest.get("instruction_version")
            and replacement.registered_at >= command.created_at
            and replacement.activated_at is not None
            and replacement.activated_at >= command.created_at
        )
        if not lineage_ok:
            discrepancies.append(
                "Replacement lineage, identity, capabilities, behavior or instruction "
                "does not match the authorized manifest"
            )
            return (
                ProofVerdict.INCONSISTENT,
                ProofVerdict.INCONSISTENT,
                ProofVerdict.INCONSISTENT,
                ProofVerdict.INCONSISTENT,
            )

        replacement_nodes = await descendants_including_self(
            session,
            run_id=command.run_id,
            root_node_id=replacement.id,
        )
        direct_children = [node for node in replacement_nodes if node.parent_id == replacement.id]
        if len(direct_children) > manifest_model.max_children:
            discrepancies.append("Replacement exceeded its authorized child budget")
            return (
                ProofVerdict.INCONSISTENT,
                ProofVerdict.INCONSISTENT,
                ProofVerdict.INCONSISTENT,
                ProofVerdict.INCONSISTENT,
            )

        replacement_verdict = ProofVerdict.VERIFIED
        contract = manifest_model.recovery_contract.model_dump(mode="json")
        expected_tool = contract.get("expected_tool")
        if expected_tool is None:
            return (
                replacement_verdict,
                ProofVerdict.NOT_APPLICABLE,
                ProofVerdict.NOT_APPLICABLE,
                ProofVerdict.NOT_APPLICABLE,
            )

        replacement_ids = {node.id for node in replacement_nodes}
        committed_actions = session.execute(
            select(ActionAttempt).where(
                ActionAttempt.run_id == command.run_id,
                ActionAttempt.node_id.in_(replacement_ids),
                ActionAttempt.tool_name == expected_tool,
                ActionAttempt.arguments_digest == contract.get("expected_arguments_digest"),
                ActionAttempt.decision == ActionDecision.ALLOW,
                ActionAttempt.committed_at.is_not(None),
                ActionAttempt.attempted_at >= command.created_at,
            ).order_by(ActionAttempt.committed_at.asc(), ActionAttempt.id.asc())
        ).scalars().all()
        max_invocations = int(contract.get("max_committed_invocations", 1))
        if not committed_actions:
            discrepancies.append(f"Expected recovery tool {expected_tool} has not committed")
            return (
                replacement_verdict,
                ProofVerdict.INCOMPLETE,
                ProofVerdict.INCOMPLETE,
                ProofVerdict.INCOMPLETE,
            )
        if len(committed_actions) > max_invocations:
            discrepancies.append(
                f"Recovery tool {expected_tool} committed {len(committed_actions)} times; "
                f"manifest allows {max_invocations}"
            )
            return (
                replacement_verdict,
                ProofVerdict.INCONSISTENT,
                ProofVerdict.INCONSISTENT,
                ProofVerdict.INCONSISTENT,
            )

        recovery_action = committed_actions[-1]
        if (
            recovery_action.result_json is None
            or recovery_action.result_digest != payload_digest(recovery_action.result_json)
        ):
            discrepancies.append("Recovery action result digest is missing or inconsistent")
            return (
                replacement_verdict,
                ProofVerdict.INCONSISTENT,
                ProofVerdict.INCONSISTENT,
                ProofVerdict.INCONSISTENT,
            )
        if replacement.status != NodeStatus.COMPLETED or replacement.completed_at is None:
            discrepancies.append("Replacement recovery action committed but replacement is not complete")
            return (
                replacement_verdict,
                ProofVerdict.INCOMPLETE,
                ProofVerdict.INCOMPLETE,
                ProofVerdict.INCOMPLETE,
            )
        if recovery_action.committed_at is None or replacement.completed_at < recovery_action.committed_at:
            discrepancies.append("Replacement completed before its recovery action committed")
            return (
                replacement_verdict,
                ProofVerdict.INCONSISTENT,
                ProofVerdict.INCONSISTENT,
                ProofVerdict.INCONSISTENT,
            )

        action_verdict = ProofVerdict.VERIFIED
        postcondition_verdict = ProofVerdict.VERIFIED
        stability_verdict = ProofVerdict.VERIFIED
        stability_seconds = int(contract.get("stability_window_seconds", 0))
        stable_before = utcnow() - timedelta(seconds=stability_seconds)
        for postcondition in contract.get("postconditions", []):
            service_name = postcondition.get("service_name")
            field = postcondition.get("field")
            if field not in {"status", "restart_count", "pool_reset_count"}:
                discrepancies.append(f"Unsupported recovery postcondition field: {field}")
                return (
                    replacement_verdict,
                    action_verdict,
                    ProofVerdict.INCONSISTENT,
                    ProofVerdict.INCONSISTENT,
                )
            state = session.get(ServiceState, (command.run_id, service_name))
            if state is None:
                discrepancies.append(f"Recovery postcondition service is missing: {service_name}")
                postcondition_verdict = ProofVerdict.INCOMPLETE
                stability_verdict = ProofVerdict.INCOMPLETE
                continue
            actual = getattr(state, field)
            operator = postcondition.get("operator")
            expected = postcondition.get("expected")
            if operator != "equals":
                discrepancies.append(f"Unsupported recovery postcondition operator: {operator}")
                return (
                    replacement_verdict,
                    action_verdict,
                    ProofVerdict.INCONSISTENT,
                    ProofVerdict.INCONSISTENT,
                )
            if actual != expected:
                discrepancies.append(
                    f"Recovery postcondition failed: {service_name}.{field} "
                    f"expected {expected!r}, found {actual!r}"
                )
                postcondition_verdict = ProofVerdict.INCOMPLETE
                stability_verdict = ProofVerdict.INCOMPLETE
                continue
            if postcondition.get("require_recovery_action") and state.last_action_id != recovery_action.id:
                discrepancies.append(
                    f"Recovery postcondition {service_name}.{field} is not causally bound "
                    "to the authorized recovery action"
                )
                postcondition_verdict = ProofVerdict.INCONSISTENT
                stability_verdict = ProofVerdict.INCONSISTENT
                continue
            if stability_seconds > 0 and state.updated_at > stable_before:
                discrepancies.append(
                    f"Recovery postcondition {service_name}.{field} has not remained stable "
                    f"for {stability_seconds} seconds"
                )
                stability_verdict = ProofVerdict.INCOMPLETE

        return (
            replacement_verdict,
            action_verdict,
            postcondition_verdict,
            stability_verdict,
        )

    @staticmethod
    def _combine_recovery_verdicts(
        action: ProofVerdict,
        postcondition: ProofVerdict,
        stability: ProofVerdict,
    ) -> ProofVerdict:
        return combine_proof_verdicts(action, postcondition, stability)

    @staticmethod
    def _combine_runtime_verdicts(
        control: ProofVerdict,
        replacement: ProofVerdict,
        recovery: ProofVerdict,
    ) -> ProofVerdict:
        return combine_proof_verdicts(control, replacement, recovery)
