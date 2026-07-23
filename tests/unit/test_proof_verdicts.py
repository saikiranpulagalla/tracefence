from __future__ import annotations

from uuid import uuid4

import pytest

import tracefence.services.proof_service as proof_module
from tracefence.db.models import ActionAttempt
from tracefence.domain.enums import ActionDecision, CommandType, IssuerType, ProofVerdict
from tracefence.domain.schemas import CommandCreate, Principal, SpawnCreate
from tracefence.security import payload_digest
from tracefence.services.common import utcnow
from tracefence.services.control_service import ControlService
from tracefence.services.proof_service import ProofService
from tracefence.services.spawn_service import SpawnService
from tracefence.signoz.mcp_client import TelemetryProof
from tests.helpers import activate, create_seeded_run


class _VerdictMCPClient:
    def __init__(self, verdict: ProofVerdict) -> None:
        self.verdict = verdict

    async def verify_command(self, **_kwargs) -> TelemetryProof:
        return TelemetryProof(
            verdict=self.verdict,
            trace_ids=[],
            discrepancies=[f"test telemetry verdict: {self.verdict.value}"],
            evidence={},
        )


@pytest.mark.parametrize(
    ("verdicts", "expected"),
    [
        (
            (ProofVerdict.INCOMPLETE, ProofVerdict.INCONSISTENT),
            ProofVerdict.INCONSISTENT,
        ),
        (
            (
                ProofVerdict.INCOMPLETE,
                ProofVerdict.STATE_CHANGED_DURING_PROOF,
            ),
            ProofVerdict.STATE_CHANGED_DURING_PROOF,
        ),
        (
            (ProofVerdict.PARTIAL, ProofVerdict.UNAVAILABLE),
            ProofVerdict.PARTIAL,
        ),
        (
            (ProofVerdict.VERIFIED, ProofVerdict.UNAVAILABLE),
            ProofVerdict.UNAVAILABLE,
        ),
        (
            (ProofVerdict.VERIFIED, ProofVerdict.NOT_APPLICABLE),
            ProofVerdict.VERIFIED,
        ),
        (
            (ProofVerdict.NOT_APPLICABLE, ProofVerdict.NOT_APPLICABLE),
            ProofVerdict.NOT_APPLICABLE,
        ),
    ],
)
def test_canonical_verdict_lattice(verdicts, expected):
    assert proof_module.combine_proof_verdicts(*verdicts) == expected


async def test_stale_committed_side_effect_is_runtime_inconsistent(session_factory):
    spawns = SpawnService(session_factory)
    controls = ControlService(session_factory)
    run = await create_seeded_run(session_factory, "stale-commit-verdict")
    child = await activate(
        spawns,
        await spawns.create_spawn(
            run.root_node_id,
            run.root_token,
            SpawnCreate(role="stale-worker", capabilities=["tool:restart_postgres"]),
        ),
    )
    command = await controls.issue_command(
        CommandCreate(
            idempotency_key="stale-commit-command",
            command_type=CommandType.CANCEL_SUBTREE,
            target_node_id=child.node_id,
            reason_code="TEST",
            reason_text="force stale committed action",
        ),
        Principal(issuer_type=IssuerType.HUMAN),
    )
    result_json = {"ok": True}
    now = utcnow()
    with session_factory() as session, session.begin():
        session.add(
            ActionAttempt(
                id=str(uuid4()),
                run_id=run.run_id,
                node_id=child.node_id,
                tool_name="restart_postgres",
                side_effecting=True,
                idempotency_key="impossible-stale-commit",
                decision=ActionDecision.ALLOW,
                denial_reason=None,
                matched_command_id=None,
                matched_scope_id=None,
                matched_snapshot_version=None,
                matched_live_version=None,
                matched_live_status=None,
                scope_evaluation_json={"allowed": True},
                request_payload_digest=payload_digest({"test": "stale"}),
                arguments_json={},
                arguments_digest=payload_digest({}),
                result_json=result_json,
                result_digest=payload_digest(result_json),
                attempted_at=now,
                committed_at=now,
            )
        )

    proof = await ProofService(
        session_factory,
        mcp_client=_VerdictMCPClient(ProofVerdict.UNAVAILABLE),
    ).build(command.command_id)

    assert proof.stale_actions_committed == 1
    assert proof.control_convergence_verdict == ProofVerdict.INCONSISTENT
    assert proof.runtime_verdict == ProofVerdict.INCONSISTENT
    assert proof.overall_verdict == ProofVerdict.INCONSISTENT


async def test_telemetry_inconsistent_dominates_incomplete_runtime(session_factory):
    spawns = SpawnService(session_factory)
    controls = ControlService(session_factory)
    run = await create_seeded_run(session_factory, "telemetry-dominates-runtime")
    child = await activate(
        spawns,
        await spawns.create_spawn(
            run.root_node_id,
            run.root_token,
            SpawnCreate(role="unfinished-correction", capabilities=[]),
        ),
    )
    command = await controls.issue_command(
        CommandCreate(
            idempotency_key="unfinished-correction-command",
            command_type=CommandType.CORRECT_SUBTREE,
            target_node_id=child.node_id,
            reason_code="TEST",
            reason_text="replacement deliberately pending",
            replacement_instruction={"task": "replace"},
        ),
        Principal(issuer_type=IssuerType.HUMAN),
    )

    proof = await ProofService(
        session_factory,
        mcp_client=_VerdictMCPClient(ProofVerdict.INCONSISTENT),
    ).build(command.command_id)

    assert proof.runtime_verdict == ProofVerdict.INCOMPLETE
    assert proof.telemetry_verdict == ProofVerdict.INCONSISTENT
    assert proof.overall_verdict == ProofVerdict.INCONSISTENT
