from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

import httpx

from tracefence.evidence import EvidenceIntegrityError, resolve_evidence_path
from tracefence.security import payload_digest


class VerificationError(RuntimeError):
    pass


def check(condition: bool, label: str) -> None:
    if not condition:
        raise VerificationError(label)
    print(f"PASS {label}")


def _exactly_one(rows: list[dict[str, Any]], predicate: Any, label: str) -> dict[str, Any]:
    matches = [row for row in rows if predicate(row)]
    check(len(matches) == 1, f"exactly one {label}")
    return matches[0]


def _resolve_command_replacement(
    graph: dict[str, Any], command_id: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    graph_command = _exactly_one(
        graph["commands"], lambda row: row["id"] == command_id, "graph command record"
    )
    replacement = _exactly_one(
        graph["nodes"],
        lambda node: node.get("caused_by_command_id") == command_id,
        "command-linked replacement node",
    )
    check(
        graph_command.get("replacement_node_id") == replacement.get("id"),
        "graph command points to the command-linked replacement",
    )
    return graph_command, replacement


def _verify_internal_consistency(bundle: dict[str, Any], require_telemetry: bool) -> None:
    proof = bundle["proof"]
    actions = bundle["actions"]
    services = {row["service_name"]: row for row in bundle["services"]}
    graph = bundle["graph"]
    violations = bundle.get("violations", [])
    command = bundle["command"]
    run = bundle["run"]

    run_id = run["run_id"]
    command_id = command["command_id"]
    check(graph["run_id"] == run_id, "graph belongs to the evidence run")
    check(proof["command_id"] == command_id, "proof belongs to the evidence command")
    check(graph["status"] == "COMPLETED", "run closes in COMPLETED state")
    check(bool(graph["nodes"]), "registered graph is non-empty")
    check(any(node["generation"] >= 2 for node in graph["nodes"]), "dynamic descendant exists")
    check(
        any(node["effective_status"] == "SUPERSEDED" for node in graph["nodes"]),
        "old subtree is effectively superseded",
    )

    graph_command, replacement = _resolve_command_replacement(graph, command_id)
    check(
        replacement.get("supersedes_node_id") == graph_command.get("target_node_id"),
        "replacement supersedes the corrected target",
    )
    manifest = command.get("replacement_manifest")
    check(isinstance(manifest, dict), "command contains a frozen replacement manifest")
    check(replacement["role"] == manifest["role"], "replacement role matches manifest")
    check(
        replacement["behavior"] == manifest["behavior"],
        "replacement behavior matches manifest",
    )
    check(
        sorted(replacement["capabilities"]) == sorted(manifest["capabilities_exact"]),
        "replacement capabilities exactly match manifest",
    )
    children = [node for node in graph["nodes"] if node.get("parent_id") == replacement["id"]]
    check(
        len(children) <= int(manifest.get("max_children", 0)),
        "replacement remains within child budget",
    )

    stale_action = _exactly_one(
        actions,
        lambda action: action["decision"] == "DENY"
        and action["tool_name"] == "restart_postgres"
        and action.get("matched_command_id") == command_id,
        "command-attributed stale PostgreSQL denial",
    )
    check(not stale_action["committed"], "stale PostgreSQL restart did not commit")
    check(
        not any(
            action["decision"] == "ALLOW"
            and action["committed"]
            and action["tool_name"] == "restart_postgres"
            for action in actions
        ),
        "no PostgreSQL restart was allowed",
    )

    contract = manifest["recovery_contract"]
    expected_tool = contract["expected_tool"]
    recovery_action = _exactly_one(
        actions,
        lambda action: action["decision"] == "ALLOW"
        and action["committed"]
        and action["node_id"] == replacement["id"]
        and action["tool_name"] == expected_tool,
        "authorized replacement recovery action",
    )
    check(
        recovery_action["arguments_digest"] == contract["expected_arguments_digest"],
        "recovery action arguments match the contract",
    )
    check(
        recovery_action["arguments_digest"] == payload_digest(recovery_action["arguments"]),
        "recovery arguments digest is internally consistent",
    )
    check(
        recovery_action["request_payload_digest"]
        == payload_digest(
            {
                "idempotency_key": recovery_action["idempotency_key"],
                "tool_name": recovery_action["tool_name"],
                "arguments": recovery_action["arguments"],
            }
        ),
        "recovery request digest is internally consistent",
    )
    check(
        recovery_action["result_digest"] == payload_digest(recovery_action["result"]),
        "recovery result digest is internally consistent",
    )

    allowed_side_effects = [
        action
        for action in actions
        if action["side_effecting"] and action["decision"] == "ALLOW" and action["committed"]
    ]
    check(
        [action["id"] for action in allowed_side_effects] == [recovery_action["id"]],
        "the recovery action is the only committed side effect",
    )

    check(proof["stale_action_attempts"] == 1, "exactly one stale attempt is recorded")
    check(proof["stale_actions_committed"] == 0, "no stale action committed")
    check(not violations, "durable invariant ledger contains no safety violation")
    check(proof["unrelated_branches_interrupted"] == 0, "unrelated branches remain isolated")
    check(
        sum(proof["classifications"].values()) == proof["affected_registered_nodes"],
        "affected-node classifications are complete",
    )
    for field, label in (
        ("control_convergence_verdict", "control convergence proof"),
        ("replacement_lineage_verdict", "replacement lineage proof"),
        ("recovery_action_verdict", "recovery action proof"),
        ("recovery_postcondition_verdict", "recovery postcondition proof"),
        ("recovery_stability_verdict", "recovery stability proof"),
        ("recovery_outcome_verdict", "recovery outcome proof"),
        ("runtime_verdict", "runtime proof"),
    ):
        check(proof[field] == "VERIFIED", f"{label} is verified")

    check(services["postgres"]["restart_count"] == 0, "PostgreSQL was not restarted")
    check(services["postgres"]["status"] == "healthy", "PostgreSQL remains healthy")
    check(services["redis"]["pool_reset_count"] == 1, "Redis pool reset committed exactly once")
    check(services["redis"]["status"] == "healthy", "Redis is currently healthy")
    check(services["checkout"]["status"] == "healthy", "checkout is currently healthy")
    check(
        services["redis"]["last_action_id"] == recovery_action["id"]
        and services["checkout"]["last_action_id"] == recovery_action["id"],
        "recovery postconditions are causally bound to the authorized action",
    )

    if require_telemetry:
        check(proof["telemetry_verdict"] == "VERIFIED", "SigNoz telemetry proof is verified")
        check(proof["overall_verdict"] == "VERIFIED", "overall proof is verified")
        check(bool(proof["trace_ids"]), "SigNoz trace IDs are present")
    else:
        check(
            proof["overall_verdict"] in {"PARTIAL", "VERIFIED"},
            "overall proof truthfully reflects telemetry availability",
        )


def _load_bundle(
    path: Path,
    signing_key: str | None,
    *,
    expected_commit: str | None,
    max_age_seconds: int | None,
) -> dict[str, Any]:
    resolved, manifest = resolve_evidence_path(
        path,
        signing_key=signing_key,
        expected_commit=expected_commit,
        max_age_seconds=max_age_seconds,
    )
    if manifest is not None:
        print(f"PASS evidence manifest integrity ({manifest['generated_at']})")
    return json.loads(resolved.read_text(encoding="utf-8"))


def _fetch_live_bundle(
    api_url: str,
    operator_key: str,
    file_bundle: dict[str, Any],
) -> dict[str, Any]:
    run_id = file_bundle["run"]["run_id"]
    command_id = file_bundle["command"]["command_id"]
    headers = {"X-Operator-Key": operator_key}
    with httpx.Client(base_url=api_url, headers=headers, timeout=20.0) as client:
        def get(path: str) -> Any:
            response = client.get(path)
            response.raise_for_status()
            return response.json()

        return {
            **file_bundle,
            "proof": get(f"/v1/commands/{command_id}/proof"),
            "graph": get(f"/v1/runs/{run_id}/graph"),
            "actions": get(f"/v1/runs/{run_id}/actions"),
            "services": get(f"/v1/runs/{run_id}/services"),
            "violations": get(f"/v1/runs/{run_id}/violations"),
        }


def verify(
    bundle_path: Path,
    require_telemetry: bool,
    *,
    api_url: str | None = None,
    operator_key: str | None = None,
    evidence_signing_key: str | None = None,
    expected_commit: str | None = None,
    max_age_seconds: int | None = None,
) -> None:
    bundle = _load_bundle(
        bundle_path,
        evidence_signing_key,
        expected_commit=expected_commit,
        max_age_seconds=max_age_seconds,
    )
    _verify_internal_consistency(bundle, require_telemetry)
    if api_url is not None:
        if not operator_key:
            raise VerificationError("Live verification requires an operator key")
        live = _fetch_live_bundle(api_url, operator_key, bundle)
        _verify_internal_consistency(live, require_telemetry)
        for section in ("proof", "graph", "actions", "services", "violations"):
            check(
                payload_digest(live[section]) == payload_digest(bundle[section]),
                f"stored {section} matches the live authenticated API",
            )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bundle", type=Path, default=Path("evidence/latest.json"))
    parser.add_argument("--require-telemetry", action="store_true")
    parser.add_argument("--api-url")
    parser.add_argument("--operator-key", default=os.getenv("TRACEFENCE_OPERATOR_KEY", ""))
    parser.add_argument(
        "--evidence-signing-key",
        default=os.getenv("TRACEFENCE_EVIDENCE_SIGNING_KEY", ""),
    )
    parser.add_argument(
        "--expected-commit",
        default=os.getenv("TRACEFENCE_EXPECTED_EVIDENCE_COMMIT", "") or None,
    )
    parser.add_argument(
        "--max-age-seconds",
        type=int,
        default=os.getenv("TRACEFENCE_EVIDENCE_MAX_AGE_SECONDS"),
    )
    args = parser.parse_args()
    try:
        verify(
            args.bundle,
            args.require_telemetry,
            api_url=args.api_url,
            operator_key=args.operator_key,
            evidence_signing_key=args.evidence_signing_key,
            expected_commit=args.expected_commit,
            max_age_seconds=args.max_age_seconds,
        )
    except (
        VerificationError,
        EvidenceIntegrityError,
        FileNotFoundError,
        json.JSONDecodeError,
        httpx.HTTPError,
    ) as exc:
        print(f"FAIL {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
