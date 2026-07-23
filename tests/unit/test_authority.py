from tracefence.db.models import Node, Run
from tracefence.domain.enums import CommandType, IssuerType
from tracefence.domain.schemas import Principal
from tracefence.services.authority_service import AuthorityService


def node(node_id, run_id, lineage, capabilities=None):
    return Node(
        id=node_id,
        run_id=run_id,
        parent_id=None,
        supersedes_node_id=None,
        caused_by_command_id=None,
        role="worker",
        behavior="cooperative",
        generation=0,
        lineage_path=lineage,
        status="ACTIVE",
        own_scope_id="scope",
        scope_snapshot_json=[],
        instruction_version=1,
        instruction_json={},
        capabilities_json=capabilities or [],
        registered_at=None,
    )


def test_sibling_cannot_cancel_sibling():
    run = Run(id="run", name="x", status="RUNNING", root_node_id="root", run_scope_id="s")
    issuer = node("a", "run", "/root/", ["control:descendants"])
    target = node("b", "run", "/root/")
    decision = AuthorityService.may_issue_command(
        Principal(issuer_type=IssuerType.AGENT, node_id="a"),
        issuer,
        target,
        run,
        CommandType.CANCEL_SUBTREE,
    )
    assert decision.allowed is False
    assert decision.reason_code == "NON_DESCENDANT_TARGET"


def test_parent_with_capability_can_control_descendant():
    run = Run(id="run", name="x", status="RUNNING", root_node_id="root", run_scope_id="s")
    issuer = node("parent", "run", "/root/", ["control:descendants"])
    target = node("child", "run", "/root/parent/")
    decision = AuthorityService.may_issue_command(
        Principal(issuer_type=IssuerType.AGENT, node_id="parent"),
        issuer,
        target,
        run,
        CommandType.CORRECT_SUBTREE,
        target_is_descendant=True,
    )
    assert decision.allowed is True


def test_delegated_parent_cannot_cancel_run():
    run = Run(id="run", name="x", status="RUNNING", root_node_id="root", run_scope_id="s")
    issuer = node("parent", "run", "/root/", ["control:descendants"])
    target = node("child", "run", "/root/parent/")
    decision = AuthorityService.may_issue_command(
        Principal(issuer_type=IssuerType.AGENT, node_id="parent"),
        issuer,
        target,
        run,
        CommandType.CANCEL_RUN,
    )
    assert decision.allowed is False
    assert decision.reason_code == "RUN_CANCELLATION_TARGET_MUST_BE_ROOT"


def test_root_cancel_run_must_target_root():
    run = Run(id="run", name="x", status="RUNNING", root_node_id="root", run_scope_id="s")
    issuer = node("root", "run", "/", ["control:descendants"])
    target = node("child", "run", "/root/")
    decision = AuthorityService.may_issue_command(
        Principal(issuer_type=IssuerType.AGENT, node_id="root"),
        issuer,
        target,
        run,
        CommandType.CANCEL_RUN,
    )
    assert decision.allowed is False
    assert decision.reason_code == "RUN_CANCELLATION_TARGET_MUST_BE_ROOT"


def test_human_cancel_run_must_target_root():
    run = Run(id="run", name="x", status="RUNNING", root_node_id="root", run_scope_id="s")
    target = node("child", "run", "/root/")
    decision = AuthorityService.may_issue_command(
        Principal(issuer_type=IssuerType.HUMAN),
        None,
        target,
        run,
        CommandType.CANCEL_RUN,
    )
    assert decision.allowed is False
    assert decision.reason_code == "RUN_CANCELLATION_TARGET_MUST_BE_ROOT"


def test_denormalized_lineage_is_not_an_authority_input():
    run = Run(id="run", name="x", status="RUNNING", root_node_id="root", run_scope_id="s")
    issuer = node("parent", "run", "/forged/", ["control:descendants"])
    target = node("child", "run", "/forged/parent/")
    decision = AuthorityService.may_issue_command(
        Principal(issuer_type=IssuerType.AGENT, node_id="parent"),
        issuer,
        target,
        run,
        CommandType.CANCEL_SUBTREE,
        target_is_descendant=False,
    )
    assert decision.allowed is False
    assert decision.reason_code == "NON_DESCENDANT_TARGET"
