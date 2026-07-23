from fastapi import APIRouter, Depends, Header

from tracefence.api.dependencies import (
    call_blocking_service,
    control_service,
    proposal_service,
    require_operator,
)
from tracefence.domain.enums import IssuerType
from tracefence.domain.errors import AuthenticationError
from tracefence.domain.schemas import (
    CommandCreate,
    CommandIssued,
    Principal,
    ProposalCreate,
    ProposalReview,
)
from tracefence.security import operator_fingerprint, operator_key_matches

router = APIRouter(prefix="/v1", tags=["control"])


@router.post("/proposals", status_code=201)
async def create_proposal(
    request: ProposalCreate,
    x_node_id: str = Header(alias="X-Node-Id"),
    x_node_token: str = Header(alias="X-Node-Token"),
) -> dict:
    proposal = await call_blocking_service(
        lambda: proposal_service.create(x_node_id, x_node_token, request)
    )
    return {"proposal_id": proposal.id, "status": proposal.status}


@router.post(
    "/proposals/{proposal_id}/review",
    dependencies=[Depends(require_operator)],
)
async def review_proposal(
    proposal_id: str,
    request: ProposalReview,
    x_operator_key: str = Header(alias="X-Operator-Key"),
) -> dict:
    proposal = await call_blocking_service(
        lambda: proposal_service.review(
            proposal_id,
            request,
            reviewer_principal=operator_fingerprint(x_operator_key),
        )
    )
    return {"proposal_id": proposal.id, "status": proposal.status}


@router.get(
    "/runs/{run_id}/proposals",
    dependencies=[Depends(require_operator)],
)
async def list_proposals(run_id: str) -> list[dict]:
    return await call_blocking_service(lambda: proposal_service.list_for_run(run_id))


@router.post("/commands", response_model=CommandIssued, status_code=201)
async def issue_command(
    request: CommandCreate,
    x_operator_key: str | None = Header(default=None, alias="X-Operator-Key"),
    x_node_id: str | None = Header(default=None, alias="X-Node-Id"),
    x_node_token: str | None = Header(default=None, alias="X-Node-Token"),
) -> CommandIssued:
    if x_operator_key is not None:
        if not operator_key_matches(x_operator_key):
            raise AuthenticationError("Invalid operator key")
        principal = Principal(
            issuer_type=IssuerType.HUMAN,
            principal_id=operator_fingerprint(x_operator_key),
        )
    elif x_node_id is not None and x_node_token is not None:
        principal = Principal(issuer_type=IssuerType.AGENT, node_id=x_node_id)
    else:
        raise AuthenticationError("Operator or agent authentication required")
    return await call_blocking_service(
        lambda: control_service.issue_command(request, principal, x_node_token)
    )
