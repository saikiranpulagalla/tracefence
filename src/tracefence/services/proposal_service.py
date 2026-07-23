from __future__ import annotations

from uuid import uuid4

from sqlalchemy import func, select, text
from sqlalchemy.orm import sessionmaker

from tracefence.config import settings
from tracefence.db.models import CorrectionProposal
from tracefence.domain.enums import CommandType, ProposalStatus, ProposalType
from tracefence.domain.errors import AuthorizationError, ConflictError, NotFoundError
from tracefence.domain.schemas import ProposalCreate, ProposalReview
from tracefence.rate_limits import authenticated_rate_limiter
from tracefence.security import payload_digest
from tracefence.services.common import (
    authenticate_node,
    get_node,
    get_run,
    utcnow,
    validate_node_runtime_state,
)


def proposal_payload(proposal: CorrectionProposal) -> dict:
    return {
        "id": proposal.id,
        "run_id": proposal.run_id,
        "reporter_node_id": proposal.reporter_node_id,
        "target_node_id": proposal.target_node_id,
        "proposal_type": proposal.proposal_type,
        "evidence": proposal.evidence_json,
        "reason": proposal.reason,
        "created_at": proposal.created_at,
    }


class ProposalService:
    def __init__(self, session_factory: sessionmaker) -> None:
        self.session_factory = session_factory

    async def create(
        self, reporter_node_id: str, reporter_token: str, request: ProposalCreate
    ) -> CorrectionProposal:
        with self.session_factory() as session:
            session.execute(text("BEGIN IMMEDIATE"))
            reporter = await authenticate_node(session, reporter_node_id, reporter_token)
            authenticated_rate_limiter.check(
                "command",
                f"{reporter.run_id}:{reporter.id}",
            )
            allowed, reason, _ = await validate_node_runtime_state(session, reporter)
            if not allowed:
                session.rollback()
                raise ConflictError(
                    f"Reporter is not live: {reason}", code=reason or "REPORTER_NOT_LIVE"
                )
            if "tool:propose_correction" not in set(reporter.capabilities_json or []):
                session.rollback()
                raise AuthorizationError("Reporter lacks tool:propose_correction capability")
            target = await get_node(session, request.target_node_id)
            if reporter.run_id != target.run_id:
                session.rollback()
                raise AuthorizationError("Cross-run proposals are not allowed")
            count = session.scalar(
                select(func.count(CorrectionProposal.id)).where(
                    CorrectionProposal.run_id == reporter.run_id
                )
            ) or 0
            if count >= settings.max_proposals_per_run:
                session.rollback()
                raise ConflictError(
                    "Proposal quota exceeded for run", code="RUN_PROPOSAL_QUOTA_EXCEEDED"
                )
            proposal = CorrectionProposal(
                id=str(uuid4()),
                run_id=reporter.run_id,
                reporter_node_id=reporter.id,
                target_node_id=target.id,
                proposal_type=request.proposal_type,
                evidence_json=request.evidence,
                reason=request.reason,
                status=ProposalStatus.PENDING,
                created_at=utcnow(),
            )
            session.add(proposal)
            session.commit()
            return proposal

    async def review(
        self,
        proposal_id: str,
        request: ProposalReview,
        *,
        reviewer_principal: str,
    ) -> CorrectionProposal:
        with self.session_factory() as session:
            session.execute(text("BEGIN IMMEDIATE"))
            proposal = session.get(CorrectionProposal, proposal_id)
            if proposal is None:
                session.rollback()
                raise NotFoundError(f"Proposal {proposal_id} was not found")
            if proposal.status != ProposalStatus.PENDING:
                session.rollback()
                raise ConflictError(
                    "Proposal was already reviewed", code="PROPOSAL_ALREADY_REVIEWED"
                )
            authorized_payload: dict | None = None
            if request.status == ProposalStatus.ACCEPTED:
                authorization = request.authorized_command
                if authorization is None:  # Defensive; Pydantic rejects this shape.
                    session.rollback()
                    raise ConflictError(
                        "Accepted proposal has no authorized command",
                        code="PROPOSAL_AUTHORIZATION_REQUIRED",
                    )
                if authorization.target_node_id != proposal.target_node_id:
                    session.rollback()
                    raise ConflictError(
                        "Authorized command targets a different node",
                        code="PROPOSAL_AUTHORIZATION_TARGET_MISMATCH",
                    )
                expected_type = (
                    CommandType.CORRECT_SUBTREE
                    if proposal.proposal_type == ProposalType.CORRECT
                    else CommandType.CANCEL_SUBTREE
                )
                if authorization.command_type != expected_type:
                    session.rollback()
                    raise ConflictError(
                        "Authorized command type does not match proposal type",
                        code="PROPOSAL_AUTHORIZATION_TYPE_MISMATCH",
                    )
                authorized_payload = authorization.model_dump(mode="json")

            proposal.status = request.status
            proposal.reviewed_by_principal = reviewer_principal
            proposal.accepted_payload_digest = payload_digest(proposal_payload(proposal))
            proposal.authorized_command_json = authorized_payload
            proposal.authorized_command_digest = (
                payload_digest(authorized_payload) if authorized_payload is not None else None
            )
            proposal.reviewed_at = utcnow()
            session.commit()
            return proposal

    async def list_for_run(
        self,
        run_id: str,
        *,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict]:
        with self.session_factory() as session:
            await get_run(session, run_id)
            rows = session.execute(
                select(CorrectionProposal)
                .where(CorrectionProposal.run_id == run_id)
                .order_by(CorrectionProposal.created_at)
                .limit(limit)
                .offset(offset)
            ).scalars().all()
            return [
                {
                    "id": row.id,
                    "run_id": row.run_id,
                    "reporter_node_id": row.reporter_node_id,
                    "target_node_id": row.target_node_id,
                    "proposal_type": row.proposal_type,
                    "reason": row.reason,
                    "evidence": row.evidence_json,
                    "status": row.status,
                    "reviewed_by_principal": row.reviewed_by_principal,
                    "reviewed_at": row.reviewed_at,
                    "authorized_command": row.authorized_command_json,
                    "resulting_command_id": row.resulting_command_id,
                    "created_at": row.created_at,
                }
                for row in rows
            ]
