from fastapi import APIRouter, Depends

from tracefence.api.dependencies import (
    call_external_service,
    proof_service,
    require_proof_operator,
)
from tracefence.domain.schemas import ProofResponse

router = APIRouter(prefix="/v1/commands", tags=["proofs"])


@router.get(
    "/{command_id}/proof",
    response_model=ProofResponse,
    dependencies=[Depends(require_proof_operator)],
)
async def command_proof(command_id: str) -> ProofResponse:
    return await call_external_service(lambda: proof_service.build(command_id))
