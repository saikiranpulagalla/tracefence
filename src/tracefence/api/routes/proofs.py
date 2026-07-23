from fastapi import APIRouter, Depends

from tracefence.api.dependencies import call_blocking_service, proof_service, require_operator
from tracefence.domain.schemas import ProofResponse

router = APIRouter(prefix="/v1/commands", tags=["proofs"])


@router.get("/{command_id}/proof", response_model=ProofResponse, dependencies=[Depends(require_operator)])
async def command_proof(command_id: str) -> ProofResponse:
    return await call_blocking_service(lambda: proof_service.build(command_id))
