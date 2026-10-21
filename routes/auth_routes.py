from fastapi import APIRouter, Header, HTTPException

from auth.authentication import authenticate_and_issue_token
from routes.models import TokenRequest

router = APIRouter()


@router.post("/auth/token")
def auth_token(
    request: TokenRequest,
    x_client_context: str | None = Header(default=None, alias="X-Client-Context"),
):
    client_context = x_client_context or "UNSPECIFIED-CONTEXT"
    result = authenticate_and_issue_token(
        request.client_id, request.client_secret, client_context
    )

    if not result["success"]:
        raise HTTPException(status_code=401, detail="Invalid client credentials")

    return {
        "access_token": result["raw_token"],
        "token_type": "bearer",
        "expires_in": result["expires_in"],
    }