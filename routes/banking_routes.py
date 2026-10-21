from fastapi import APIRouter, Depends, Header, HTTPException

from auth.authentication import get_current_token
from banking.access import access_accounts, access_transactions

router = APIRouter()


@router.get("/banking/accounts")
def banking_accounts(
    token: dict = Depends(get_current_token),
    x_client_context: str | None = Header(default=None, alias="X-Client-Context"),
):
    client_context = x_client_context or "UNSPECIFIED-CONTEXT"
    result = access_accounts(token, client_context)

    if not result["success"]:
        raise HTTPException(
            status_code=result["status_code"],
            detail=result.get("detail", "Request failed"),
        )

    return result["data"]


@router.get("/banking/accounts/{account_id}/transactions")
def banking_account_transactions(
    account_id: str,
    token: dict = Depends(get_current_token),
    x_client_context: str | None = Header(default=None, alias="X-Client-Context"),
):
    client_context = x_client_context or "UNSPECIFIED-CONTEXT"
    result = access_transactions(token, client_context, account_id)

    if not result["success"]:
        raise HTTPException(
            status_code=result["status_code"],
            detail=result.get("detail", "Request failed"),
        )

    return result["data"]