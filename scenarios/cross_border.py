from auth.authentication import validate_access_token
from banking.access import access_accounts

SCENARIO_CONTEXT = "TPP-PRIMARY-DEVICE"
FOREIGN_DESTINATION = "GB"


def run_cross_border_scenario(access_token: str, account_id: str | None = None) -> dict:
    token = validate_access_token(access_token)
    if token is None:
        return {
            "scenario": "CROSS_BORDER_DATA_EXFILTRATION",
            "executed": False,
            "detected": False,
            "finding_id": None,
            "detail": "Invalid or expired token",
        }

    result = access_accounts(
        token,
        client_context=SCENARIO_CONTEXT,
        account_id=account_id,
        destination_country=FOREIGN_DESTINATION,
    )

    if not result.get("success"):
        return {
            "scenario": "CROSS_BORDER_DATA_EXFILTRATION",
            "executed": True,
            "detected": False,
            "finding_id": None,
            "detail": "Access was not successful; this application may not have an "
            "authorized 'accounts' consent for this account.",
        }

    return {
        "scenario": "CROSS_BORDER_DATA_EXFILTRATION",
        "executed": True,
        "detected": bool(result.get("cross_border_finding_id")),
        "finding_id": result.get("cross_border_finding_id"),
    }
