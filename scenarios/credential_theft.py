from auth.authentication import (
    authenticate_and_issue_token,
    authenticate_application,
    get_baseline_context,
)

SUSPICIOUS_CONTEXT = "UNKNOWN-DEVICE-01"

#uses the application's client_id and client_secret to simulate a credential theft scenario
def run_credential_theft_scenario(
    client_id: str, client_secret: str, account_id: str | None = None
) -> dict:
    
    application = authenticate_application(client_id, client_secret)
    if application is None:
        return {
            "scenario": "CREDENTIAL_THEFT",
            "executed": False,
            "detected": False,
            "finding_id": None,
            "detail": "Invalid application credentials.",
        }

    baseline_context = get_baseline_context(application["application_id"])
    if baseline_context is None:
        return {
            "scenario": "CREDENTIAL_THEFT",
            "executed": False,
            "detected": False,
            "finding_id": None,
            "detail": "This application has no prior legitimate activity. Connect it "
            "to an account (send an access request or view an account) "
            "before running this simulation.",
        }

    suspicious_result = authenticate_and_issue_token(
        client_id, client_secret, SUSPICIOUS_CONTEXT, account_id=account_id
    )

    if not suspicious_result.get("success"):
        return {
            "scenario": "CREDENTIAL_THEFT",
            "executed": False,
            "detected": False,
            "finding_id": None,
            "detail": "Authentication failed; check client_id/client_secret",
        }

    return {
        "scenario": "CREDENTIAL_THEFT",
        "executed": True,
        "detected": suspicious_result.get("detected", False),
        "finding_id": suspicious_result.get("finding_id"),
    }
