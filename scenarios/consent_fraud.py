from auth.authentication import validate_access_token
from auth.consent import find_authorized_consent
from banking.access import access_transactions
from forensic.detection import detect_consent_fraud
from forensic.evidence import find_consent_event_ids

SCENARIO_CONTEXT = "TPP-PRIMARY-DEVICE"

#wants access to transactions but only has consent for accounts, so this is a deliberate consent fraud scenario
def run_consent_fraud_scenario(
    access_token: str, account_id: str, customer_id: str | None = None
) -> dict:
    
    token = validate_access_token(access_token)
    if token is None:
        return {
            "scenario": "CONSENT_BASED_FRAUD",
            "executed": False,
            "detected": False,
            "finding_id": None,
            "detail": "Invalid or expired token",
        }

    governing_consent = find_authorized_consent(token["application_id"], "accounts")
    consent_id = governing_consent["consent_id"] if governing_consent else None

    result = access_transactions(
        token, client_context=SCENARIO_CONTEXT, account_id=account_id
    )

    if result.get("success") or result.get("status_code") != 403:
        return {
            "scenario": "CONSENT_BASED_FRAUD",
            "executed": True,
            "detected": False,
            "finding_id": None,
            "detail": "Access was not denied as expected; the application's consent may "
            "already permit 'transactions' — revoke it to run this scenario.",
        }

    consent_event_ids = find_consent_event_ids(consent_id) if consent_id else []
    related_event_ids = consent_event_ids + [result["event_id"]]

    finding = detect_consent_fraud(
        application_id=token["application_id"],
        customer_id=customer_id,
        account_id=account_id,
        consent_id=consent_id,
        required_permission="transactions",
        related_event_ids=related_event_ids,
    )

    return {
        "scenario": "CONSENT_BASED_FRAUD",
        "executed": True,
        "detected": finding is not None,
        "finding_id": finding["finding_id"] if finding else None,
    }
