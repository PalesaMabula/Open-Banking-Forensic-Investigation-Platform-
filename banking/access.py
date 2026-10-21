from banking.investec import get_accounts, get_account_transactions
from forensic.evidence import (
    record_api_interaction,
    record_forensic_event,
    find_events_by_token_fingerprint,
)
from forensic.detection import (
    check_token_context_consistency,
    detect_token_hijacking,
    detect_cross_border_exfiltration,
)
from auth.consent import find_authorized_consent

TOKEN_EVENT_TYPES = [
    "TOKEN_ISSUED",
    "ACCOUNT_DATA_ACCESSED",
    "TRANSACTION_DATA_ACCESSED",
]

# to detect token hijacking, we look for a token being used in a different client context than it was originally issue
# If the same client context is used, it's not considered hijackin
# If a different client context is used, we check if there are any prior contexts for this token
# If there are, and the current context is not one of them, we consider it a potential hijacking event
def _maybe_detect_hijacking(token, application_id, client_context, account_id):
   
    prior_contexts = check_token_context_consistency(token["token_hash"])
   
    if len(prior_contexts) <= 1:
        return None

  
    if client_context not in prior_contexts:
        return None

    earlier_contexts = [c for c in prior_contexts if c != client_context]
    if not earlier_contexts:
        return None

   
    from forensic.detection import get_findings
    import json as _json

    existing = [
        f
        for f in get_findings()
        if f["scenario_type"] == "TOKEN_HIJACKING"
        and f.get("token_fingerprint") == token["token_hash"]
    ]
    if existing:
        return None

    token_related_ids = find_events_by_token_fingerprint(
        token["token_hash"], event_types=TOKEN_EVENT_TYPES
    )
    finding = detect_token_hijacking(
        token_fingerprint=token["token_hash"],
        application_id=application_id,
        new_context=client_context,
        related_event_ids=token_related_ids,
        account_id=account_id,
    )
    return finding["finding_id"] if finding else None


def access_accounts(
    token: dict,
    client_context: str,
    account_id: str | None = None,
    destination_country: str = "ZA",
) -> dict:
    endpoint = "/banking/accounts"
    application_id = token["application_id"]

    consent = find_authorized_consent(application_id, "accounts", account_id=account_id)
    if consent is None:
        interaction_id = record_api_interaction(
            http_method="GET",
            endpoint=endpoint,
            response_status=403,
            account_id=account_id,
        )
        event_id = record_forensic_event(
            interaction_id=interaction_id,
            event_type="CONSENT_PERMISSION_DENIED",
            account_id=account_id,
            details={
                "application_id": application_id,
                "required_permission": "accounts",
                "account_id": account_id,
                "token_fingerprint": token["token_hash"],
            },
        )
        return {
            "success": False,
            "status_code": 403,
            "detail": "No authorized consent for 'accounts'",
            "event_id": event_id,
        }

    try:
        response = get_accounts()
    except Exception:
        interaction_id = record_api_interaction(
            http_method="GET",
            endpoint=endpoint,
            response_status=500,
            account_id=account_id,
        )
        event_id = record_forensic_event(
            interaction_id=interaction_id,
            event_type="ACCOUNT_ACCESS_FAILED",
            details={"resource": "accounts", "provider": "Investec Sandbox"},
        )
        return {
            "success": False,
            "status_code": 502,
            "detail": "Failed to reach Investec",
            "event_id": event_id,
        }

    interaction_id = record_api_interaction(
        http_method="GET",
        endpoint=endpoint,
        response_status=response.status_code,
        account_id=account_id,
    )

    if response.status_code != 200:
        event_id = record_forensic_event(
            interaction_id=interaction_id,
            event_type="ACCOUNT_ACCESS_FAILED",
            details={"resource": "accounts", "provider": "Investec Sandbox"},
        )
        return {
            "success": False,
            "status_code": response.status_code,
            "detail": "Investec request failed",
            "event_id": event_id,
        }

    access_event_id = record_forensic_event(
        interaction_id=interaction_id,
        event_type="ACCOUNT_DATA_ACCESSED",
        account_id=account_id,
        details={
            "resource": "accounts",
            "provider": "Investec Sandbox",
            "application_id": application_id,
            "account_id": account_id,
            "consent_id": consent["consent_id"],
            "token_fingerprint": token["token_hash"],
            "client_context": client_context,
            "destination_country": destination_country,
        },
    )

    hijack_finding_id = _maybe_detect_hijacking(
        token, application_id, client_context, account_id
    )

    cross_border_finding_id = None
    if destination_country != "ZA":
        token_related_ids = find_events_by_token_fingerprint(
            token["token_hash"], event_types=TOKEN_EVENT_TYPES
        )
        finding = detect_cross_border_exfiltration(
            application_id=application_id,
            account_id=account_id,
            destination_country=destination_country,
            related_event_ids=token_related_ids,
        )
        cross_border_finding_id = finding["finding_id"] if finding else None

    return {
        "success": True,
        "status_code": 200,
        "data": response.json(),
        "consent": consent,
        "event_id": access_event_id,
        "hijack_finding_id": hijack_finding_id,
        "cross_border_finding_id": cross_border_finding_id,
    }


def access_transactions(
    token: dict, client_context: str, account_id: str, destination_country: str = "ZA"
) -> dict:
    endpoint = f"/banking/accounts/{account_id}/transactions"
    application_id = token["application_id"]

    consent = find_authorized_consent(
        application_id, "transactions", account_id=account_id
    )
    if consent is None:
        interaction_id = record_api_interaction(
            http_method="GET",
            endpoint=endpoint,
            response_status=403,
            account_id=account_id,
        )
        event_id = record_forensic_event(
            interaction_id=interaction_id,
            event_type="CONSENT_PERMISSION_DENIED",
            account_id=account_id,
            details={
                "application_id": application_id,
                "required_permission": "transactions",
                "account_id": account_id,
                "token_fingerprint": token["token_hash"],
            },
        )
        return {
            "success": False,
            "status_code": 403,
            "detail": "No authorized consent for 'transactions'",
            "event_id": event_id,
        }

    try:
        response = get_account_transactions(account_id)
    except Exception:
        interaction_id = record_api_interaction(
            http_method="GET",
            endpoint=endpoint,
            response_status=500,
            account_id=account_id,
        )
        event_id = record_forensic_event(
            interaction_id=interaction_id,
            event_type="TRANSACTION_ACCESS_FAILED",
            account_id=account_id,
            details={
                "resource": "transactions",
                "provider": "Investec Sandbox",
                "account_id": account_id,
            },
        )
        return {
            "success": False,
            "status_code": 502,
            "detail": "Failed to reach Investec",
            "event_id": event_id,
        }

    interaction_id = record_api_interaction(
        http_method="GET",
        endpoint=endpoint,
        response_status=response.status_code,
        account_id=account_id,
    )

    if response.status_code != 200:
        event_id = record_forensic_event(
            interaction_id=interaction_id,
            event_type="TRANSACTION_ACCESS_FAILED",
            account_id=account_id,
            details={
                "resource": "transactions",
                "provider": "Investec Sandbox",
                "account_id": account_id,
            },
        )
        return {
            "success": False,
            "status_code": response.status_code,
            "detail": "Investec request failed",
            "event_id": event_id,
        }

    access_event_id = record_forensic_event(
        interaction_id=interaction_id,
        event_type="TRANSACTION_DATA_ACCESSED",
        account_id=account_id,
        details={
            "resource": "transactions",
            "provider": "Investec Sandbox",
            "account_id": account_id,
            "application_id": application_id,
            "consent_id": consent["consent_id"],
            "token_fingerprint": token["token_hash"],
            "client_context": client_context,
            "destination_country": destination_country,
        },
    )

    hijack_finding_id = _maybe_detect_hijacking(
        token, application_id, client_context, account_id
    )

    cross_border_finding_id = None
    if destination_country != "ZA":
        token_related_ids = find_events_by_token_fingerprint(
            token["token_hash"], event_types=TOKEN_EVENT_TYPES
        )
        finding = detect_cross_border_exfiltration(
            application_id=application_id,
            account_id=account_id,
            destination_country=destination_country,
            related_event_ids=token_related_ids,
        )
        cross_border_finding_id = finding["finding_id"] if finding else None

    return {
        "success": True,
        "status_code": 200,
        "data": response.json(),
        "consent": consent,
        "event_id": access_event_id,
        "hijack_finding_id": hijack_finding_id,
        "cross_border_finding_id": cross_border_finding_id,
    }
#bypass the consent check and just return the account view for a given account_id, to test 

def get_customer_account_view(account_id: str) -> dict:
   
    try:
        accounts_response = get_accounts()
    except Exception:
        return {"success": False, "detail": "Failed to reach Investec"}

    if accounts_response.status_code != 200:
        return {"success": False, "detail": "Investec request failed"}

    accounts_json = accounts_response.json()
    accounts_list = (
        accounts_json.get("accounts")
        or accounts_json.get("data", {}).get("accounts")
        or []
    )

    matched_account = None
    for acc in accounts_list:
        if acc.get("accountId") == account_id:
            matched_account = acc
            break

    if matched_account is None:
        return {"success": False, "detail": "Account not found"}

    transactions = []
    try:
        transactions_response = get_account_transactions(account_id)
        if transactions_response.status_code == 200:
            transactions_json = transactions_response.json()
            transactions = (
                transactions_json.get("transactions")
                or transactions_json.get("data", {}).get("transactions")
                or []
            )
    except Exception:
        pass

    return {"success": True, "account": matched_account, "transactions": transactions}
