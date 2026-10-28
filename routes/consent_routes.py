import json

from fastapi import APIRouter, HTTPException

from auth.consent import create_consent, authorize_consent, reject_consent
from forensic.evidence import record_api_interaction, record_forensic_event
from routes.models import ConsentCreateRequest

router = APIRouter()


@router.post("/consents")
def create_consent_endpoint(request: ConsentCreateRequest):
    consent = create_consent(
        application_id=request.application_id,
        customer_id=request.customer_id,
        permissions=request.permissions,
        account_id=request.account_id,
    )

    interaction_id = record_api_interaction(
        http_method="POST",
        endpoint="/consents",
        response_status=200,
        account_id=request.account_id,
        source="TPP",
        destination="OBFIR",
    )
    record_forensic_event(
        interaction_id=interaction_id,
        event_type="CONSENT_CREATED",
        account_id=request.account_id,
        details={
            "consent_id": consent["consent_id"],
            "application_id": consent["application_id"],
            "customer_id": consent["customer_id"],
            "account_id": consent["account_id"],
            "permissions": request.permissions,
            "status": consent["status"],
        },
    )

    return consent


@router.post("/consents/{consent_id}/authorize")
def authorize_consent_endpoint(consent_id: str):
    consent = authorize_consent(consent_id)

    if consent is None:
        raise HTTPException(status_code=404, detail="Consent not found")

    interaction_id = record_api_interaction(
        http_method="POST",
        endpoint=f"/consents/{consent_id}/authorize",
        response_status=200,
        account_id=consent["account_id"],
        source="CUSTOMER",
        destination="OBFIR",
    )
    record_forensic_event(
        interaction_id=interaction_id,
        event_type="CONSENT_AUTHORIZED",
        account_id=consent["account_id"],
        details={
            "consent_id": consent["consent_id"],
            "application_id": consent["application_id"],
            "customer_id": consent["customer_id"],
            "account_id": consent["account_id"],
            "permissions": json.loads(consent["permissions_json"]),
            "status": consent["status"],
        },
    )

    return consent


@router.post("/consents/{consent_id}/reject")
def reject_consent_endpoint(consent_id: str):
    consent = reject_consent(consent_id)

    if consent is None:
        raise HTTPException(status_code=404, detail="Consent not found")

    interaction_id = record_api_interaction(
        http_method="POST",
        endpoint=f"/consents/{consent_id}/reject",
        response_status=200,
        account_id=consent["account_id"],
        source="CUSTOMER",
        destination="OBFIR",
    )
    record_forensic_event(
        interaction_id=interaction_id,
        event_type="CONSENT_REJECTED",
        account_id=consent["account_id"],
        details={
            "consent_id": consent["consent_id"],
            "application_id": consent["application_id"],
            "customer_id": consent["customer_id"],
            "account_id": consent["account_id"],
            "permissions": json.loads(consent["permissions_json"]),
            "status": consent["status"],
        },
    )

    return consent