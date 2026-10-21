from pydantic import BaseModel


class TokenRequest(BaseModel):
    client_id: str
    client_secret: str


class ConsentCreateRequest(BaseModel):
    application_id: str
    customer_id: str
    account_id: str | None = None
    permissions: list[str]


class CustodyActionRequest(BaseModel):
    actor: str
    action: str
    from_holder: str | None = None
    to_holder: str | None = None
    reason: str | None = None


class CredentialTheftScenarioRequest(BaseModel):
    client_id: str
    client_secret: str


class TokenHijackingScenarioRequest(BaseModel):
    client_id: str
    client_secret: str


class ConsentFraudScenarioRequest(BaseModel):
    access_token: str
    account_id: str
    customer_id: str | None = None


class CrossBorderScenarioRequest(BaseModel):
    access_token: str


class FindingStatusUpdateRequest(BaseModel):
    status: str
    actor: str = "INVESTIGATOR_001"


class MarkAnalysedRequest(BaseModel):
    actor: str = "INVESTIGATOR_001"
    reason: str | None = None


class AccessRequestCreate(BaseModel):
    account_id: str
    permissions: list[str]


class AccountIdBody(BaseModel):
    account_id: str


class ScenarioAccountBody(BaseModel):
    account_id: str


class InvestigatorLoginRequest(BaseModel):
    username: str
    password: str


class InvestigatorCreateRequest(BaseModel):
    display_name: str
    username: str
    password: str
    role: str
    status: str = "ACTIVE"


class InvestigatorUpdateRequest(BaseModel):
    display_name: str | None = None
    role: str | None = None
    status: str | None = None


class CaseCreateRequest(BaseModel):
    title: str
    assigned_investigator_id: str | None = None
    account_id: str | None = None
    finding_id: str | None = None
    description: str | None = None


class CaseReassignRequest(BaseModel):
    investigator_id: str


class CaseStatusRequest(BaseModel):
    status: str


class EvidenceActionRequest(BaseModel):
    reason: str | None = None