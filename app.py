from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import uvicorn

from auth.authentication import seed_demo_applications
from auth.consent import seed_demo_consents
from auth.investigator import seed_demo_investigators
from banking.investec import get_access_token, get_accounts
from database.database import init_database, get_connection
from forensic.custody import backfill_created_custody_events
from forensic.integrity import backfill_hash_chain

from routes import (
    auth_routes,
    banking_routes,
    case_routes,
    consent_routes,
    forensics_routes,
    investigator_routes,
    open_banking_routes,
    scenario_routes,
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_database()
    backfill_hash_chain()
    seed_demo_applications()
    seed_demo_consents()
    seed_demo_investigators()
    backfill_created_custody_events()
    yield


app = FastAPI(title="Open Banking Forensic", lifespan=lifespan)

app.mount("/static", StaticFiles(directory="web"), name="static")

app.include_router(auth_routes.router)
app.include_router(consent_routes.router)
app.include_router(open_banking_routes.router)
app.include_router(banking_routes.router)
app.include_router(forensics_routes.router)
app.include_router(investigator_routes.router)
app.include_router(case_routes.router)
app.include_router(scenario_routes.router)


@app.get("/")
def root():
    return FileResponse("web/index.html")


@app.get("/health")
def health():
    return {"status": "ok", "application": "OB-FIR"}


@app.get("/investec/token-test")
def investec_token_test():
    token_data = get_access_token()
    return {
        "status": "ok",
        "token_type": token_data.get("token_type"),
        "expires_in": token_data.get("expires_in"),
        "scope": token_data.get("scope"),
    }

@app.get("/sandbox/accounts")
def sandbox_accounts():
    """Demo helper: lists the live Investec sandbox accounts so the UI can
    offer them as a dropdown. This is a convenience for demonstration only
    and is not part of the consented Open Banking data-access flow."""
    try:
        response = get_accounts()
        response.raise_for_status()
        payload = response.json()
    except Exception as exc:  # noqa: BLE001 - surface any failure to the UI
        return {"status": "error", "detail": str(exc), "accounts": []}

    raw_accounts = payload.get("data", {}).get("accounts", [])
    accounts = [
        {
            "accountId": acc.get("accountId"),
            "accountName": acc.get("accountName")
            or acc.get("productName")
            or "Account",
            "productName": acc.get("productName") or "",
        }
        for acc in raw_accounts
        if acc.get("accountId")
    ]
    return {"status": "ok", "accounts": accounts}

@app.get("/database/status")
def database_status():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = [row[0] for row in cursor.fetchall()]
    conn.close()
    return {"status": "ok", "database": "connected", "tables": tables}


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8001)