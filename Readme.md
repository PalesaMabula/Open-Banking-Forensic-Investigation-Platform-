# OB-FIR: Open Banking Forensic Investigation Platform

A research prototype that adds forensic readiness to API-driven Open Banking. OB-FIR sits between third-party provider (TPP) applications and a bank's Open API. It captures every interaction as tamper-evident evidence, detects four attack scenarios, and supports investigators with timelines, chain of custody and case management.


## Features

- **Investec sandbox integration:** OAuth 2.0 client-credentials flow to retrieve accounts and transactions
- **Simulated TPP apps:** BudgetWise (accounts + transactions) and InsureWise (accounts only)
- **Consent enforcement:** customers authorise or reject consents, which expire after 90 days and are checked on every request
- **Forensic event capture:** every API interaction is logged with actor, account, context and timestamp
- **Evidence integrity:** SHA-256 hash chain in which each event's hash includes the previous one, so any change is detectable
- **Chain of custody:** a separate hash chain records who created, accessed, verified, analysed or transferred each evidence item
- **Investigation and cases:** incident summaries, reconstructed timelines, and investigator logins for case assignment
- **Evaluation metrics:** detection latency, log completeness and evidence preservation rate
- **Web dashboard:** served directly by the backend

## Tech Stack

Python 3.10+, FastAPI, Uvicorn, httpx, SQLite, python-dotenv, plain HTML/CSS/JavaScript, and the Investec Open API (sandbox).

## Project Structure

```
app.py          Entry point
config.py       Loads settings from .env
auth/           TPP authentication, consent, investigator accounts
banking/        Investec sandbox client and consent-checked data access
database/       SQLite schema and queries
forensic/       Evidence capture, integrity, custody, detection, investigation, evaluation
scenarios/      Controlled attack simulations
routes/         API endpoints
web/            Dashboard
```

## Getting Started

**Prerequisites:** Python 3.10+ and an internet connection. No configuration needed.

```bash
git clone https://github.com/<your-username>/Open-Banking-Forensic-Investigation-Platform.git
cd Open-Banking-Forensic-Investigation-Platform

python -m venv venv
venv\Scripts\activate          # macOS/Linux: source venv/bin/activate
pip install -r requirements.txt

python app.py
```

Open http://127.0.0.1:8001 for the dashboard, or http://127.0.0.1:8001/docs for the API documentation.

On first run, OB-FIR creates a local database and seeds the demo accounts.

**Configuration:** settings are loaded from `.env.example`, which contains Investec's public sandbox credentials and the demo accounts. To use different credentials, copy it to `.env` and edit that file; `.env` takes priority when it exists.

## Demo Accounts

These are **local, fictional** accounts created from `.env.example`. They exist only on your machine.

| Account | Default username / client ID | Role / consent |
|---|---|---|
| Investigator 001 | `investigator001` | Lead Investigator |
| Investigator 002 | `investigator002` | Forensic Analyst |
| BudgetWise | `demo-tpp-client-id` | accounts + transactions |
| InsureWise | `insurewise-app-001` | accounts only |

Default passwords are in `.env.example`. You don't need to configure bank account numbers: the app fetches the sandbox test accounts live from Investec.

## Attack Scenarios

Run these from **Scenario Controls** in the dashboard. They are controlled, local simulations.

| Scenario | Simulation | Severity |
|---|---|---|
| Credential Theft | Valid TPP credentials used from an unknown device | HIGH |
| Token Hijacking | A valid bearer token replayed from another device | CRITICAL |
| Consent-Based Fraud | InsureWise tries to read transactions without consent | HIGH |
| Cross-Border Exfiltration | Account data sent to a destination outside South Africa | CRITICAL |

Each detection creates a finding linked to its evidence, which an investigator can open to view the timeline, related evidence and custody history.

## Troubleshooting

| Problem | Fix |
|---|---|
| `venv\Scripts\activate` is blocked in PowerShell | Run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned`, then activate again |
| `python` is not recognised | Install Python 3.10+ and tick **Add Python to PATH**, or use `py` instead of `python` |
| `TypeError: unsupported operand type(s) for \|` | Your Python version is older than 3.10. Upgrade Python |
| Port 8001 is already in use | Close the other program using it, or change `port=8001` at the bottom of `app.py` |
| `/investec/token-test` or account data returns an error | Check your internet connection. The Investec sandbox may also be temporarily unavailable. Try again later |
| Investigator login fails after changing passwords | Demo accounts are only created on the first run. Stop the app, delete `data/obfir.db`, and restart |
| You want to start with a clean database | Stop the app, delete the `data/` folder, and restart |