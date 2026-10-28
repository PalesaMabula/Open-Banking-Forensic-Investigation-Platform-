# OB-FIR — Open Banking Forensic Investigation Platform

OB-FIR is a research prototype that demonstrates how digital forensic readiness can be incorporated into API-driven Open Banking. It operates as a gateway between simulated third-party provider (TPP) applications and a bank's Open API, recording instrumented interactions as tamper-evident evidence to support incident detection and investigation.

The prototype illustrates how investigators can reconstruct activity across the TPP → Gateway → Bank communication chain using event logs, digital signatures, timelines, and chain-of-custody records.

Developed for the COS700 Honours research project, Digital Forensic Science Research Group (DigiForS), Department of Computer Science, University of Pretoria.

## Live demo

**[Launch OB-FIR](https://open-banking-forensic.onrender.com)**

Research demonstration only. OB-FIR uses sandbox banking data and simulated attack scenarios. No real customer accounts or funds are involved. The free hosting service may take approximately a minute to start after inactivity.

The demo provides prefilled sign-in details and an account-selection dropdown. Participants do not need to register, enter their own bank account numbers, or provide personal banking information.

## Why OB-FIR?

Open Banking enables customers to share banking information with authorised third-party applications through APIs. Because interactions involve multiple participants, relevant forensic evidence can be fragmented across systems, making it difficult to reconstruct incidents.

OB-FIR explores how forensic evidence can be captured and preserved at an API gateway so that investigators can review activity, verify evidence integrity, and examine suspicious interactions.

## Key features

- Open Banking simulation: BudgetWise and InsureWise demonstrate different levels of authorised access to banking data.
- Consent management: Customers can approve or reject access requests, and the gateway checks permissions before allowing data access.
- Forensic event capture: Instrumented interactions are recorded with contextual information such as actors, timestamps, and API activity.
- Evidence integrity: SHA-256 hash chaining helps reveal modifications to previously recorded events.
- Digital signatures: Cryptographic signatures support verification of recorded evidence and its origin, subject to protection of the signing key.
- Chain of custody: Records track actions performed on evidence during an investigation.
- Attack detection: Four controlled scenarios generate findings for investigation.
- Investigation workspace: Investigators can review findings, timelines, evidence, and case information.
- Evaluation metrics: The prototype reports detection latency, log completeness, and evidence preservation rate.

## System communication

OB-FIR captures relevant activity across the following interactions:

| Communication | Purpose |
|---|---|
| TPP → Gateway | Authentication, access requests, and API interactions |
| Customer → Gateway | Consent approval or rejection |
| Gateway → Bank | Authorised account and transaction requests to the Investec sandbox |
| Investigator → Gateway | Evidence review, findings, and case actions |

The API Communication, Timeline, and Evidence views help investigators trace recorded events through the prototype.

## Forensic evidence and integrity

| Mechanism | Purpose |
|---|---|
| SHA-256 hash chain | Links recorded events so that modifications to earlier records can be detected during verification. |
| Digital signatures | Allow verification that evidence was signed by the holder of the corresponding private key and has not changed since signing. |
| Chain of custody | Records who performed actions on evidence and when. |
| Public-key verification | Makes it possible to verify signatures using the public key exposed at /forensics/public-key. |

The prototype stores its signing key locally. A production deployment would require stronger key management, access controls, durable evidence storage, and independent audit arrangements.

## Simulated attack scenarios

The following scenarios can be run from Scenario Controls. They are controlled demonstrations and do not attack real systems.

| Scenario | Description | Severity |
|---|---|---|
| Credential Theft | Valid TPP credentials are used from an unfamiliar simulated device context. | HIGH |
| Token Hijacking | A valid access token is replayed from another simulated device context. | CRITICAL |
| Consent-Based Fraud | A TPP attempts to access data beyond its authorised consent. | HIGH |
| Cross-Border Exfiltration | Account-data access is associated with a simulated destination outside South Africa. | CRITICAL |

Each detected scenario produces a finding linked to forensic evidence for further review.

## How to test the live demo

Open https://open-banking-forensic.onrender.com and follow this sequence:

1. BudgetWise: Select a sandbox account from the dropdown and choose Send Access Request.
2. Customer: Load the selected account and Approve the request.
3. BudgetWise: Use View Account and View Transactions to demonstrate authorised access.
4. Scenario Controls: Run one of the simulated attack scenarios.
5. Findings → Investigate: Open the detected finding and review the timeline, evidence, digital-signature verification, and chain-of-custody information.

## Demo roles

| Role | What it demonstrates |
|---|---|
| BudgetWise | Requests access to accounts and transactions. |
| InsureWise | Demonstrates access restricted to accounts only. |
| Customer | Approves or rejects data-sharing requests. |
| Investigator | Reviews incidents, evidence, and case activity. |

The investigator sign-in is prefilled for demonstration. Sandbox account numbers are retrieved automatically and displayed for selection; no real account details are required.

**Shared-demo note:** The hosted instance is for evaluation and may contain activity generated by other visitors. Do not enter real credentials or personal banking information.

## Demo accounts

The prototype seeds fictional local users and TPP clients for testing.

| Account | Username / client ID | Role or permitted access |
|---|---|---|
| Investigator 001 | investigator001 | Lead Investigator |
| Investigator 002 | investigator002 | Forensic Analyst |
| BudgetWise | demo-tpp-client-id | Accounts and transactions |
| InsureWise | insurewise-app-001 | Accounts only |

Demo credential settings are documented in .env.example. The live demo provides prefilled sign-in details. Banking account data is obtained from the Investec sandbox rather than entered by participants.

## Run locally

Requirements: Python 3.10+ and an internet connection.

```bash
git clone https://github.com/PalesaMabula/Open-Banking-Forensic-Investigation-Platform-.git
cd Open-Banking-Forensic-Investigation-Platform-

python -m venv venv
```

Activate the virtual environment:

**Windows PowerShell**
```powershell
.\venv\Scripts\Activate.ps1
```

**macOS / Linux**
```bash
source venv/bin/activate
```

Install dependencies and start the application:

```bash
pip install -r requirements.txt
python app.py
```

- Dashboard: http://127.0.0.1:8001
- API documentation: http://127.0.0.1:8001/docs

On first launch, the application initialises its local database, creates demo accounts, and generates a signing key.

## Configuration

The application loads demonstration settings from .env.example. To override them, copy that file to .env and edit the values. Keep .env, private keys, and any non-public credentials out of version control. Only use credentials explicitly authorised for public sandbox testing.

## Evaluation metrics

| Metric | What it measures |
|---|---|
| Detection latency | Time between a simulated suspicious event and the resulting detection. |
| Log completeness | Proportion of expected events that were successfully recorded. |
| Evidence preservation rate | Proportion of expected evidence items preserved according to the evaluation criteria. |

These metrics describe the prototype's controlled evaluation, not guarantees about real-world forensic performance.

## Technology

Python 3.10+, FastAPI, Uvicorn, httpx, SQLite, cryptography, python-dotenv, HTML, CSS, JavaScript, and the Investec Open API sandbox.

## Project structure

```
app.py          Application entry point
config.py       Environment and configuration settings
auth/           TPP authentication, consent, investigator accounts
banking/        Investec sandbox client and banking access
database/       SQLite schema and database operations
forensic/       Evidence capture, integrity, signing, custody,
                detection, investigation, and evaluation
scenarios/      Controlled attack simulations
routes/         API endpoints
web/            Web dashboard
```

## Troubleshooting

| Problem | Suggested action |
|---|---|
| PowerShell blocks environment activation | Run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned` and retry. |
| Python is not recognised | Install Python 3.10+ with Python added to PATH, or try `py`. |
| `TypeError: unsupported operand type(s) for \|` | Upgrade to Python 3.10 or later. |
| Port 8001 is in use | Stop the other service or change the configured application port. |
| Investec token or account request fails | Check connectivity and sandbox availability. |
| Demo data needs resetting locally | Stop the application, remove the local `data/` folder, and restart. This deletes local evidence and accounts. |

