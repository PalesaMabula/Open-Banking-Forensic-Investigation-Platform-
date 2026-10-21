import httpx

import config

CLIENT_ID = config.INVESTEC_CLIENT_ID
CLIENT_SECRET = config.INVESTEC_CLIENT_SECRET
API_KEY = config.INVESTEC_API_KEY
BASE_URL = config.INVESTEC_BASE_URL

# for authentication use the client credentials flow to get an access tokens 
def get_access_token() -> dict:
   
    url = f"{BASE_URL}/identity/v2/oauth2/token"

    response = httpx.post(
        url,
        auth=(CLIENT_ID, CLIENT_SECRET),
        headers={"x-api-key": API_KEY},
        data={"grant_type": "client_credentials"},
    )
    response.raise_for_status()
    return response.json()

#calls the Investec accounts endpoint to get a list of accounts for the authenticated client
def get_accounts() -> httpx.Response:
    
    token_data = get_access_token()
    access_token = token_data["access_token"]

    url = f"{BASE_URL}/za/pb/v1/accounts"
    response = httpx.get(
        url,
        headers={"Authorization": f"Bearer {access_token}"},
    )
    return response

#for transactions, call the Investec transactions endpoint to get a list of transaction 

def get_account_transactions(account_id: str) -> httpx.Response:
  
    token_data = get_access_token()
    access_token = token_data["access_token"]

    url = f"{BASE_URL}/za/pb/v1/accounts/{account_id}/transactions"
    response = httpx.get(
        url,
        headers={"Authorization": f"Bearer {access_token}"},
    )
    return response
