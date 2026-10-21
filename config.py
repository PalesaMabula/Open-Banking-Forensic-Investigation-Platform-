import os
from pathlib import Path
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent

# Use .env if present; otherwise fall back to the committed sandbox defaults
_env_file = BASE_DIR / ".env"
load_dotenv(_env_file if _env_file.exists() else BASE_DIR / ".env.example")

INVESTEC_CLIENT_ID = os.getenv("INVESTEC_CLIENT_ID")
INVESTEC_CLIENT_SECRET = os.getenv("INVESTEC_CLIENT_SECRET")
INVESTEC_API_KEY = os.getenv("INVESTEC_API_KEY")
INVESTEC_BASE_URL = os.getenv("INVESTEC_BASE_URL")

OBFIR_TPP_CLIENT_ID = os.getenv("OBFIR_TPP_CLIENT_ID")
OBFIR_TPP_CLIENT_SECRET = os.getenv("OBFIR_TPP_CLIENT_SECRET")

OBFIR_APP2_CLIENT_ID = os.getenv("OBFIR_APP2_CLIENT_ID")
OBFIR_APP2_CLIENT_SECRET = os.getenv("OBFIR_APP2_CLIENT_SECRET")

OBFIR_INV001_USERNAME = os.getenv("OBFIR_INV001_USERNAME")
OBFIR_INV001_PASSWORD = os.getenv("OBFIR_INV001_PASSWORD")
OBFIR_INV002_USERNAME = os.getenv("OBFIR_INV002_USERNAME")
OBFIR_INV002_PASSWORD = os.getenv("OBFIR_INV002_PASSWORD")

DATA_DIR = BASE_DIR / "data"
DATABASE_PATH = DATA_DIR / "obfir.db"
