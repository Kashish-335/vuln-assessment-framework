"""
Configuration module for the Vulnerability Assessment Framework and Mini WAF.
Loads environment variables from .env with secure academic defaults.
"""
import os
from pathlib import Path
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent

# Load .env file if it exists, otherwise rely on environment variables
env_path = BASE_DIR / '.env'
if env_path.exists():
    load_dotenv(dotenv_path=env_path)
else:
    load_dotenv()

class Config:
    # Flask Settings - loaded strictly from environment (no hardcoded fallback)
    SECRET_KEY = os.getenv('SECRET_KEY')
    DEBUG = os.getenv('FLASK_DEBUG', 'False').lower() in ('true', '1', 't')

    # SQLite Database
    DATABASE_PATH = BASE_DIR / 'assessment_framework.db'
    SQLALCHEMY_DATABASE_URI = f"sqlite:///{DATABASE_PATH}"
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # OWASP ZAP API Daemon - loaded strictly from environment (no hardcoded fallback)
    ZAP_URL = os.getenv('ZAP_URL', 'http://localhost:8090')
    ZAP_API_KEY = os.getenv('ZAP_API_KEY')

    # Ports & Upstream targets
    DASHBOARD_PORT = int(os.getenv('DASHBOARD_PORT', '5000'))
    WAF_PORT = int(os.getenv('WAF_PORT', '8080'))
    UPSTREAM_TARGET_URL = os.getenv('UPSTREAM_TARGET_URL', 'http://localhost:3000')

    # Rate Limiting
    WAF_RATE_LIMIT_RPM = int(os.getenv('WAF_RATE_LIMIT_RPM', '60'))

    # Reports
    REPORTS_DIR = BASE_DIR / 'reports' / 'generated'
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
