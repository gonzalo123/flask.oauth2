import os
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent
ENVIRONMENT = os.getenv('ENVIRONMENT', 'local')

load_dotenv(dotenv_path=Path(BASE_DIR).resolve().joinpath('env', ENVIRONMENT, '.env'))

SECRET = 'BAD_SECRET_KEY'

SESSION = dict(
    SESSION_PERMANENT=False,
    SESSION_TYPE="filesystem",
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_DOMAIN=False,
)

OAUTH = dict(
    CLIENT_ID=os.getenv('CLIENT_ID'),
    CLIENT_SECRET=os.getenv('CLIENT_SECRET'),
    TOKEN_URL=os.getenv('TOKEN_URL'),
    AUTHORIZE_URL=os.getenv('AUTHORIZE_URL'),
    USER_URL=os.getenv('USER_URL'),
    REDIRECT_URL=os.getenv('REDIRECT_URL'),
)
