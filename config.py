import os
from dotenv import load_dotenv

load_dotenv()


class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret')
    # Use the variable from Railway
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL')
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Force SQLAlchemy to use a safer connection pool for cloud environments
    SQLALCHEMY_ENGINE_OPTIONS = {
        "pool_pre_ping": True,
        "pool_recycle": 280,
        "connect_args": {
            "connect_timeout": 10,
            "keepalives": 1,
            "keepalives_idle": 30,
            "keepalives_interval": 10,
            "keepalives_count": 5
        }
    }

    # Mail & Supabase
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = os.environ.get('EMAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('EMAIL_APP_PASSWORD')
    MAIL_DEFAULT_SENDER = os.environ.get('EMAIL_USERNAME')

    SUPABASE_URL = os.environ.get('SUPABASE_URL')
    SUPABASE_KEY = os.environ.get('SUPABASE_SERVICE_ROLE_KEY')