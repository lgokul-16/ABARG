import os
from dotenv import load_dotenv
from datetime import timedelta

load_dotenv()


class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'supersecret123')
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(days=7) # Extend session to 7 days
    uri = os.environ.get('DATABASE_URL', 'sqlite:///ultimatum.db')
    if uri and uri.startswith("postgres://"):
        uri = uri.replace("postgres://", "postgresql://", 1)
    SQLALCHEMY_DATABASE_URI = uri
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Critical for Supabase stability on Railway
    SQLALCHEMY_ENGINE_OPTIONS = {
        "pool_pre_ping": True,
        "pool_recycle": 280,
    }

    # Mail & Supabase
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = os.environ.get('EMAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('EMAIL_APP_PASSWORD')
    MAIL_DEFAULT_SENDER = os.environ.get('EMAIL_USERNAME')

    SUPABASE_URL = os.environ.get('SUPABASE_URL')
    if SUPABASE_URL and not SUPABASE_URL.endswith('/'):
        SUPABASE_URL += '/'
    SUPABASE_KEY = os.environ.get('SUPABASE_SERVICE_ROLE_KEY')

    # Cloudinary
    CLOUDINARY_CLOUD_NAME = os.environ.get('CLOUDINARY_CLOUD_NAME')
    CLOUDINARY_API_KEY = os.environ.get('CLOUDINARY_API_KEY')
    CLOUDINARY_API_SECRET = os.environ.get('CLOUDINARY_API_SECRET')

    # AI
    GEMINI_API_KEY = os.environ.get('GEMINI_API_KEY')