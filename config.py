"""
Configuration for QR Code Scam Prevention System
"""
import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))


class Config:
    """Base configuration."""
    SECRET_KEY = os.environ.get('SECRET_KEY', 'qr-scam-prevention-secret-key-2026')

    # ---- Database ----
    # Default: SQLite (works out-of-the-box, no setup needed)
    # For MySQL, set the environment variable DATABASE_URL
    # Example: mysql+pymysql://root:password@localhost/qr_scam_db
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        'DATABASE_URL',
        'sqlite:///' + os.path.join(BASE_DIR, 'qr_scam.db')
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # ---- File Uploads ----
    UPLOAD_FOLDER = os.path.join(BASE_DIR, 'static', 'uploads')
    MAX_CONTENT_LENGTH = 5 * 1024 * 1024  # 5 MB max upload
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'bmp', 'webp'}


class DevelopmentConfig(Config):
    DEBUG = True


class ProductionConfig(Config):
    DEBUG = False


config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}
