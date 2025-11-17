"""
Application configuration
Loads settings from environment variables
"""
import os
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Base directory
basedir = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))


class Config:
    """Base configuration"""

    # Security
    SECRET_KEY = os.getenv('SECRET_KEY')
    if not SECRET_KEY:
        raise ValueError("SECRET_KEY not defined! Create a .env file with a secure SECRET_KEY.")

    # Password hashing (OWASP 2023: 600k iterations)
    PASSWORD_HASH_METHOD = os.getenv('PASSWORD_HASH_METHOD', 'pbkdf2:sha256:600000')

    # Session security
    SESSION_COOKIE_SECURE = os.getenv('FLASK_DEBUG', 'False').lower() != 'true'
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Strict'
    PERMANENT_SESSION_LIFETIME = 3600

    # Database
    default_db_path = f"sqlite:///{os.path.join(basedir, 'instance', 'backups.db')}"
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URI', default_db_path)
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Backup path
    BACKUP_BASE_PATH = os.getenv('BACKUP_BASE_PATH', os.path.join(basedir, 'backups'))

    # SSH Security (VULN-003)
    SSH_HOST_KEY_POLICY = os.getenv('SSH_HOST_KEY_POLICY', 'warning').lower()
    SSH_KNOWN_HOSTS_PATH = os.getenv('SSH_KNOWN_HOSTS_PATH', os.path.expanduser('~/.ssh/known_hosts'))

    # Encryption
    ENCRYPTION_KEY = os.getenv('ENCRYPTION_KEY')
    if not ENCRYPTION_KEY:
        raise ValueError(
            "ENCRYPTION_KEY not defined! "
            "Generate a secure key and add it to .env:\n"
            "  python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\"\n"
            "NEVER commit the key to the repository!"
        )

    @staticmethod
    def init_app(app):
        """Initialize application-specific configuration"""
        # Ensure instance path exists
        instance_path = os.path.join(basedir, 'instance')
        if not os.path.exists(instance_path):
            os.makedirs(instance_path)

        # Ensure backup path exists
        if not os.path.exists(Config.BACKUP_BASE_PATH):
            os.makedirs(Config.BACKUP_BASE_PATH)


class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True
    TESTING = False


class ProductionConfig(Config):
    """Production configuration"""
    DEBUG = False
    TESTING = False


class TestingConfig(Config):
    """Testing configuration"""
    DEBUG = True
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'


# Configuration dictionary
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}
