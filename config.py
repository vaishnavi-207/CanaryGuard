import os
from pathlib import Path

# Set default timezone to IST
os.environ['TZ'] = 'Asia/Kolkata'

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

BASE_DIR = Path(__file__).resolve().parent

class Config:
    """Base Configuration Class for CanaryGuard EDR Platform."""
    SECRET_KEY = os.getenv('SECRET_KEY', 'canaryguard-secret-key-super-secure-dev')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Path configuration
    DB_DIR = BASE_DIR / 'database'
    LOG_DIR = BASE_DIR / 'logs'
    REPORTS_DIR = BASE_DIR / 'reports'
    QUARANTINE_DIR = BASE_DIR / 'quarantine_store'
    TEST_MONITOR_DIR = BASE_DIR / 'monitored_test'
    
    # SQLite Database URI
    SQLALCHEMY_DATABASE_URI = os.getenv(
        'DATABASE_URL', 
        f"sqlite:///{DB_DIR / 'canaryguard.db'}"
    )
    
    # Ransomware & Behavioral Analysis Thresholds
    DEFAULT_ENTROPY_THRESHOLD = float(os.getenv('DEFAULT_ENTROPY_THRESHOLD', '7.2'))
    MAX_FILE_BURST_COUNT = int(os.getenv('MAX_FILE_BURST_COUNT', '10'))
    BURST_TIME_WINDOW_SECONDS = int(os.getenv('BURST_TIME_WINDOW_SECONDS', '3'))
    AUTO_QUARANTINE_ENABLED = os.getenv('AUTO_QUARANTINE_ENABLED', 'true').lower() in ('true', '1', 'yes')
    
    # Log Level
    LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')

    @classmethod
    def init_app(cls, app):
        """Ensure necessary directories exist on initialization."""
        cls.DB_DIR.mkdir(parents=True, exist_ok=True)
        cls.LOG_DIR.mkdir(parents=True, exist_ok=True)
        cls.REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        cls.QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
        cls.TEST_MONITOR_DIR.mkdir(parents=True, exist_ok=True)

class DevelopmentConfig(Config):
    DEBUG = True

class TestingConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    DEFAULT_ENTROPY_THRESHOLD = 7.0

class ProductionConfig(Config):
    DEBUG = False

config_by_name = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}
