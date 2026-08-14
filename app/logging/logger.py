import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
from config import Config

class CanaryLogger:
    """Multi-channel structured logging system for CanaryGuard."""
    
    _loggers = {}

    @classmethod
    def get_logger(cls, name: str, log_filename: str = 'system.log', level: str = None) -> logging.Logger:
        """Returns a configured logger instance with rotating file and console handlers."""
        if name in cls._loggers:
            return cls._loggers[name]

        log_dir = Config.LOG_DIR
        log_dir.mkdir(parents=True, exist_ok=True)
        log_path = log_dir / log_filename

        logger = logging.getLogger(name)
        log_level = getattr(logging, (level or Config.LOG_LEVEL).upper(), logging.INFO)
        logger.setLevel(log_level)
        logger.propagate = False

        if not logger.handlers:
            # Formatting
            formatter = logging.Formatter(
                '[%(asctime)s] [%(levelname)s] [%(name)s] - %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )

            # Rotating File Handler (10MB max per file, keep 5 backups)
            file_handler = RotatingFileHandler(
                log_path, maxBytes=10 * 1024 * 1024, backupCount=5, encoding='utf-8'
            )
            file_handler.setFormatter(formatter)
            file_handler.setLevel(log_level)
            logger.addHandler(file_handler)

            # Console Handler
            console_handler = logging.StreamHandler()
            console_handler.setFormatter(formatter)
            console_handler.setLevel(log_level)
            logger.addHandler(console_handler)

        cls._loggers[name] = logger
        return logger

# Pre-defined logger accessors
def get_system_logger():
    return CanaryLogger.get_logger('CanaryGuard.System', 'system.log')

def get_security_logger():
    return CanaryLogger.get_logger('CanaryGuard.Security', 'security.log')

def get_error_logger():
    return CanaryLogger.get_logger('CanaryGuard.Error', 'errors.log')

def get_quarantine_logger():
    return CanaryLogger.get_logger('CanaryGuard.Quarantine', 'quarantine.log')

def get_entropy_logger():
    return CanaryLogger.get_logger('CanaryGuard.Entropy', 'entropy.log')

def get_api_logger():
    return CanaryLogger.get_logger('CanaryGuard.API', 'api.log')
