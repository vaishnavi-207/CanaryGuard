import os
from flask import Flask

from config import config_by_name
from app.database.db import db
from app.websocket.events import (
    socketio,
    register_socket_events,
    broadcast_threat_alert,
    broadcast_dashboard_update,
)
from app.monitoring.file_monitor import FileMonitorManager
from app.services.detection_engine import BehavioralDetectionEngine
from app.logging.logger import get_system_logger

logger = get_system_logger()


def create_app(config_name: str = "development") -> Flask:
    """Application factory for CanaryGuard EDR."""

    app = Flask(
        __name__,
        template_folder="../templates",
        static_folder="../static",
    )

    config_obj = config_by_name.get(
        config_name,
        config_by_name["default"],
    )

    app.config.from_object(config_obj)
    config_obj.init_app(app)

    # Initialize Extensions
    db.init_app(app)
    socketio.init_app(app, cors_allowed_origins="*")
    register_socket_events(socketio)

    # Callback for filesystem events
    def handle_filesystem_event(event_data):
        with app.app_context():
            result = BehavioralDetectionEngine.evaluate_and_respond(
                event_data,
                auto_quarantine=app.config["AUTO_QUARANTINE_ENABLED"],
            )
            broadcast_threat_alert(result)
            broadcast_dashboard_update()

    # Initialize File Monitor
    app.monitor_manager = FileMonitorManager(
        app=app,
        callback_event=handle_filesystem_event,
    )

    # Register Blueprints
    from app.routes.main_routes import main_bp
    from app.routes.api_routes import api_bp

    app.register_blueprint(main_bp)
    app.register_blueprint(api_bp)

    # Create database tables
    with app.app_context():
        db.create_all()
        seed_default_settings()

    logger.info("CanaryGuard Application Initialized Successfully.")

    return app


def seed_default_settings():
    from app.models.system_setting import SystemSetting

    default_settings = [
        (
            "entropy_threshold",
            "7.2",
            "float",
            "Shannon entropy threshold for ransomware encryption detection",
        ),
        (
            "auto_quarantine",
            "true",
            "bool",
            "Automatically suspend and terminate processes triggering threats",
        ),
        (
            "burst_rate_threshold",
            "10",
            "int",
            "Maximum allowed file modifications in rolling 3s window",
        ),
        (
            "log_level",
            "INFO",
            "string",
            "Global application logging verbosity",
        ),
    ]

    for key, value, dtype, desc in default_settings:
        setting = SystemSetting.query.filter_by(key=key).first()

        if not setting:
            db.session.add(
                SystemSetting(
                    key=key,
                    value=value,
                    data_type=dtype,
                    description=desc,
                )
            )

    db.session.commit()