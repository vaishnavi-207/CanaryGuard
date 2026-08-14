from flask_socketio import SocketIO, emit
from typing import Dict, Any, Optional
from app.logging.logger import get_system_logger

logger = get_system_logger()
socketio = SocketIO(cors_allowed_origins="*")

def register_socket_events(socketio_instance: SocketIO):
    """Registers WebSocket handlers with SocketIO instance."""

    @socketio_instance.on('connect')
    def handle_connect():
        logger.info("WebSocket Client Connected to Dashboard Stream.")
        emit('connection_response', {'status': 'connected', 'message': 'CanaryGuard Real-Time Gateway Active'})

    @socketio_instance.on('disconnect')
    def handle_disconnect():
        logger.info("WebSocket Client Disconnected.")

    @socketio_instance.on('ping_status')
    def handle_ping():
        emit('pong_status', {'server_time': str(socketio_instance.server)})

def broadcast_threat_alert(payload: Dict[str, Any]):
    """Broadcast real-time threat alert to all connected dashboard clients."""
    socketio.emit('threat_alert', payload)

def broadcast_monitoring_status(status_payload: Dict[str, Any]):
    """Broadcast monitor status change."""
    socketio.emit('monitoring_status', status_payload)

def broadcast_dashboard_update(data: Optional[Dict[str, Any]] = None):
    """Broadcast dashboard metric updates."""
    if data is None:
        from app.models.incident import Incident
        from app.models.canary_file import CanaryFile
        from app.models.quarantine_history import QuarantineHistory

        data = {
            'total_incidents': Incident.query.count(),
            'active_incidents': Incident.query.filter_by(status='ACTIVE').count(),
            'canary_count': CanaryFile.query.filter_by(is_active=True).count(),
            'quarantine_count': QuarantineHistory.query.count()
        }
    socketio.emit('dashboard_update', data)
