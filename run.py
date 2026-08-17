import os
from app import create_app
from app.websocket.events import socketio
from app.logging.logger import get_system_logger

logger = get_system_logger()
app = create_app(os.getenv('FLASK_ENV', 'development'))

if __name__ == '__main__':
    host = os.getenv('HOST', '127.0.0.1')
    port = int(os.getenv('PORT', 5001))
    debug = os.getenv('FLASK_DEBUG', 'false').lower() in ('true', '1', 'yes')
    use_reloader = False
    logger.info(f"Launching CanaryGuard EDR Server on http://{host}:{port}")
    print(f" * Running on http://{host}:{port}")
    socketio.run(
        app,
        host=host,
        port=port,
        debug=debug,
        use_reloader=use_reloader,
        allow_unsafe_werkzeug=True
    )
