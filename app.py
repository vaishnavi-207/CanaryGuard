import os
from app import create_app

app = create_app(os.getenv('FLASK_ENV', 'development'))

if __name__ == '__main__':
    from app.websocket.events import socketio
    host = os.getenv('HOST', '127.0.0.1')
    port = int(os.getenv('PORT', 5000))
    debug = os.getenv('FLASK_DEBUG', 'false').lower() in ('true', '1', 'yes')
    use_reloader = os.getenv('FLASK_USE_RELOADER', 'false').lower() in ('true', '1', 'yes')
    print(f" * Running on http://{host}:{port}")
    socketio.run(app, host=host, port=port, debug=debug, use_reloader=use_reloader, allow_unsafe_werkzeug=True)

