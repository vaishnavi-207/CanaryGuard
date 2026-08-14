# CanaryGuard Deployment Guide

## Production Deployment with Gunicorn / Gevent

1. **Install Production Server**:
   ```bash
   pip install gevent gevent-websocket gunicorn
   ```

2. **Run Application**:
   ```bash
   gunicorn --worker-class geventwebsocket.gunicorn.workers.GeventWebSocketWorker -w 1 run:app
   ```

3. **System Service (systemd on Linux)**:
   Create `/etc/systemd/system/canaryguard.service`:
   ```ini
   [Unit]
   Description=CanaryGuard EDR Service
   After=network.target

   [Service]
   User=root
   WorkingDirectory=/opt/CanaryGuard
   ExecStart=/opt/CanaryGuard/venv/bin/gunicorn --worker-class geventwebsocket.gunicorn.workers.GeventWebSocketWorker -w 1 run:app
   Restart=always

   [Install]
   WantedBy=multi-user.target
   ```
