# CanaryGuard Architecture Documentation

CanaryGuard uses a **Modular Layered Architecture**:

```
+-------------------------------------------------------+
|                 Presentation Layer                    |
|       (Jinja2 Templates, Dark CSS, JS, Chart.js)      |
+-------------------------------------------------------+
                           |
                           v
+-------------------------------------------------------+
|             API & WebSocket Gateway Layer             |
|          (Flask Blueprints, Flask-SocketIO)          |
+-------------------------------------------------------+
                           |
                           v
+-------------------------------------------------------+
|                 Business Logic Layer                  |
|    (Behavioral Detection Engine, API Controllers)     |
+-------------------------------------------------------+
          /                |                \
         v                 v                 v
+-----------------+ +----------------+ +----------------+
|  Entropy Engine | | Canary Engine  | | Process Service|
+-----------------+ +----------------+ +----------------+
         \                 |                 /
          v                v                v
+-------------------------------------------------------+
|                Quarantine & Monitor Layer             |
|         (Watchdog Observer, psutil Termination)       |
+-------------------------------------------------------+
                           |
                           v
+-------------------------------------------------------+
|                Database & Logging Layer               |
|         (SQLite, SQLAlchemy ORM, Rotating Logs)       |
+-------------------------------------------------------+
```

## Key Layer Interactions
1. **Watchdog Observer** captures filesystem events in real-time.
2. **Canary Engine** and **Entropy Engine** process event details and evaluate integrity/entropy.
3. **Behavioral Detection Engine** computes a unified confidence score (0-100%).
4. If score exceeds threshold, **Process Quarantine Engine** suspends and kills the responsible PID via `psutil`.
5. **WebSocket Gateway** broadcasts instant alerts to connected dashboard clients.
