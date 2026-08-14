# CanaryGuard REST API Specification

### Endpoints

#### 1. System Status
- **URL**: `/api/status`
- **Method**: `GET`
- **Response**:
  ```json
  {
    "active_canaries": 8,
    "active_incidents": 0,
    "engine_version": "1.0.0",
    "monitoring": { "is_running": true, "monitored_paths": ["/path/to/dir"] },
    "quarantined_processes": 1,
    "status": "OK"
  }
  ```

#### 2. Start/Stop Monitoring
- **URL**: `/api/start-monitor` | `/api/stop-monitor`
- **Method**: `POST`

#### 3. Incident History
- **URL**: `/api/incidents`
- **Method**: `GET` | `DELETE /api/incidents/<id>`

#### 4. Canary Decoys
- **URL**: `/api/canaries`
- **Method**: `GET`
- **URL**: `/api/deploy-canaries`
- **Method**: `POST`

#### 5. Process & Quarantine
- **URL**: `/api/processes`
- **Method**: `GET`
- **URL**: `/api/quarantine`
- **Method**: `POST`
- **Payload**: `{ "pid": 1234, "reason": "Operator Request" }`
