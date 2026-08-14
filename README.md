# CanaryGuard: Intelligent Endpoint Ransomware Detection & File Integrity Monitoring Dashboard

[![Python Version](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://python.org)
[![Framework](https://img.shields.io/badge/Framework-Flask-green.svg)](https://flask.palletsprojects.com)
[![WebSockets](https://img.shields.io/badge/Sockets-Socket.IO-orange.svg)](https://socket.io)
[![License](https://img.shields.io/badge/License-MIT-purple.svg)](LICENSE)

**CanaryGuard** is an enterprise-grade, lightweight Endpoint Detection & Response (EDR) and File Integrity Monitoring (FIM) security platform designed to detect zero-day ransomware attacks via behavioral indicators rather than traditional static signature matching.

---

## Key Features

- **Decoy Canary Files Engine**: Automatically generates and deploys hidden decoy files (`Confidential_Report.docx`, `Payroll.xlsx`, `Employee_Database.pdf`, etc.) across target directories. Any modification or deletion instantly triggers high-severity alerts.
- **Shannon Entropy Engine**: Computes real-time byte entropy ($H(X) = -\sum p(x) \log_2 p(x)$) on file events. High entropy (> 7.2) strongly indicates active encryption payloads.
- **Behavioral Detection Matrix**: Combines canary triggers, entropy spikes, burst modification rates, and process metadata into a multi-factor confidence score.
- **Process Identification & Automatic Quarantine Engine**: Utilizes `psutil` to trace file activity to active PIDs. Automatically freezes execution, recursively terminates process trees, and isolates tampered files into `quarantine_store/`.
- **Cyberpunk SOC Real-Time Dashboard**: Modern, dark-themed responsive UI with WebSocket live threat alerts, process explorer, directory monitoring controls, log viewer, and analytics.

---

## Directory Structure

```
CanaryGuard/
├── app/
│   ├── canary/          # Canary decoy generation & verification
│   ├── controllers/     # REST API business logic
│   ├── database/        # SQLAlchemy ORM database initialization
│   ├── entropy/         # Shannon Entropy engine
│   ├── logging/         # Structured multi-channel rotating logging
│   ├── models/          # 13 relational database models
│   ├── monitoring/      # Watchdog real-time file monitor
│   ├── quarantine/      # Process termination & file isolation
│   ├── routes/          # Flask blueprints for UI & REST API
│   ├── services/        # Process identification & detection scoring
│   └── websocket/       # Flask-SocketIO event streaming
├── database/            # SQLite storage
├── docs/                # Complete technical & academic documentation
├── logs/                # Rotating logs (system, security, error, entropy)
├── static/              # Dark cybersecurity CSS & client JS
├── templates/           # Jinja2 HTML dashboard templates
├── tests/               # Pytest suite
├── config.py            # Modular configuration system
├── app.py / run.py      # Entrypoints
└── requirements.txt     # Dependencies
```

---

## Quick Start Guide

### 1. Prerequisites
- Python 3.10 or higher
- `pip` package manager

### 2. Installation
Clone the repository and install required dependencies:
```bash
git clone https://github.com/your-username/CanaryGuard.git
cd CanaryGuard
pip install -r requirements.txt
```

### 3. Launching the Application
Run the launcher script:
```bash
python run.py
```
Open your web browser and navigate to: **`http://127.0.0.1:5000`**

### 4. Running Test Suite
Execute the pytest suite:
```bash
python -m pytest tests/ -v
```

---

## Documentation

Full project documentation is available in the [`docs/`](./docs/) directory:
- [Installation Guide](docs/INSTALLATION.md)
- [User Manual](docs/USER_GUIDE.md)
- [Software Architecture](docs/ARCHITECTURE.md)
- [REST API Specification](docs/API_DOCUMENTATION.md)
- [Database Documentation](docs/DATABASE.md)
- [Testing Guide](docs/TESTING.md)
- [Deployment Guide](docs/DEPLOYMENT.md)
- [Academic Project Report](docs/PROJECT_REPORT.md)

---

## License

This project is released under the MIT License.
