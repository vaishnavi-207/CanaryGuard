# CanaryGuard Installation Guide

## System Requirements
- **Operating System**: Windows 10/11, Ubuntu 20.04+, or macOS 12+
- **Python**: 3.10 or newer
- **RAM**: 2 GB minimum (4 GB recommended)
- **Disk Space**: 500 MB free space

## Step-by-Step Setup

1. **Clone Repository & Enter Workspace**:
   ```bash
   cd CanaryGuard
   ```

2. **Create Virtual Environment**:
   ```bash
   python -m venv venv
   # On Windows:
   venv\Scripts\activate
   # On Linux/macOS:
   source venv/bin/activate
   ```

3. **Install Dependencies**:
   ```bash
   pip install --upgrade pip
   pip install -r requirements.txt
   ```

4. **Environment Configuration**:
   Copy `.env.example` to `.env`:
   ```bash
   cp .env.example .env
   ```

5. **Start Server**:
   ```bash
   python run.py
   ```
