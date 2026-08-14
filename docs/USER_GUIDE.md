# CanaryGuard User Guide

## Overview of Dashboard Controls

1. **Dashboard Page (`/`)**:
   - High-level metrics: Protection status, Active canaries count, Total incidents, Quarantines executed.
   - Quick action buttons to start/stop protection engine or deploy canary decoy files.

2. **Canary Manager (`/canaries`)**:
   - Lists all active trap files.
   - Shows SHA-256 integrity hash, trap status, and trigger counts.

3. **Process Explorer (`/processes`)**:
   - Lists live system processes with CPU & RAM metrics.
   - Provides one-click manual operator quarantine button for suspicious processes.

4. **Monitored Folders (`/monitored-folders`)**:
   - Allows administrators to register custom directory paths for real-time filesystem observation.

5. **Log Viewer (`/logs`)**:
   - Filterable terminal viewer displaying rotating system, security, error, entropy, and quarantine log files.
