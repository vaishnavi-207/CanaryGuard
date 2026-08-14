import os
import sys
import unittest
from pathlib import Path

# Add project root to sys.path
BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))

def verify_imports():
    print("--- 1. Verifying Python Imports & Syntax ---")
    python_files = list(BASE_DIR.glob("**/*.py"))
    failed_imports = []
    
    for py_file in python_files:
        if "venv" in str(py_file) or ".git" in str(py_file):
            continue
        rel_path = py_file.relative_to(BASE_DIR)
        module_name = str(rel_path).replace(os.sep, ".").replace(".py", "")
        if module_name.endswith(".__init__"):
            module_name = module_name[:-9]
        try:
            __import__(module_name)
            print(f"  [OK] Imported: {module_name}")
        except Exception as e:
            print(f"  [FAIL] Import failed for {module_name}: {e}")
            failed_imports.append((module_name, str(e)))
            
    return failed_imports

def verify_app_and_database():
    print("\n--- 2. Verifying Flask App Initialization & SQLite Database ---")
    from app import create_app
    from app.database.db import db
    from app.models import (
        User, Incident, CanaryFile, EntropyLog, ProcessLog, ThreatStatistics,
        QuarantineHistory, SystemSetting, ActivityLog, DashboardEvent,
        SecurityPolicy, MonitoredFolder, Alert
    )
    
    app = create_app('testing')
    with app.app_context():
        # Check all models registered
        tables = db.metadata.tables.keys()
        print(f"  Registered SQL Tables ({len(tables)}): {', '.join(tables)}")
        assert len(tables) >= 13, "Fewer than 13 tables registered in metadata!"
        
        # Test query on each model
        models = [
            User, Incident, CanaryFile, EntropyLog, ProcessLog, ThreatStatistics,
            QuarantineHistory, SystemSetting, ActivityLog, DashboardEvent,
            SecurityPolicy, MonitoredFolder, Alert
        ]
        for m in models:
            count = m.query.count()
            print(f"  Model {m.__name__} query successful (Count: {count})")
            
    return app

def verify_endpoints(app):
    print("\n--- 3. Verifying REST API Endpoints & UI Views ---")
    client = app.test_client()
    endpoints = [
        ('/', 200),
        ('/threat-feed', 200),
        ('/incidents', 200),
        ('/processes', 200),
        ('/canaries', 200),
        ('/monitored-folders', 200),
        ('/statistics', 200),
        ('/settings', 200),
        ('/logs', 200),
        ('/about', 200),
        ('/api/status', 200),
        ('/api/incidents', 200),
        ('/api/canaries', 200),
        ('/api/processes', 200),
        ('/api/statistics', 200),
        ('/api/settings', 200),
        ('/api/monitored-folders', 200),
        ('/api/logs', 200)
    ]
    
    failed_endpoints = []
    for ep, expected_code in endpoints:
        res = client.get(ep)
        if res.status_code == expected_code:
            print(f"  [OK] GET {ep} -> {res.status_code}")
        else:
            print(f"  [FAIL] GET {ep} -> {res.status_code} (Expected {expected_code})")
            failed_endpoints.append((ep, res.status_code))
            
    return failed_endpoints

def verify_engines():
    print("\n--- 4. Verifying Security & Detection Engines ---")
    import tempfile
    from app.entropy.entropy_engine import ShannonEntropyEngine
    from app.canary.canary_engine import CanaryDeploymentEngine
    from app.quarantine.quarantine_engine import ProcessQuarantineEngine
    from app import create_app
    from app.database.db import db
    
    app = create_app('testing')
    with app.app_context():
        temp_dir = tempfile.mkdtemp()
        
        # 1. Canary engine
        canaries = CanaryDeploymentEngine.deploy_canaries_in_directory(temp_dir)
        assert len(canaries) == 8, f"Expected 8 canaries, got {len(canaries)}"
        print("  [OK] Canary Deployment Engine (8 files created)")
        
        # 2. Entropy engine
        entropy_val = ShannonEntropyEngine.calculate_entropy(canaries[0]['file_path'])
        print(f"  [OK] Shannon Entropy Engine calculated value: {entropy_val}")
        
        # 3. Quarantine history logging
        q_res = ProcessQuarantineEngine.terminate_suspicious_process(
            pid=999999, reason="Verification Test", target_file=canaries[0]['file_path']
        )
        assert q_res['pid'] == 999999
        print("  [OK] Quarantine Engine integration verified")

if __name__ == '__main__':
    print("==================================================")
    print("Starting CanaryGuard Comprehensive Project Verification")
    print("==================================================")
    
    imports_failed = verify_imports()
    app = verify_app_and_database()
    endpoints_failed = verify_endpoints(app)
    verify_engines()
    
    print("\n==================================================")
    if not imports_failed and not endpoints_failed:
        print("[SUCCESS] ALL CANARYGUARD VERIFICATION CHECKS PASSED SUCCESSFULLY!")
        print("==================================================")
        sys.exit(0)
    else:
        print("❌ VERIFICATION DISCOVERED ISSUES!")
        print(f"Failed Imports: {imports_failed}")
        print(f"Failed Endpoints: {endpoints_failed}")
        print("==================================================")
        sys.exit(1)
