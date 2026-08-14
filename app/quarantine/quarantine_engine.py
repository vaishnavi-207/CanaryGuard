import os
import shutil
import psutil
from pathlib import Path
from typing import Dict, Any, Optional
from datetime import datetime
from config import Config
from app.database.db import db
from app.models.quarantine_history import QuarantineHistory
from app.models.incident import Incident
from app.models.alert import Alert
from app.services.process_service import ProcessService
from app.logging.logger import get_quarantine_logger, get_error_logger

logger = get_quarantine_logger()
error_logger = get_error_logger()

class ProcessQuarantineEngine:
    """Handles thread suspension, process termination, child tree cleanup, and file isolation."""

    @classmethod
    def terminate_suspicious_process(cls, pid: int, reason: str = "Ransomware Behavioral Threat Detected", target_file: Optional[str] = None) -> Dict[str, Any]:
        """
        Freezes and terminates a target process along with all its child processes.
        Records quarantine history in DB and moves affected file to quarantine store.
        """
        proc_details = ProcessService.get_process_details(pid)
        proc_name = proc_details['name'] if proc_details else "Unknown Process"
        exe_path = proc_details['exe'] if proc_details else ""

        result = {
            'pid': pid,
            'process_name': proc_name,
            'executable': exe_path,
            'reason': reason,
            'terminated': False,
            'children_terminated': 0,
            'quarantined_file': None
        }

        try:
            parent = psutil.Process(pid)

            # 1. Freeze process execution threads if supported
            try:
                parent.suspend()
                logger.info(f"SUSPENDED process PID {pid} ({proc_name})")
            except Exception as e:
                logger.warning(f"Could not suspend PID {pid}: {e}")

            # 2. Terminate child processes recursively
            children = parent.children(recursive=True)
            for child in children:
                try:
                    child.kill()
                    result['children_terminated'] += 1
                    logger.info(f"KILLED child process PID {child.pid} ({child.name()})")
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

            # 3. Kill main parent process
            parent.kill()
            parent.wait(timeout=3)
            result['terminated'] = True
            logger.info(f"TERMINATED malicious process PID {pid} ({proc_name})")

        except psutil.NoSuchProcess:
            logger.info(f"Process PID {pid} already exited before termination.")
            result['terminated'] = True
        except psutil.AccessDenied:
            error_logger.error(f"Permission denied attempting to kill PID {pid} ({proc_name})")
        except Exception as e:
            error_logger.exception(f"Unexpected failure terminating process PID {pid}: {e}")

        # 4. Isolate target file if supplied
        if target_file and os.path.exists(target_file):
            try:
                q_store = Config.QUARANTINE_DIR
                q_store.mkdir(parents=True, exist_ok=True)
                
                filename = Path(target_file).name
                timestamp_prefix = datetime.now().strftime("%Y%m%d_%H%M%S_")
                dest_path = str(q_store / f"{timestamp_prefix}{filename}")
                
                shutil.copy2(target_file, dest_path)
                result['quarantined_file'] = dest_path
                logger.info(f"Isolated file {target_file} to quarantine store: {dest_path}")
            except Exception as e:
                error_logger.error(f"Failed to isolate file {target_file}: {e}")

        # 5. Persist Quarantine History Record
        q_record = QuarantineHistory(
            process_id=pid,
            process_name=proc_name,
            executable_path=exe_path,
            target_file_path=target_file,
            quarantined_file_path=result['quarantined_file'],
            reason=reason,
            threat_score=1.0,
            status='QUARANTINED' if result['terminated'] else 'FAILED'
        )
        db.session.add(q_record)

        # 6. Create Alert Record
        alert = Alert(
            alert_type='QUARANTINE_EXECUTED',
            severity='CRITICAL',
            title=f"Quarantine Executed on {proc_name} (PID: {pid})",
            message=f"Terminated malicious process PID {pid} ({proc_name}). Reason: {reason}",
            source='ProcessQuarantineEngine'
        )
        db.session.add(alert)
        db.session.commit()

        return result
