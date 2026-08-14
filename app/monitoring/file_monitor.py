import time
import os
from pathlib import Path
from collections import defaultdict, deque
from typing import Dict, Any, List, Optional, Callable
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileSystemEvent

from app.entropy.entropy_engine import ShannonEntropyEngine
from app.canary.canary_engine import CanaryDeploymentEngine
from app.services.process_service import ProcessService
from app.quarantine.quarantine_engine import ProcessQuarantineEngine
from app.logging.logger import get_system_logger, get_security_logger, get_error_logger

logger = get_system_logger()
security_logger = get_security_logger()
error_logger = get_error_logger()

class CanaryGuardEventHandler(FileSystemEventHandler):
    """Watchdog Event Handler capturing file modification bursts, canary triggers, and entropy anomalies."""

    def __init__(self, app: Optional[Any] = None, callback_event: Optional[Callable[[Dict[str, Any]], None]] = None, entropy_threshold: float = 7.2, auto_quarantine: bool = True):
        super().__init__()
        self.app = app
        self.callback_event = callback_event
        self.entropy_threshold = entropy_threshold
        self.auto_quarantine = auto_quarantine
        
        # Track rapid file modifications per process window (3 second rolling window)
        self.modification_timestamps = deque()
        self.burst_count_threshold = 10
        self.burst_time_window = 3.0

    def _process_file_event(self, event_type: str, src_path: str, dest_path: Optional[str] = None):
        # Ignore temp or log files
        if any(ignored in src_path for ignored in ['.log', '.db', '__pycache__', '.git', 'tmp']):
            return

        now = time.time()
        self.modification_timestamps.append(now)
        
        # Clean timestamps outside window
        while self.modification_timestamps and now - self.modification_timestamps[0] > self.burst_time_window:
            self.modification_timestamps.popleft()

        is_burst = len(self.modification_timestamps) >= self.burst_count_threshold

        event_data = {
            'event_type': event_type,
            'src_path': src_path,
            'dest_path': dest_path,
            'timestamp': now,
            'is_burst': is_burst,
            'entropy': 0.0,
            'is_high_entropy': False,
            'canary_triggered': False,
            'threat_level': 'INFO',
            'pid': None,
            'process_name': 'Unknown',
            'action_taken': 'LOGGED'
        }

        # 1. Identify Process Touching File
        pids = ProcessService.find_processes_accessing_file(src_path)
        if pids:
            event_data['pid'] = pids[0]
            proc_details = ProcessService.get_process_details(pids[0])
            if proc_details:
                event_data['process_name'] = proc_details['name']

        # Wrap DB calls and callback in app_context if app reference exists
        if self.app:
            with self.app.app_context():
                self._evaluate_event(event_type, src_path, event_data, is_burst)
        else:
            self._evaluate_event(event_type, src_path, event_data, is_burst)

    def _evaluate_event(self, event_type: str, src_path: str, event_data: Dict[str, Any], is_burst: bool):
        # 2. Check Canary Decoy File Tampering
        canary_alert = CanaryDeploymentEngine.verify_canary_integrity(src_path)
        if canary_alert:
            event_data['canary_triggered'] = True
            event_data['threat_level'] = 'CRITICAL'
            security_logger.critical(f"CANARY TRIGGERED by {event_data['process_name']} (PID: {event_data['pid']}) on {src_path}")

        # 3. Check Entropy Anomaly if file exists
        if os.path.exists(src_path) and os.path.isfile(src_path):
            entropy, is_high, _ = ShannonEntropyEngine.evaluate_threat(src_path, threshold=self.entropy_threshold)
            event_data['entropy'] = entropy
            event_data['is_high_entropy'] = is_high
            if is_high and event_data['threat_level'] != 'CRITICAL':
                event_data['threat_level'] = 'HIGH'

        # 4. Burst Rate Detection Threat Elevation
        if is_burst and event_data['threat_level'] == 'INFO':
            event_data['threat_level'] = 'MEDIUM'
            security_logger.warning(f"Rapid File Burst Modification Detected on {src_path}")

        # 5. Quarantine Decision Engine
        if (event_data['canary_triggered'] or (event_data['is_high_entropy'] and is_burst)) and self.auto_quarantine:
            if event_data['pid']:
                q_res = ProcessQuarantineEngine.terminate_suspicious_process(
                    pid=event_data['pid'],
                    reason=f"Ransomware threat: Canary={event_data['canary_triggered']}, HighEntropy={event_data['is_high_entropy']}, Burst={is_burst}",
                    target_file=src_path
                )
                event_data['action_taken'] = 'QUARANTINED' if q_res['terminated'] else 'FAILED_QUARANTINE'
            else:
                event_data['action_taken'] = 'LOGGED_NO_PID'

        # Dispatch event callback if registered
        if self.callback_event:
            self.callback_event(event_data)

    def on_created(self, event: FileSystemEvent):
        if not event.is_directory:
            self._process_file_event('CREATED', event.src_path)

    def on_modified(self, event: FileSystemEvent):
        if not event.is_directory:
            self._process_file_event('MODIFIED', event.src_path)

    def on_deleted(self, event: FileSystemEvent):
        if not event.is_directory:
            self._process_file_event('DELETED', event.src_path)

    def on_moved(self, event: FileSystemEvent):
        if not event.is_directory:
            self._process_file_event('MOVED', event.src_path, event.dest_path)


class FileMonitorManager:
    """Manages active Watchdog Observers for monitored directories."""

    def __init__(self, app: Optional[Any] = None, callback_event: Optional[Callable[[Dict[str, Any]], None]] = None):
        self.app = app
        self.observer: Optional[Observer] = None
        self.monitored_paths: List[str] = []
        self.is_running: bool = False
        self.callback_event = callback_event

    def start_monitoring(self, paths: List[str], entropy_threshold: float = 7.2, auto_quarantine: bool = True):
        """Starts filesystem watcher on specified directories."""
        if self.is_running:
            self.stop_monitoring()

        self.observer = Observer()
        handler = CanaryGuardEventHandler(
            app=self.app,
            callback_event=self.callback_event,
            entropy_threshold=entropy_threshold,
            auto_quarantine=auto_quarantine
        )

        valid_paths = []
        for p in paths:
            abs_p = str(Path(p).resolve())
            if os.path.exists(abs_p):
                self.observer.schedule(handler, path=abs_p, recursive=True)
                valid_paths.append(abs_p)
                logger.info(f"File Monitoring scheduled for: {abs_p}")
            else:
                logger.warning(f"Path does not exist, skipped monitoring: {abs_p}")

        if valid_paths:
            self.observer.start()
            self.monitored_paths = valid_paths
            self.is_running = True
            logger.info("File System Monitoring Service STARTED successfully.")

    def stop_monitoring(self):
        """Stops active filesystem watcher."""
        if self.observer and self.is_running:
            self.observer.stop()
            self.observer.join(timeout=5)
            self.observer = None
            self.is_running = False
            self.monitored_paths = []
            logger.info("File System Monitoring Service STOPPED.")

    def get_status(self) -> Dict[str, Any]:
        """Returns monitor status object."""
        return {
            'is_running': self.is_running,
            'monitored_paths': self.monitored_paths,
            'observer_alive': self.observer.is_alive() if self.observer else False
        }
