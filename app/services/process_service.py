import psutil
import os
import sys
from typing import Dict, Any, List, Optional
from app.logging.logger import get_system_logger, get_error_logger

logger = get_system_logger()
error_logger = get_error_logger()

class ProcessService:
    """Uses psutil to inspect, track, and analyze system processes."""

    @staticmethod
    def get_process_details(pid: int) -> Optional[Dict[str, Any]]:
        """Extracts comprehensive details about a process by PID."""
        try:
            p = psutil.Process(pid)
            with p.oneshot():
                cmdline_str = " ".join(p.cmdline()) if p.cmdline() else ""
                children = [c.pid for c in p.children(recursive=True)]
                
                return {
                    'pid': p.pid,
                    'ppid': p.ppid(),
                    'name': p.name(),
                    'exe': p.exe() if hasattr(p, 'exe') else '',
                    'cmdline': cmdline_str,
                    'username': p.username() if hasattr(p, 'username') else '',
                    'cpu_percent': p.cpu_percent(interval=None),
                    'memory_percent': round(p.memory_percent(), 2),
                    'create_time': p.create_time(),
                    'status': p.status(),
                    'children': children
                }
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return None
        except Exception as e:
            error_logger.error(f"Error fetching process details for PID {pid}: {e}")
            return None

    @staticmethod
    def list_active_processes() -> List[Dict[str, Any]]:
        """Returns a list of all currently running processes."""
        processes = []
        for proc in psutil.process_iter(['pid', 'ppid', 'name', 'exe', 'username', 'cpu_percent', 'memory_percent', 'status']):
            try:
                info = proc.info
                processes.append({
                    'pid': info['pid'],
                    'ppid': info['ppid'],
                    'name': info['name'] or 'Unknown',
                    'exe': info['exe'] or '',
                    'username': info['username'] or '',
                    'cpu_percent': info['cpu_percent'] or 0.0,
                    'memory_percent': round(info['memory_percent'] or 0.0, 2),
                    'status': info['status'] or 'UNKNOWN'
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return processes

    @staticmethod
    def find_processes_accessing_file(file_path: str) -> List[int]:
        """Finds PIDs of processes holding open file handles to the specified path."""
        matching_pids = []
        normalized_path = os.path.normpath(file_path).lower()

        for proc in psutil.process_iter(['pid', 'name']):
            try:
                for open_file in proc.open_files():
                    if os.path.normpath(open_file.path).lower() == normalized_path:
                        matching_pids.append(proc.pid)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            except Exception:
                continue

        return matching_pids
