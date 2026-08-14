from typing import Dict, Any, Tuple
from datetime import datetime

from app.database.db import db
from app.models.incident import Incident
from app.models.alert import Alert
from app.models.entropy_log import EntropyLog
from app.models.threat_statistics import ThreatStatistics
from app.quarantine.quarantine_engine import ProcessQuarantineEngine
from app.logging.logger import get_security_logger, get_error_logger

logger = get_security_logger()
error_logger = get_error_logger()

class BehavioralDetectionEngine:
    """Combines canary hits, entropy spikes, burst rate, and process behavior into unified confidence scoring."""

    @classmethod
    def evaluate_and_respond(cls, event_data: Dict[str, Any], auto_quarantine: bool = True) -> Dict[str, Any]:
        """
        Evaluates a file system event data dictionary, assigns confidence score,
        logs incident, and triggers quarantine if score >= 60.0.
        """
        score = 0.0
        reasons = []

        # 1. Canary File Trigger
        if event_data.get('canary_triggered'):
            score += 55.0
            reasons.append("Canary decoy file tampered or deleted")

        # 2. Shannon Entropy Spike
        if event_data.get('is_high_entropy'):
            score += 35.0
            reasons.append(f"High Shannon entropy calculated: {event_data.get('entropy')}")

        # 3. Burst Rate Multi-File Activity
        if event_data.get('is_burst'):
            score += 25.0
            reasons.append("Rapid burst file modification rate detected")

        # 4. Critical Event Types
        if event_data.get('event_type') in ['DELETED', 'MOVED']:
            score += 10.0
            reasons.append(f"Destructive file action: {event_data.get('event_type')}")

        confidence_score = min(score, 100.0)
        
        # Determine Threat Level
        if confidence_score >= 80.0:
            threat_level = 'CRITICAL'
        elif confidence_score >= 50.0:
            threat_level = 'HIGH'
        elif confidence_score >= 25.0:
            threat_level = 'MEDIUM'
        else:
            threat_level = 'LOW'

        # Log Entropy Record if entropy available
        if event_data.get('entropy', 0.0) > 0.0:
            entropy_record = EntropyLog(
                file_path=event_data['src_path'],
                entropy=event_data['entropy'],
                threshold=7.2,
                exceeded_threshold=event_data.get('is_high_entropy', False),
                file_size_bytes=0,
                event_type=event_data.get('event_type', 'UNKNOWN'),
                process_id=event_data.get('pid')
            )
            db.session.add(entropy_record)

        action_taken = 'LOGGED'
        # Perform Quarantine if threat level is HIGH or CRITICAL
        if confidence_score >= 50.0 and auto_quarantine and event_data.get('pid'):
            q_res = ProcessQuarantineEngine.terminate_suspicious_process(
                pid=event_data['pid'],
                reason=" | ".join(reasons),
                target_file=event_data['src_path']
            )
            action_taken = 'QUARANTINED' if q_res['terminated'] else 'QUARANTINE_FAILED'

        # Create Incident Record in DB
        incident = Incident(
            threat_level=threat_level,
            file_path=event_data['src_path'],
            canary_triggered=event_data.get('canary_triggered', False),
            entropy_value=event_data.get('entropy'),
            process_id=event_data.get('pid'),
            process_name=event_data.get('process_name'),
            action_taken=action_taken,
            status='ACTIVE' if threat_level in ['HIGH', 'CRITICAL'] else 'RESOLVED',
            confidence_score=confidence_score,
            description="; ".join(reasons) if reasons else "Normal file activity log",
            recovery_notes="Automated EDR Response" if action_taken == 'QUARANTINED' else None
        )
        db.session.add(incident)

        # Create Security Alert Record if threat level >= MEDIUM
        if threat_level in ['MEDIUM', 'HIGH', 'CRITICAL']:
            alert = Alert(
                alert_type='RANSOMWARE_THREAT' if confidence_score >= 50.0 else 'SUSPICIOUS_ACTIVITY',
                severity=threat_level,
                title=f"{threat_level} Threat Detected on {event_data.get('process_name')}",
                message=f"Detected suspicious behavior on {event_data['src_path']}. Reasons: {', '.join(reasons)}",
                source='BehavioralDetectionEngine'
            )
            db.session.add(alert)

        # Update Daily Threat Statistics
        today = datetime.utcnow().date()
        stats = ThreatStatistics.query.filter_by(record_date=today).first()
        if not stats:
            stats = ThreatStatistics(
                record_date=today,
                total_incidents=0,
                canary_triggers=0,
                entropy_violations=0,
                processes_quarantined=0,
                protected_files_count=0
            )
            db.session.add(stats)

        stats.total_incidents = (stats.total_incidents or 0) + 1
        if event_data.get('canary_triggered'):
            stats.canary_triggers = (stats.canary_triggers or 0) + 1
        if event_data.get('is_high_entropy'):
            stats.entropy_violations = (stats.entropy_violations or 0) + 1
        if action_taken == 'QUARANTINED':
            stats.processes_quarantined = (stats.processes_quarantined or 0) + 1

        db.session.commit()

        return {
            'incident_id': incident.id,
            'threat_level': threat_level,
            'confidence_score': confidence_score,
            'reasons': reasons,
            'action_taken': action_taken,
            'src_path': event_data['src_path'],
            'pid': event_data.get('pid'),
            'process_name': event_data.get('process_name')
        }
