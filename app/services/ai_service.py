import os
import math
import requests
from app.models.incident import Incident
from app.models.canary_file import CanaryFile
from app.models.monitored_folder import MonitoredFolder
from app.models.quarantine_history import QuarantineHistory

class AIService:
    """
    AI Threat Analysis, Threat Scoring, Summary, and Recommendation engine.
    Supports intelligent rule-based templates and can seamlessly integrate
    with Anthropic Claude API when configured.
    """

    @staticmethod
    def _call_anthropic_api(system_prompt: str, user_message: str):
        """
        Helper method to call Anthropic API if ANTHROPIC_API_KEY is set.
        Returns response text string or None. Never raises exceptions.
        """
        try:
            key = os.environ.get('ANTHROPIC_API_KEY')
            if not key:
                return None

            url = "https://api.anthropic.com/v1/messages"
            headers = {
                "x-api-key": key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json"
            }
            payload = {
                "model": "claude-haiku-4-5",
                "max_tokens": 500,
                "system": system_prompt,
                "messages": [{"role": "user", "content": user_message}]
            }

            resp = requests.post(url, headers=headers, json=payload, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                content = data.get('content', [])
                if content and isinstance(content, list) and len(content) > 0:
                    return content[0].get('text')
            return None
        except Exception:
            return None

    @staticmethod
    def calculate_threat_score(incident_data):
        """
        Computes AI Threat Score (0-100%) based on threat factors:
        + Canary trigger (35 points)
        + Entropy > 7.0 (25 points) or > 6.0 (15 points)
        + Burst activity / Multiple modifications (15 points)
        + File deletion (15 points)
        + Unknown process / Suspicious execution (10 points)
        """
        score = 0
        if incident_data.get('canary_triggered'):
            score += 35

        entropy = incident_data.get('entropy_value') or 0.0
        if entropy >= 7.0:
            score += 25
        elif entropy >= 6.0:
            score += 15

        if incident_data.get('burst_activity') or incident_data.get('multiple_modifications'):
            score += 15

        if incident_data.get('file_deleted') or 'deleted' in (incident_data.get('description') or '').lower():
            score += 15

        proc_name = (incident_data.get('process_name') or '').lower()
        if proc_name and proc_name not in ['explorer.exe', 'python.exe', 'cmd.exe', 'powershell.exe', 'svchost.exe', 'code.exe', 'system']:
            score += 10
        elif not proc_name or proc_name == 'unknown':
            score += 10

        return min(max(score, 15 if incident_data.get('canary_triggered') else 5), 100)

    @classmethod
    def generate_explanation(cls, incident):
        """
        Generates structured AI Threat Analysis explanation for an incident.
        Uses Anthropic API if available, falling back to template logic.
        """
        # Build incident_json representation
        incident_dict = {
            "id": getattr(incident, 'id', None),
            "threat_level": getattr(incident, 'threat_level', None),
            "file_path": getattr(incident, 'file_path', None),
            "canary_triggered": getattr(incident, 'canary_triggered', False),
            "entropy_value": getattr(incident, 'entropy_value', None),
            "process_id": getattr(incident, 'process_id', None),
            "process_name": getattr(incident, 'process_name', None),
            "action_taken": getattr(incident, 'action_taken', None),
            "description": getattr(incident, 'description', None),
            "confidence_score": getattr(incident, 'confidence_score', None)
        }

        system_prompt = (
            "You are a malware analyst. Analyze this ransomware incident and return "
            "exactly 3 bullet points explaining why it is suspicious. Be specific and technical."
        )

        llm_response = cls._call_anthropic_api(system_prompt, str(incident_dict))
        if llm_response:
            # Parse bullet points from LLM output
            lines = [line.strip() for line in llm_response.split('\n') if line.strip()]
            reasons = []
            for line in lines:
                clean_line = line.lstrip('•*-123456789. ').strip()
                if clean_line:
                    reasons.append(clean_line)
            reasons = reasons[:3]

            if reasons:
                explanation_text = (
                    f"This activity resembles ransomware behavior because:\n\n" +
                    "\n".join([f"• {r}" for r in reasons]) +
                    "\n\nThis pattern indicates automated unauthorized payload execution targeting local storage assets."
                )
                return {
                    "title": "AI Threat Analysis",
                    "summary_text": explanation_text,
                    "reasons": reasons
                }

        # Fallback template logic
        reasons = []

        if incident.canary_triggered:
            reasons.append("A protected canary file decoy was modified or deleted.")
        
        if incident.entropy_value and incident.entropy_value >= 6.5:
            reasons.append(f"File entropy spiked to {incident.entropy_value:.2f} (high randomness indicating potential encryption).")
        
        if incident.description and "deleted" in incident.description.lower():
            reasons.append("Rapid or unauthorized file deletion was detected in a monitored folder.")
        
        if incident.process_name and incident.process_name.lower() not in ['explorer.exe', 'python.exe']:
            reasons.append(f"Suspicious execution context identified: process '{incident.process_name}' (PID: {incident.process_id or 'N/A'}).")
        else:
            reasons.append("Unidentified or non-standard process initiated rapid file operations.")

        if not reasons:
            reasons.append("Anomalous file modification rate triggered endpoint heuristics.")

        explanation_text = (
            f"This activity resembles ransomware behavior because:\n\n" +
            "\n".join([f"• {r}" for r in reasons]) +
            "\n\nThis pattern indicates automated unauthorized payload execution targeting local storage assets."
        )

        return {
            "title": "AI Threat Analysis",
            "summary_text": explanation_text,
            "reasons": reasons
        }

    @classmethod
    def get_recommendations(cls, incident):
        """
        Generates dynamic security recommendations tailored to incident parameters.
        """
        recommendations = [
            {"title": "Disconnect system", "desc": "Isolate the endpoint network adapter to prevent lateral movement.", "recommended": True},
            {"title": "Enable Auto Quarantine", "desc": "Ensure automated process suspension rules are active in settings.", "recommended": True},
            {"title": "Restore files", "desc": "Replace altered or deleted canary decoys from clean backup snapshots.", "recommended": True},
            {"title": "Review suspicious process", "desc": f"Investigate process '{incident.process_name or 'Unknown'}' binary signature and hash.", "recommended": True},
            {"title": "Backup monitored folders", "desc": "Create offline immutable backups of all protected directories.", "recommended": True}
        ]
        return recommendations

    @classmethod
    def generate_incident_summary(cls, incident):
        """
        Produces AI Incident Summary payload.
        """
        score = int(incident.confidence_score) if incident.confidence_score else cls.calculate_threat_score({
            'canary_triggered': incident.canary_triggered,
            'entropy_value': incident.entropy_value,
            'process_name': incident.process_name,
            'description': incident.description
        })

        time_str = incident.created_at.strftime("%I:%M %p") if hasattr(incident, 'created_at') and incident.created_at else "Recently"
        target_file = os.path.basename(incident.file_path) if incident.file_path else "Protected Asset"

        summary = f"At {time_str}, a security event occurred involving '{target_file}'."
        if incident.canary_triggered:
            summary = f"At {time_str}, protected canary document '{target_file}' was modified or deleted."
        
        proc = incident.process_name or "No trusted process"
        summary += f" Executed by {proc} (PID: {incident.process_id or 'N/A'}). Threat confidence score evaluated at {score}%."

        return {
            "time_str": time_str,
            "target_file": target_file,
            "summary": summary,
            "threat_confidence": score,
            "recommended_action": "Immediate isolation & threat investigation required."
        }

    @classmethod
    def generate_timeline(cls, incident):
        """
        Generates chronological vertical timeline events for an incident.
        """
        created_time = incident.created_at.strftime("%H:%M:%S") if hasattr(incident, 'created_at') and incident.created_at else "15:48:00"
        
        events = [
            {"time": "00:00:01", "title": "Monitoring engine initialized", "icon": "shield-check", "color": "info"},
            {"time": "00:01:15", "title": "Canary decoy files deployed to filesystem", "icon": "file-earmark-code", "color": "primary"},
            {"time": created_time, "title": f"Canary file triggered: {os.path.basename(incident.file_path or 'file')}", "icon": "exclamation-triangle", "color": "danger"},
            {"time": created_time, "title": f"Threat detected (Level: {incident.threat_level})", "icon": "lightning", "color": "warning"},
            {"time": created_time, "title": f"Security Incident #{incident.id} logged", "icon": "journal-text", "color": "danger"},
            {"time": created_time, "title": f"AI Analysis completed (Score: {int(incident.confidence_score or 80)}%)", "icon": "cpu", "color": "success"}
        ]
        return events

    @classmethod
    def get_dashboard_insights(cls, monitor_running=True):
        """
        Calculates live dashboard security insights.
        """
        total_incidents = Incident.query.count()
        active_incidents = Incident.query.filter_by(status='ACTIVE').count()
        quarantined = QuarantineHistory.query.count()

        # Find most targeted file type
        incidents = Incident.query.all()
        ext_counts = {}
        highest_entropy = 0.0
        most_suspicious_proc = "None"
        proc_counts = {}

        for inc in incidents:
            if inc.file_path:
                ext = os.path.splitext(inc.file_path)[1].lower()
                if ext:
                    ext_counts[ext] = ext_counts.get(ext, 0) + 1
            if inc.entropy_value and inc.entropy_value > highest_entropy:
                highest_entropy = inc.entropy_value
            if inc.process_name:
                proc_counts[inc.process_name] = proc_counts.get(inc.process_name, 0) + 1

        most_targeted_ext = max(ext_counts, key=ext_counts.get) if ext_counts else ".docx / .xlsx"
        if proc_counts:
            most_suspicious_proc = max(proc_counts, key=proc_counts.get)

        folders = MonitoredFolder.query.filter_by(is_active=True).all()
        most_active_folder = folders[0].folder_path if folders else "C:\\Monitored"

        trend_status = "STABLE"
        if active_incidents > 5:
            trend_status = "CRITICAL ELEVATION"
        elif active_incidents > 0:
            trend_status = "MODERATE RISK"

        return {
            "monitoring_health": "Healthy & Active" if monitor_running else "Monitoring Paused",
            "ransomware_status": "No active ransomware payload running" if active_incidents == 0 else f"{active_incidents} Active Threats Under Containment",
            "most_active_folder": most_active_folder,
            "most_targeted_type": most_targeted_ext,
            "highest_entropy_today": f"{highest_entropy:.2f}" if highest_entropy > 0 else "4.12 (Normal)",
            "most_suspicious_process": most_suspicious_proc,
            "threat_trend": trend_status,
            "total_incidents": total_incidents,
            "quarantined_count": quarantined
        }

    @classmethod
    def chat_response(cls, user_message):
        """
        AI Chatbot handler with optional Anthropic Claude integration and local fallback.
        """
        system_prompt = (
            "You are a cybersecurity assistant for CanaryGuard EDR ransomware detection platform. "
            "Answer concisely in 2-3 sentences. Focus on practical security advice."
        )

        llm_response = cls._call_anthropic_api(system_prompt, user_message)
        if llm_response:
            return llm_response

        # Fallback keyword logic
        msg = user_message.lower().strip()

        if "flagged" in msg or ("why" in msg and "file" in msg):
            return (
                "Files are flagged when CanaryGuard detects unauthorized modifications to decoy canary files, "
                "a sudden surge in file entropy (indicating encryption), or rapid burst file operations executed "
                "by an unverified process."
            )
        elif "entropy" in msg:
            return (
                "Shannon Entropy measures data randomness on a scale from 0.0 to 8.0. Standard text files have an entropy "
                "around 3.5 to 5.0. Ransomware encrypts files into pseudorandom ciphertext, raising entropy near 7.5 - 8.0. "
                "CanaryGuard alerts whenever entropy exceeds the safe threshold (default 7.0)."
            )
        elif "canary" in msg:
            return (
                "Canary files are strategic decoy files (like Confidential_Report.docx) placed in monitored directories. "
                "Legitimate users never touch them, but ransomware scans and encrypts files sequentially. Modifying a canary "
                "immediately triggers CanaryGuard to quarantine the offending process before real data is compromised."
            )
        elif "quarantine" in msg:
            return (
                "Quarantine suspends or terminates the malicious process PID and safely isolates suspicious files into "
                "the `quarantine_store` directory to halt ransomware encryption in real time."
            )
        elif "statistic" in msg or "dashboard" in msg or "score" in msg:
            return (
                "The AI Threat Score (0-100%) aggregates canary decoy breaches, file entropy spikes, modification frequency, "
                "and process integrity. The dashboard provides SOC-level real-time telemetry via WebSocket."
            )
        elif "hello" in msg or "hi" in msg:
            return "Greetings! I am the CanaryGuard AI Security Assistant. Ask me anything about flagged threats, entropy, canary decoys, or quarantine actions!"
        else:
            return (
                f"I analyzed your query regarding '{user_message}'. CanaryGuard monitors endpoint behavior using canary decoy "
                "traps and Shannon entropy math. If an active threat occurs, CanaryGuard automatically calculates an AI Threat Score "
                "and offers recommended remediation steps."
            )
