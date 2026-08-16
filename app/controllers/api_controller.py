import os
from typing import Dict, Any, Tuple
from flask import jsonify, request, current_app, send_file
from datetime import datetime
from pathlib import Path

from app.database.db import db
from app.models.incident import Incident
from app.models.canary_file import CanaryFile
from app.models.entropy_log import EntropyLog
from app.models.process_log import ProcessLog
from app.models.quarantine_history import QuarantineHistory
from app.models.system_setting import SystemSetting
from app.models.monitored_folder import MonitoredFolder
from app.models.alert import Alert
from app.models.threat_statistics import ThreatStatistics

from app.canary.canary_engine import CanaryDeploymentEngine
from app.services.process_service import ProcessService
from app.quarantine.quarantine_engine import ProcessQuarantineEngine
from app.logging.logger import get_api_logger, get_error_logger

logger = get_api_logger()
error_logger = get_error_logger()

class APIController:
    """REST API Controller handling request validation, database interactions, and response formatting."""

    @staticmethod
    def get_system_status() -> Tuple[Dict[str, Any], int]:
        monitor_mgr = getattr(current_app, 'monitor_manager', None)
        status = monitor_mgr.get_status() if monitor_mgr else {'is_running': False, 'monitored_paths': []}
        
        incidents_count = Incident.query.filter_by(status='ACTIVE').count()
        canaries_count = CanaryFile.query.filter_by(is_active=True).count()
        quarantined_count = QuarantineHistory.query.count()

        return jsonify({
            'status': 'OK',
            'monitoring': status,
            'active_incidents': incidents_count,
            'active_canaries': canaries_count,
            'quarantined_processes': quarantined_count,
            'engine_version': '1.0.0'
        }), 200

    @staticmethod
    def get_incidents() -> Tuple[Dict[str, Any], int]:
        incidents = Incident.query.order_by(Incident.created_at.desc()).limit(100).all()
        return jsonify([i.to_dict() for i in incidents]), 200

    @staticmethod
    def delete_incident(incident_id: int) -> Tuple[Dict[str, Any], int]:
        incident = Incident.query.get(incident_id)
        if not incident:
            return jsonify({'error': 'Incident not found'}), 404
        db.session.delete(incident)
        db.session.commit()
        return jsonify({'message': f'Incident {incident_id} deleted successfully'}), 200

    @staticmethod
    def get_canaries() -> Tuple[Dict[str, Any], int]:
        canaries = CanaryFile.query.all()
        return jsonify([c.to_dict() for c in canaries]), 200

    @staticmethod
    def delete_canaries() -> Tuple[Dict[str, Any], int]:
        """
        Marks all active canary files as inactive in the DB and deletes them safely from disk.
        """
        canaries = CanaryFile.query.filter_by(is_active=True).all()
        deleted_count = 0
        for canary in canaries:
            canary.is_active = False
            if canary.file_path and os.path.exists(canary.file_path):
                try:
                    os.remove(canary.file_path)
                except Exception as e:
                    logger.warning(f"Failed to remove canary file {canary.file_path} from disk: {e}")
            deleted_count += 1

        db.session.commit()
        from app.websocket.events import broadcast_dashboard_update
        broadcast_dashboard_update()
        return jsonify({
            'message': f'Successfully deactivated and deleted {deleted_count} canary files.',
            'deleted_count': deleted_count
        }), 200


    @staticmethod
    def deploy_canaries() -> Tuple[Dict[str, Any], int]:
        data = request.get_json() or {}
        target_dir = data.get('directory', current_app.config['TEST_MONITOR_DIR'])
        
        records = CanaryDeploymentEngine.deploy_canaries_in_directory(str(target_dir))
        from app.websocket.events import broadcast_dashboard_update
        broadcast_dashboard_update()
        return jsonify({
            'message': f'Successfully deployed {len(records)} canary files.',
            'directory': str(target_dir),
            'canaries': records
        }), 200

    @staticmethod
    def get_processes() -> Tuple[Dict[str, Any], int]:
        processes = ProcessService.list_active_processes()
        return jsonify(processes), 200

    @staticmethod
    def manual_quarantine() -> Tuple[Dict[str, Any], int]:
        data = request.get_json() or {}
        pid = data.get('pid')
        reason = data.get('reason', 'Manual Operator Quarantine Request')

        if not pid or not isinstance(pid, int):
            return jsonify({'error': 'Valid Integer PID is required'}), 400

        result = ProcessQuarantineEngine.terminate_suspicious_process(pid=pid, reason=reason)
        from app.websocket.events import broadcast_dashboard_update
        broadcast_dashboard_update()
        return jsonify(result), 200 if result['terminated'] else 500

    @staticmethod
    def get_statistics() -> Tuple[Dict[str, Any], int]:
        total_incidents = Incident.query.count()
        critical_threats = Incident.query.filter_by(threat_level='CRITICAL').count()
        canary_triggers = CanaryFile.query.filter(CanaryFile.trigger_count > 0).count()
        quarantined_count = QuarantineHistory.query.count()

        return jsonify({
            'total_incidents': total_incidents,
            'critical_threats': critical_threats,
            'canary_triggers': canary_triggers,
            'quarantined_count': quarantined_count
        }), 200

    @staticmethod
    def get_settings() -> Tuple[Dict[str, Any], int]:
        settings = SystemSetting.query.all()
        return jsonify({s.key: s.value for s in settings}), 200

    @staticmethod
    def update_settings() -> Tuple[Dict[str, Any], int]:
        data = request.get_json() or {}
        for key, val in data.items():
            setting = SystemSetting.query.filter_by(key=key).first()
            if not setting:
                setting = SystemSetting(key=key, value=str(val))
                db.session.add(setting)
            else:
                setting.value = str(val)
        db.session.commit()
        return jsonify({'message': 'Settings updated successfully'}), 200

    @staticmethod
    def get_monitored_folders() -> Tuple[Dict[str, Any], int]:
        folders = MonitoredFolder.query.all()
        return jsonify([f.to_dict() for f in folders]), 200

    @staticmethod
    def add_monitored_folder() -> Tuple[Dict[str, Any], int]:
        data = request.get_json() or {}
        folder_path = data.get('folder_path')
        if not folder_path:
            return jsonify({'error': 'folder_path parameter required'}), 400

        abs_path = str(Path(folder_path).resolve())
        os.makedirs(abs_path, exist_ok=True)

        existing = MonitoredFolder.query.filter_by(folder_path=abs_path).first()
        if not existing:
            monitored = MonitoredFolder(folder_path=abs_path, is_active=True)
            db.session.add(monitored)
            db.session.commit()
            return jsonify({'message': f'Folder {abs_path} added to monitored list'}), 201
        
        return jsonify({'message': f'Folder {abs_path} already monitored'}), 200

    @staticmethod
    def start_monitor() -> Tuple[Dict[str, Any], int]:
        monitor_mgr = getattr(current_app, 'monitor_manager', None)
        if not monitor_mgr:
            return jsonify({'error': 'Monitor manager uninitialized'}), 500

        folders = [f.folder_path for f in MonitoredFolder.query.filter_by(is_active=True).all()]
        if not folders:
            test_dir = str(current_app.config['TEST_MONITOR_DIR'])
            folders = [test_dir]
            monitored = MonitoredFolder(folder_path=test_dir, is_active=True)
            db.session.add(monitored)
            db.session.commit()

        # Also auto-deploy canaries into monitored folders if not present
        for f in folders:
            CanaryDeploymentEngine.deploy_canaries_in_directory(f)

        monitor_mgr.start_monitoring(folders)
        from app.websocket.events import broadcast_dashboard_update
        broadcast_dashboard_update()
        return jsonify({'message': 'Monitoring started successfully', 'monitored_folders': folders}), 200

    @staticmethod
    def stop_monitor() -> Tuple[Dict[str, Any], int]:
        monitor_mgr = getattr(current_app, 'monitor_manager', None)
        if monitor_mgr:
            monitor_mgr.stop_monitoring()
        from app.websocket.events import broadcast_dashboard_update
        broadcast_dashboard_update()
        return jsonify({'message': 'Monitoring stopped successfully'}), 200

    @staticmethod
    def get_logs() -> Tuple[Dict[str, Any], int]:
        log_type = request.args.get('type', 'system')
        log_file_map = {
            'system': 'system.log',
            'security': 'security.log',
            'errors': 'errors.log',
            'quarantine': 'quarantine.log',
            'entropy': 'entropy.log',
            'api': 'api.log'
        }
        filename = log_file_map.get(log_type, 'system.log')
        log_path = current_app.config['LOG_DIR'] / filename

        lines = []
        if log_path.exists():
            try:
                with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
                    lines = f.readlines()[-200:] # Last 200 lines
            except Exception as e:
                lines = [f"Error reading log file: {e}"]

        return jsonify({'log_type': log_type, 'lines': lines}), 200

    @staticmethod
    def ai_chat() -> Tuple[Dict[str, Any], int]:
        data = request.get_json() or {}
        user_message = data.get('message', '')
        if not user_message:
            return jsonify({'error': 'Message parameter is required'}), 400
        from app.services.ai_service import AIService
        response_text = AIService.chat_response(user_message)
        return jsonify({'response': response_text}), 200

    @staticmethod
    def get_ai_insights() -> Tuple[Dict[str, Any], int]:
        monitor_mgr = getattr(current_app, 'monitor_manager', None)
        is_running = monitor_mgr.get_status().get('is_running', False) if monitor_mgr else False
        from app.services.ai_service import AIService
        insights = AIService.get_dashboard_insights(is_running)
        return jsonify(insights), 200

    @staticmethod
    def get_ai_status() -> Tuple[Dict[str, Any], int]:
        key = os.environ.get('ANTHROPIC_API_KEY', '')
        return jsonify({'llm_enabled': bool(key)}), 200

    @staticmethod
    def download_pdf_report():
        from app.services.pdf_service import PDFService
        pdf_buffer = PDFService.generate_security_report()
        return send_file(
            pdf_buffer,
            as_attachment=True,
            download_name=f"CanaryGuard_Security_Report_{datetime.now().strftime('%Y%m%d_%H%M')}.pdf",
            mimetype='application/pdf'
        )

    @staticmethod
    def export_data(fmt: str):
        import csv
        import json
        import io
        from flask import Response
        
        fmt = fmt.lower()
        incidents = Incident.query.order_by(Incident.created_at.desc()).all()
        canaries = CanaryFile.query.all()
        quarantined = QuarantineHistory.query.all()

        if fmt == 'json':
            data = {
                'incidents': [i.to_dict() for i in incidents],
                'canaries': [c.to_dict() for c in canaries],
                'quarantined': [q.to_dict() for q in quarantined]
            }
            return jsonify(data), 200
        elif fmt == 'csv':
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow(['Incident ID', 'Created At', 'Threat Level', 'File Path', 'Entropy', 'Process', 'Status', 'Confidence Score'])
            for i in incidents:
                writer.writerow([i.id, i.created_at, i.threat_level, i.file_path, i.entropy_value, i.process_name, i.status, i.confidence_score])
            
            output.seek(0)
            return Response(
                output.getvalue(),
                mimetype="text/csv",
                headers={"Content-Disposition": "attachment;filename=CanaryGuard_Export.csv"}
            )
        else:
            return jsonify({'error': 'Invalid format. Use json or csv.'}), 400
