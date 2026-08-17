from flask import Blueprint
from app.controllers.api_controller import APIController
from app.security import login_required

api_bp = Blueprint('api', __name__, url_prefix='/api')

# System & Monitoring Status
api_bp.route('/status', methods=['GET'])(login_required(APIController.get_system_status))
api_bp.route('/start-monitor', methods=['POST'])(login_required(APIController.start_monitor))
api_bp.route('/stop-monitor', methods=['POST'])(login_required(APIController.stop_monitor))

# Incidents
api_bp.route('/incidents', methods=['GET'])(login_required(APIController.get_incidents))
api_bp.route('/incidents/<int:incident_id>', methods=['DELETE'])(login_required(APIController.delete_incident))
api_bp.route('/incidents/<int:incident_id>/recovery', methods=['POST', 'PUT'])(login_required(APIController.update_incident_recovery))
api_bp.route('/recovery/stats', methods=['GET'])(login_required(APIController.get_recovery_stats))

# Canary Files
api_bp.route('/canaries', methods=['GET'])(login_required(APIController.get_canaries))
api_bp.route('/canaries', methods=['DELETE'])(login_required(APIController.delete_canaries))
api_bp.route('/deploy-canaries', methods=['POST'])(login_required(APIController.deploy_canaries))

# Processes & Quarantine
api_bp.route('/processes', methods=['GET'])(login_required(APIController.get_processes))
api_bp.route('/quarantine', methods=['POST'])(login_required(APIController.manual_quarantine))

# Metrics & Folders
api_bp.route('/statistics', methods=['GET'])(login_required(APIController.get_statistics))
api_bp.route('/settings', methods=['GET'])(login_required(APIController.get_settings))
api_bp.route('/settings', methods=['POST'])(login_required(APIController.update_settings))
api_bp.route('/monitored-folders', methods=['GET'])(login_required(APIController.get_monitored_folders))
api_bp.route('/monitored-folders', methods=['POST'])(login_required(APIController.add_monitored_folder))
api_bp.route('/logs', methods=['GET'])(login_required(APIController.get_logs))

# AI & Reporting Routes
api_bp.route('/ai/chat', methods=['POST'])(login_required(APIController.ai_chat))
api_bp.route('/ai/insights', methods=['GET'])(login_required(APIController.get_ai_insights))
api_bp.route('/ai/status', methods=['GET'])(APIController.get_ai_status)
api_bp.route('/reports/pdf', methods=['GET'])(login_required(APIController.download_pdf_report))
api_bp.route('/export/<fmt>', methods=['GET'])(login_required(APIController.export_data))
