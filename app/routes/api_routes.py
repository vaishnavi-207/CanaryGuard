from flask import Blueprint
from app.controllers.api_controller import APIController

api_bp = Blueprint('api', __name__, url_prefix='/api')

# System & Monitoring Status
api_bp.route('/status', methods=['GET'])(APIController.get_system_status)
api_bp.route('/start-monitor', methods=['POST'])(APIController.start_monitor)
api_bp.route('/stop-monitor', methods=['POST'])(APIController.stop_monitor)

# Incidents
api_bp.route('/incidents', methods=['GET'])(APIController.get_incidents)
api_bp.route('/incidents/<int:incident_id>', methods=['DELETE'])(APIController.delete_incident)

# Canary Files
api_bp.route('/canaries', methods=['GET'])(APIController.get_canaries)
api_bp.route('/deploy-canaries', methods=['POST'])(APIController.deploy_canaries)

# Processes & Quarantine
api_bp.route('/processes', methods=['GET'])(APIController.get_processes)
api_bp.route('/quarantine', methods=['POST'])(APIController.manual_quarantine)

# Metrics & Folders
api_bp.route('/statistics', methods=['GET'])(APIController.get_statistics)
api_bp.route('/settings', methods=['GET'])(APIController.get_settings)
api_bp.route('/settings', methods=['POST'])(APIController.update_settings)
api_bp.route('/monitored-folders', methods=['GET'])(APIController.get_monitored_folders)
api_bp.route('/monitored-folders', methods=['POST'])(APIController.add_monitored_folder)
api_bp.route('/logs', methods=['GET'])(APIController.get_logs)

# AI & Reporting Routes
api_bp.route('/ai/chat', methods=['POST'])(APIController.ai_chat)
api_bp.route('/ai/insights', methods=['GET'])(APIController.get_ai_insights)
api_bp.route('/reports/pdf', methods=['GET'])(APIController.download_pdf_report)
api_bp.route('/export/<fmt>', methods=['GET'])(APIController.export_data)

# Presentation Mode Trigger
api_bp.route('/presentation/trigger-demo', methods=['POST'])(APIController.trigger_presentation_demo)

