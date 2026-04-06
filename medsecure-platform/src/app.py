"""
MedSecure Platform - Main Flask Application

This is the main entry point for the MedSecure healthcare platform API.
Provides RESTful endpoints for EHR, patient management, and integrations.

Created: 2024-05-01
Last modified: 2025-01-22
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import logging

from config import config
from auth.login import AuthenticationService
from auth.tokens import JWTTokenService
from patients.records import PatientRecordService
from patients.search import PatientSearchService
from patients.export import PatientExportService
from api.webhooks import WebhookProcessor
from api.integrations import ClinicalDocumentProcessor
from utils.logging import audit_logger

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = config.secret_key
app.config['DEBUG'] = config.debug

# Configure CORS
CORS(app, origins=config.cors_origins)

# Configure logging
logging.basicConfig(
    level=getattr(logging, config.log_level),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


# ============================================================================
# Authentication Endpoints
# ============================================================================

@app.route('/api/auth/login', methods=['POST'])
def login():
    """
    Authenticate a healthcare provider.

    Request body:
    {
        "username": "doctor@example.com",
        "password": "password123",
        "facility_id": "FAC-001"
    }
    """
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    facility_id = data.get('facility_id')

    if not all([username, password, facility_id]):
        return jsonify({'error': 'Missing required fields'}), 400

    # Authenticate user
    auth_service = AuthenticationService(config.get_database_config().__dict__)
    user = auth_service.authenticate_user(username, password, facility_id)

    if not user:
        audit_logger.log_authentication(username, False, request.remote_addr)
        return jsonify({'error': 'Invalid credentials'}), 401

    # Generate JWT tokens
    token_service = JWTTokenService()
    tokens = token_service.generate_token_pair(
        user_id=user['user_id'],
        role=user['role'],
        facility_id=user['facility_id'],
        email=user['email']
    )

    audit_logger.log_authentication(username, True, request.remote_addr)

    return jsonify({
        'user': user,
        'access_token': tokens.access_token,
        'refresh_token': tokens.refresh_token,
        'expires_at': tokens.expires_at
    }), 200


# ============================================================================
# Patient Records Endpoints
# ============================================================================

@app.route('/api/patients/<patient_id>/documents/<path:document_path>', methods=['GET'])
def download_patient_document(patient_id, document_path):
    """Download a patient document."""
    # In production, would verify JWT token and authorization
    user_id = request.headers.get('X-User-ID', 0)

    record_service = PatientRecordService()
    file_handle = record_service.download_patient_document(
        patient_id, document_path, int(user_id)
    )

    if not file_handle:
        return jsonify({'error': 'Document not found'}), 404

    # Return file (simplified)
    return jsonify({'status': 'success'}), 200


@app.route('/api/patients/search', methods=['POST'])
def search_patients():
    """Search for patients."""
    data = request.get_json()
    facility_id = request.headers.get('X-Facility-ID', 'FAC-001')
    user_id = int(request.headers.get('X-User-ID', 0))

    search_service = PatientSearchService(config.mongo_uri)
    results = search_service.search_patients(data, facility_id, user_id)

    return jsonify({'patients': results, 'count': len(results)}), 200


@app.route('/api/patients/<patient_id>/export/pdf', methods=['POST'])
def export_patient_pdf(patient_id):
    """Export patient summary as PDF."""
    user_id = int(request.headers.get('X-User-ID', 0))
    template = request.args.get('template', 'clinical_summary')

    export_service = PatientExportService()
    pdf_bytes = export_service.export_patient_summary_pdf(patient_id, user_id, template)

    if not pdf_bytes:
        return jsonify({'error': 'Export failed'}), 500

    return jsonify({'status': 'success'}), 200


@app.route('/api/patients/<patient_id>/export/external', methods=['POST'])
def export_to_external(patient_id):
    """Export patient data to external service."""
    data = request.get_json()
    export_url = data.get('export_url')
    format_type = data.get('format', 'fhir')
    user_id = int(request.headers.get('X-User-ID', 0))

    if not export_url:
        return jsonify({'error': 'export_url is required'}), 400

    export_service = PatientExportService()
    success = export_service.export_to_external_service(
        patient_id, export_url, user_id, format_type
    )

    if success:
        return jsonify({'status': 'success'}), 200
    else:
        return jsonify({'error': 'Export failed'}), 500


# ============================================================================
# Webhook Endpoints
# ============================================================================

@app.route('/api/webhooks/lab-results', methods=['POST'])
def lab_results_webhook():
    """Receive lab results from external lab systems."""
    processor = WebhookProcessor(None)
    result = processor.process_lab_result_webhook(request)
    return jsonify(result), 200 if result['status'] == 'success' else 400


@app.route('/api/webhooks/pharmacy', methods=['POST'])
def pharmacy_webhook():
    """Receive prescription status updates from pharmacies."""
    processor = WebhookProcessor(None)
    result = processor.process_pharmacy_webhook(request)
    return jsonify(result), 200 if result['status'] == 'success' else 400


# ============================================================================
# Integration Endpoints
# ============================================================================

@app.route('/api/integrations/cda', methods=['POST'])
def process_cda_document():
    """Process a CDA clinical document."""
    cda_xml = request.data.decode('utf-8')
    source_system = request.headers.get('X-Source-System', 'unknown')

    processor = ClinicalDocumentProcessor()
    result = processor.process_cda_document(cda_xml, source_system)

    return jsonify(result), 200


# ============================================================================
# Health Check
# ============================================================================

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint for load balancers."""
    return jsonify({
        'status': 'healthy',
        'version': config.version,
        'environment': config.environment
    }), 200


if __name__ == '__main__':
    # Log configuration issues
    config_issues = config.validate()
    if config_issues:
        logger.warning("Configuration issues detected:")
        for issue in config_issues:
            logger.warning(f"  - {issue}")

    # Start Flask development server
    logger.info(f"Starting MedSecure Platform v{config.version}")
    logger.info(f"Environment: {config.environment}")
    logger.info(f"Debug mode: {config.debug}")

    app.run(
        host=config.host,
        port=config.port,
        debug=config.debug
    )
