# MedSecure Platform

Enterprise healthcare EHR and integration platform supporting FHIR R4, HL7 v2.x, and CDA standards.

## Overview

MedSecure Platform is a comprehensive healthcare data management system that provides:

- **Electronic Health Records (EHR)**: Patient demographics, medical history, medications, allergies
- **Clinical Integrations**: HL7 v2.x and FHIR R4 message processing
- **Lab Integrations**: Real-time lab result ingestion via webhooks
- **Patient Portal**: Secure patient access to medical records
- **Interoperability**: FHIR API for external system integration
- **HIPAA Compliance**: Audit logging, encryption at rest, role-based access control

## Architecture

```
medsecure-platform/
├── src/
│   ├── auth/              # Authentication & authorization
│   ├── patients/          # Patient data management
│   ├── api/               # Webhooks and integrations
│   ├── utils/             # Cryptography, logging utilities
│   ├── app.py             # Flask application
│   └── config.py          # Configuration management
├── tests/                 # Unit and integration tests
├── docs/                  # API documentation
└── .github/workflows/     # CI/CD and security scanning
```

## Technology Stack

- **Backend**: Python 3.11, Flask 3.0
- **Databases**: PostgreSQL 15 (transactional data), MongoDB 6 (search index)
- **Cache**: Redis 7
- **Standards**: FHIR R4, HL7 v2.x, CDA R2
- **Security**: JWT authentication, AES-256-GCM encryption, HIPAA audit logging

## Setup

### Prerequisites

- Python 3.11+
- PostgreSQL 15+
- MongoDB 6+
- Redis 7+

### Installation

```bash
# Clone repository
git clone https://github.com/medsecure/platform.git
cd platform

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Set environment variables
cp .env.example .env
# Edit .env with your configuration

# Run database migrations
python scripts/migrate.py

# Start application
python src/app.py
```

## Environment Variables

```bash
# Application
ENVIRONMENT=production
DEBUG=false
SECRET_KEY=your-secret-key-here

# Database
DB_HOST=localhost
DB_PORT=5432
DB_NAME=medsecure
DB_USER=medsecure_app
DB_PASSWORD=secure-password

# MongoDB
MONGO_URI=mongodb://localhost:27017

# Redis
REDIS_URL=redis://localhost:6379/0

# JWT
JWT_SECRET=your-jwt-secret
JWT_EXPIRY_HOURS=1

# CORS
CORS_ORIGINS=https://app.medsecure.com,https://portal.medsecure.com

# Webhooks
LAB_WEBHOOK_SECRET=your-lab-webhook-secret
PHARMACY_WEBHOOK_SECRET=your-pharmacy-webhook-secret
```

## API Documentation

Full API documentation is available at `/docs/api-spec.md`.

### Authentication

```bash
POST /api/auth/login
Content-Type: application/json

{
  "username": "doctor@example.com",
  "password": "password",
  "facility_id": "FAC-001"
}
```

### Patient Search

```bash
POST /api/patients/search
Authorization: Bearer {access_token}
Content-Type: application/json

{
  "name": "Smith",
  "dob": "1980-05-15"
}
```

## Security

### CodeQL Scanning

This repository uses GitHub CodeQL for automated security scanning. Scans run:
- On every pull request
- On push to main branch
- Daily at 6:00 AM UTC

### Known Issues

Security findings are tracked in GitHub Issues with the `security` and `codeql` labels. Our security team triages all findings within 48 hours.

Critical and High severity findings are prioritized for immediate remediation.

### Reporting Security Issues

To report a security vulnerability, please email security@medsecure.com. Do not open public GitHub issues for security vulnerabilities.

## Testing

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=src --cov-report=html

# Run specific test file
pytest tests/test_auth.py
```

## HIPAA Compliance

MedSecure Platform implements HIPAA Security Rule requirements:

- **Access Control**: Role-based access control (RBAC) with facility-level isolation
- **Audit Controls**: Comprehensive audit logging of all PHI access
- **Integrity**: Cryptographic checksums for data integrity verification
- **Transmission Security**: TLS 1.3 for all network communication
- **Encryption**: AES-256-GCM for data at rest

All access to Protected Health Information (PHI) is logged and retained for 7 years in compliance with HIPAA requirements.

## License

Proprietary - Copyright © 2024 MedSecure Inc. All rights reserved.

## Support

For technical support, contact support@medsecure.com or open a ticket in our support portal.
