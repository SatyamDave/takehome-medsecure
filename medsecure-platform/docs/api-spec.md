# MedSecure Platform API Specification

## Authentication

All API endpoints (except `/api/auth/login`) require authentication via JWT Bearer token.

Include token in Authorization header:
```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

## Endpoints

### POST /api/auth/login
Authenticate and receive access token.

**Request:**
```json
{
  "username": "doctor@example.com",
  "password": "password123",
  "facility_id": "FAC-001"
}
```

**Response:**
```json
{
  "user": {
    "user_id": 42,
    "username": "doctor@example.com",
    "role": "physician",
    "facility_id": "FAC-001"
  },
  "access_token": "eyJhbGc...",
  "refresh_token": "eyJhbGc...",
  "expires_at": "2025-01-20T15:30:00Z"
}
```

### POST /api/patients/search
Search for patients by various criteria.

**Request:**
```json
{
  "name": "Smith",
  "dob": "1980-05-15",
  "diagnosis": "E11.9"
}
```

**Response:**
```json
{
  "patients": [
    {
      "patient_id": "507f1f77bcf86cd799439011",
      "mrn": "MRN-123456",
      "first_name": "Jane",
      "last_name": "Smith",
      "date_of_birth": "1980-05-15",
      "gender": "F"
    }
  ],
  "count": 1
}
```

## Webhook Endpoints

### POST /api/webhooks/lab-results
Receive lab results from external lab systems.

**Headers:**
```
Content-Type: application/json
X-Lab-Signature: sha256=abc123...
```

**Request:**
```json
{
  "patient_mrn": "MRN-123456",
  "accession_number": "LAB-2024-0001",
  "lab_name": "Quest Diagnostics",
  "results": [
    {
      "test_code": "CBC",
      "test_name": "Complete Blood Count",
      "value": "14.5",
      "unit": "g/dL",
      "reference_range": "12-16",
      "abnormal_flag": null
    }
  ]
}
```
