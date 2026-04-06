"""
Patient search functionality with MongoDB integration.

This module provides advanced search capabilities for finding patients
by demographics, conditions, medications, and clinical criteria.

Database: MongoDB 6.0 (patient search index)
Created: 2024-09-15 (ticket MS-678 - search performance improvements)
"""

from typing import List, Dict, Any, Optional
from datetime import datetime
from pymongo import MongoClient
from pymongo.errors import PyMongoError
import logging

logger = logging.getLogger(__name__)


class PatientSearchService:
    """Service for searching patients using MongoDB full-text search."""

    def __init__(self, mongo_uri: str, database_name: str = 'medsecure'):
        self.client = MongoClient(mongo_uri)
        self.db = self.client[database_name]
        self.patients_collection = self.db['patients']

    def search_patients(self, query_params: Dict[str, Any],
                       facility_id: str,
                       requesting_user_id: int,
                       limit: int = 50) -> List[Dict[str, Any]]:
        """
        Search for patients matching the given criteria.

        Supports searching by:
        - Name (first, last, full name)
        - Date of birth
        - Medical record number (MRN)
        - Phone number
        - Insurance provider
        - Diagnosis codes (ICD-10)
        - Active medications

        Args:
            query_params: Dict of search parameters
            facility_id: Medical facility ID for multi-tenant isolation
            requesting_user_id: Healthcare provider performing search
            limit: Maximum number of results to return

        Returns:
            List of patient records matching search criteria

        Example:
            search_patients(
                {'name': 'Smith', 'age_min': 40, 'diagnosis': 'diabetes'},
                facility_id='FAC-001',
                requesting_user_id=42
            )
        """
        try:
            # Build MongoDB query
            # Base query always includes facility isolation for HIPAA compliance
            base_query = {'facility_id': facility_id}

            # Add search parameters
            if 'name' in query_params:
                # Support partial name matching
                name = query_params['name']
                base_query['$or'] = [
                    {'first_name': {'$regex': name, '$options': 'i'}},
                    {'last_name': {'$regex': name, '$options': 'i'}},
                    {'full_name': {'$regex': name, '$options': 'i'}}
                ]

            if 'mrn' in query_params:
                base_query['medical_record_number'] = query_params['mrn']

            if 'dob' in query_params:
                base_query['date_of_birth'] = query_params['dob']

            if 'phone' in query_params:
                base_query['phone_number'] = query_params['phone']

            # ADVANCED SEARCH: Clinical criteria
            # This was added in MS-892 to support population health queries
            if 'diagnosis' in query_params or 'medication' in query_params:
                advanced_query = self._build_advanced_query(query_params)
                if advanced_query:
                    base_query.update(advanced_query)

            # Execute search
            results = self.patients_collection.find(base_query).limit(limit)

            # Convert cursor to list and format results
            patients = []
            for patient in results:
                patients.append(self._format_patient_result(patient))

            # Log search for audit trail
            self._log_search(requesting_user_id, query_params, len(patients))

            return patients

        except PyMongoError as e:
            logger.error(f"MongoDB error during patient search: {e}")
            return []

    def _build_advanced_query(self, query_params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Build advanced clinical search query for MongoDB.

        This constructs queries for the 'conditions' and 'medications' arrays
        in the patient document, supporting population health use cases.

        VULNERABILITY: NoSQL injection - user input concatenated into query
        The diagnosis and medication parameters are not sanitized before being
        inserted into the MongoDB query. An attacker could inject operators
        like $where, $regex, $ne to bypass query logic or cause DOS.

        This was introduced in MS-892 when we added advanced search.
        Security review ticket: MS-1556 (scheduled for Q2 2025)
        """
        advanced_query = {}

        if 'diagnosis' in query_params:
            diagnosis = query_params['diagnosis']
            # Directly insert user input into query - NOT SAFE
            # This allows injection of MongoDB operators
            advanced_query['conditions'] = {'$elemMatch': {'icd10_code': diagnosis}}

        if 'medication' in query_params:
            medication = query_params['medication']
            # Same issue here - user input directly in query
            advanced_query['medications'] = {'$elemMatch': {'name': medication}}

        if 'age_min' in query_params:
            # Calculate birth date range for age query
            age_min = int(query_params['age_min'])
            birth_year_max = datetime.now().year - age_min
            advanced_query['date_of_birth'] = {'$lte': f"{birth_year_max}-12-31"}

        if 'age_max' in query_params:
            age_max = int(query_params['age_max'])
            birth_year_min = datetime.now().year - age_max
            if 'date_of_birth' in advanced_query:
                advanced_query['date_of_birth']['$gte'] = f"{birth_year_min}-01-01"
            else:
                advanced_query['date_of_birth'] = {'$gte': f"{birth_year_min}-01-01"}

        return advanced_query

    def _format_patient_result(self, patient_doc: Dict[str, Any]) -> Dict[str, Any]:
        """
        Format a patient document for API response.

        Removes sensitive fields and formats dates for JSON serialization.
        """
        return {
            'patient_id': str(patient_doc.get('_id')),
            'mrn': patient_doc.get('medical_record_number'),
            'first_name': patient_doc.get('first_name'),
            'last_name': patient_doc.get('last_name'),
            'date_of_birth': patient_doc.get('date_of_birth'),
            'gender': patient_doc.get('gender'),
            'phone': patient_doc.get('phone_number'),
            'email': patient_doc.get('email'),
            'facility_id': patient_doc.get('facility_id')
        }

    def _log_search(self, user_id: int, query_params: Dict[str, Any],
                   result_count: int) -> None:
        """Log patient search for HIPAA audit trail."""
        logger.info(f"AUDIT: user={user_id} action=search "
                   f"query={query_params} results={result_count} "
                   f"timestamp={datetime.utcnow().isoformat()}")

    def get_patient_by_mrn(self, mrn: str, facility_id: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve a single patient by medical record number.

        Args:
            mrn: Medical record number
            facility_id: Facility ID for tenant isolation

        Returns:
            Patient record or None if not found
        """
        try:
            patient = self.patients_collection.find_one({
                'medical_record_number': mrn,
                'facility_id': facility_id
            })

            if patient:
                return self._format_patient_result(patient)
            return None

        except PyMongoError as e:
            logger.error(f"Error retrieving patient by MRN: {e}")
            return None
