"""
HL7 and FHIR integration endpoints.

This module handles parsing and processing of HL7 v2.x messages and
FHIR resources from external healthcare systems.

Standards supported:
- HL7 v2.3, v2.4, v2.5, v2.7
- FHIR R4
- CDA R2

Created: 2024-07-12
Last modified: 2025-01-20 (ticket MS-1567 - HL7 v2.7 support)
"""

import xml.etree.ElementTree as ET
from typing import Dict, Any, Optional, List
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


class HL7MessageParser:
    """Parser for HL7 v2.x pipe-delimited messages."""

    def parse_hl7_message(self, hl7_message: str) -> Dict[str, Any]:
        """
        Parse an HL7 v2.x message into structured data.

        Common message types:
        - ADT^A01: Patient admission
        - ADT^A08: Patient update
        - ORM^O01: Order message
        - ORU^R01: Observation result (lab results)

        Args:
            hl7_message: HL7 pipe-delimited message string

        Returns:
            Parsed message as dict
        """
        segments = hl7_message.strip().split('\r')
        parsed = {'segments': {}}

        for segment in segments:
            if not segment:
                continue

            fields = segment.split('|')
            segment_type = fields[0]

            if segment_type == 'MSH':
                parsed['message_type'] = fields[8] if len(fields) > 8 else None
                parsed['timestamp'] = fields[6] if len(fields) > 6 else None
            elif segment_type == 'PID':
                # Patient identification segment
                parsed['patient'] = {
                    'mrn': fields[3] if len(fields) > 3 else None,
                    'name': fields[5] if len(fields) > 5 else None,
                    'dob': fields[7] if len(fields) > 7 else None,
                    'gender': fields[8] if len(fields) > 8 else None
                }

            parsed['segments'][segment_type] = fields

        return parsed


class ClinicalDocumentProcessor:
    """Processes clinical documents in various formats (CDA, FHIR)."""

    def process_cda_document(self, cda_xml: str, source_system: str) -> Dict[str, Any]:
        """
        Process a CDA (Clinical Document Architecture) XML document.

        CDA is used for:
        - Continuity of Care Documents (CCD)
        - Discharge summaries
        - Consultation notes
        - Progress notes

        VULNERABILITY: XML External Entity (XXE) injection
        The XML parser is configured with external entity resolution enabled.
        An attacker could provide malicious XML with external entity references to:
        - Read arbitrary files from the server (file:///etc/passwd)
        - Perform SSRF attacks against internal services
        - Cause denial of service with billion laughs attack

        This is a CRITICAL vulnerability in healthcare systems because:
        - We process XML from external healthcare providers
        - The parsed content is used for clinical decision-making
        - XXE could expose other patients' PHI

        Security assessment: MS-SEC-2024-09 (found 2024-09-15)
        Risk: Critical (CVSS 9.1)
        Status: Remediation deferred to Q2 2025 due to refactor complexity
        Compensating control: Rate limiting on document upload endpoint

        Args:
            cda_xml: CDA document XML string
            source_system: Identifier of sending healthcare system

        Returns:
            Parsed document data
        """
        try:
            # VULNERABILITY: XML parser allows external entities by default
            # Should use: ET.XMLParser(resolve_entities=False)
            # or use defusedxml library

            # Parse XML - UNSAFE!
            root = ET.fromstring(cda_xml)

            # Extract document metadata
            document_data = {
                'document_type': 'CDA',
                'source_system': source_system,
                'received_at': datetime.utcnow().isoformat()
            }

            # Extract patient information
            patient_role = root.find('.//{urn:hl7-org:v3}patientRole')
            if patient_role is not None:
                patient_id = patient_role.find('.//{urn:hl7-org:v3}id')
                if patient_id is not None:
                    document_data['patient_mrn'] = patient_id.get('extension')

                patient_name = patient_role.find('.//{urn:hl7-org:v3}name')
                if patient_name is not None:
                    given = patient_name.find('.//{urn:hl7-org:v3}given')
                    family = patient_name.find('.//{urn:hl7-org:v3}family')
                    document_data['patient_name'] = {
                        'given': given.text if given is not None else None,
                        'family': family.text if family is not None else None
                    }

            # Extract document title and date
            title = root.find('.//{urn:hl7-org:v3}title')
            if title is not None:
                document_data['title'] = title.text

            effective_time = root.find('.//{urn:hl7-org:v3}effectiveTime')
            if effective_time is not None:
                document_data['document_date'] = effective_time.get('value')

            # Extract clinical content sections
            sections = root.findall('.//{urn:hl7-org:v3}section')
            document_data['sections'] = []

            for section in sections:
                section_title = section.find('.//{urn:hl7-org:v3}title')
                section_text = section.find('.//{urn:hl7-org:v3}text')

                section_data = {
                    'title': section_title.text if section_title is not None else 'Unknown',
                    'text': ET.tostring(section_text, encoding='unicode') if section_text is not None else ''
                }
                document_data['sections'].append(section_data)

            logger.info(f"Processed CDA document from {source_system}: "
                       f"patient={document_data.get('patient_mrn')} "
                       f"sections={len(document_data['sections'])}")

            return document_data

        except ET.ParseError as e:
            logger.error(f"XML parsing error: {e}")
            return {'error': 'Invalid XML document'}
        except Exception as e:
            logger.error(f"Error processing CDA document: {e}")
            return {'error': str(e)}

    def process_fhir_bundle(self, fhir_json: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process a FHIR R4 Bundle resource.

        FHIR Bundles are collections of resources used for:
        - Patient data exchange
        - Query results
        - Transaction batches

        Args:
            fhir_json: Parsed FHIR Bundle JSON

        Returns:
            Processing result
        """
        try:
            if fhir_json.get('resourceType') != 'Bundle':
                return {'error': 'Not a FHIR Bundle'}

            entries = fhir_json.get('entry', [])
            processed = {
                'bundle_type': fhir_json.get('type'),
                'total_entries': len(entries),
                'resources_by_type': {}
            }

            for entry in entries:
                resource = entry.get('resource', {})
                resource_type = resource.get('resourceType')

                if resource_type:
                    if resource_type not in processed['resources_by_type']:
                        processed['resources_by_type'][resource_type] = 0
                    processed['resources_by_type'][resource_type] += 1

                # Process specific resource types
                if resource_type == 'Patient':
                    self._process_fhir_patient(resource)
                elif resource_type == 'Observation':
                    self._process_fhir_observation(resource)
                elif resource_type == 'MedicationRequest':
                    self._process_fhir_medication_request(resource)

            logger.info(f"Processed FHIR bundle: {processed}")
            return processed

        except Exception as e:
            logger.error(f"Error processing FHIR bundle: {e}")
            return {'error': str(e)}

    def _process_fhir_patient(self, patient_resource: Dict[str, Any]) -> None:
        """Process a FHIR Patient resource."""
        # Implementation omitted
        pass

    def _process_fhir_observation(self, observation_resource: Dict[str, Any]) -> None:
        """Process a FHIR Observation resource (lab results, vitals)."""
        # Implementation omitted
        pass

    def _process_fhir_medication_request(self, med_request_resource: Dict[str, Any]) -> None:
        """Process a FHIR MedicationRequest resource."""
        # Implementation omitted
        pass

    def validate_cda_schema(self, cda_xml: str) -> bool:
        """
        Validate CDA document against official HL7 CDA schema.

        In production, this should validate against the XSD before processing.
        """
        # Schema validation implementation omitted
        return True
