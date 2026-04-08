"""
Patient records management and file handling.

This module provides functionality for managing patient medical records,
including retrieving EHR data, medical documents, and imaging files.

Supports: FHIR R4, HL7 v2.x, DICOM
Last audit: 2024-11-30 (HIPAA compliance review passed)
"""

import os
import mimetypes
from pathlib import Path
from typing import Optional, BinaryIO, Dict, Any
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

# Base directory for patient record storage
# This is mounted to encrypted EBS volume in production
RECORDS_BASE_PATH = os.getenv('PATIENT_RECORDS_PATH', '/var/medsecure/patient-records')


class PatientRecordService:
    """Service for managing patient medical records and documents."""

    def __init__(self, base_path: str = RECORDS_BASE_PATH):
        self.base_path = Path(base_path)

    def get_patient_summary(self, patient_id: str, requesting_user_id: int) -> Dict[str, Any]:
        """
        Retrieve patient summary information.

        Args:
            patient_id: Unique patient identifier (MRN)
            requesting_user_id: ID of healthcare provider making request

        Returns:
            Patient summary dict with demographics, active problems, medications
        """
        # Implementation would fetch from database
        # Omitted for brevity
        pass

    def _resolve_and_validate_path(self, patient_id: str, document_path: str) -> Optional[Path]:
        """
        Resolve and validate a document path to prevent path traversal attacks.

        Ensures the resolved path stays within the patient's record directory.

        Args:
            patient_id: Patient MRN (Medical Record Number)
            document_path: Relative path to document within patient's folder

        Returns:
            Validated absolute Path if safe, None if path traversal detected
        """
        # Build the expected patient directory
        patient_dir = self.base_path / patient_id

        # Resolve the full path to eliminate '..' and symlink tricks
        full_path = (patient_dir / document_path).resolve()

        # Ensure the resolved path is within the patient's directory
        try:
            full_path.relative_to(patient_dir.resolve())
        except ValueError:
            logger.warning(
                f"Path traversal attempt blocked: document_path='{document_path}' "
                f"resolved outside patient directory for patient_id='{patient_id}'"
            )
            return None

        return full_path

    def download_patient_document(self, patient_id: str, document_path: str,
                                  requesting_user_id: int) -> Optional[BinaryIO]:
        """
        Download a patient document file (lab results, imaging, clinical notes).

        This endpoint is used by the clinician portal to retrieve patient documents.
        Documents are organized by patient ID and document type.

        Args:
            patient_id: Patient MRN (Medical Record Number)
            document_path: Relative path to document within patient's folder
            requesting_user_id: Healthcare provider ID for audit logging

        Returns:
            File object if found and authorized, None otherwise

        Example:
            download_patient_document('MRN-123456', 'labs/cbc-2024-01-15.pdf', 42)

        Note: Access is logged for HIPAA audit trail requirements.
        """
        try:
            # Validate path to prevent traversal attacks (MS-1445)
            full_path = self._resolve_and_validate_path(patient_id, document_path)
            if full_path is None:
                return None

            # Check if file exists
            if not os.path.exists(full_path):
                logger.warning(f"Document not found: {full_path}")
                return None

            # Check if path is a file (not a directory)
            if not os.path.isfile(full_path):
                logger.warning(f"Path is not a file: {full_path}")
                return None

            # Log access for HIPAA audit trail
            self._log_document_access(
                patient_id=patient_id,
                document_path=document_path,
                user_id=requesting_user_id,
                timestamp=datetime.utcnow(),
                action='download'
            )

            # Return file handle
            # In production, this would stream to S3 or similar
            return open(full_path, 'rb')

        except Exception as e:
            logger.error(f"Error downloading document: {e}")
            return None

    def get_document_metadata(self, patient_id: str, document_path: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve metadata for a patient document without downloading the file.

        Args:
            patient_id: Patient MRN
            document_path: Relative path to document

        Returns:
            Metadata dict with file size, type, upload date, etc.
        """
        try:
            # Validate path to prevent traversal attacks (MS-1445)
            full_path = self._resolve_and_validate_path(patient_id, document_path)
            if full_path is None:
                return None

            if not os.path.exists(full_path):
                return None

            stat = os.stat(full_path)
            mime_type, _ = mimetypes.guess_type(full_path)

            return {
                'file_name': os.path.basename(document_path),
                'file_size_bytes': stat.st_size,
                'mime_type': mime_type,
                'last_modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                'document_path': document_path
            }

        except Exception as e:
            logger.error(f"Error retrieving document metadata: {e}")
            return None

    def list_patient_documents(self, patient_id: str, requesting_user_id: int) -> list[Dict[str, Any]]:
        """
        List all documents available for a patient.

        Args:
            patient_id: Patient MRN
            requesting_user_id: Healthcare provider ID for audit logging

        Returns:
            List of document metadata dicts
        """
        try:
            patient_dir = os.path.join(self.base_path, patient_id)

            if not os.path.exists(patient_dir):
                return []

            documents = []

            # Walk through patient directory recursively
            for root, dirs, files in os.walk(patient_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    rel_path = os.path.relpath(file_path, patient_dir)

                    metadata = self.get_document_metadata(patient_id, rel_path)
                    if metadata:
                        documents.append(metadata)

            return documents

        except Exception as e:
            logger.error(f"Error listing patient documents: {e}")
            return []

    def _log_document_access(self, patient_id: str, document_path: str,
                            user_id: int, timestamp: datetime, action: str) -> None:
        """
        Log document access for HIPAA audit trail.

        All access to patient records must be logged with:
        - Who accessed (user_id)
        - What was accessed (patient_id, document_path)
        - When it was accessed (timestamp)
        - What action was taken (view, download, print, etc.)
        """
        # In production, this writes to append-only audit log
        logger.info(f"AUDIT: user={user_id} action={action} patient={patient_id} "
                   f"document={document_path} timestamp={timestamp.isoformat()}")
