import hashlib
import os
import subprocess
import sys
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
from app.database.db import db
from app.models.canary_file import CanaryFile
from app.logging.logger import get_security_logger, get_error_logger

logger = get_security_logger()
error_logger = get_error_logger()

CANARY_FILENAMES = [
    "Confidential_Report.docx",
    "Payroll.xlsx",
    "Employee_Database.pdf",
    "Financial_Records.xlsx",
    "Annual_Report.docx",
    "Passwords.pdf",
    "Project_Plan.docx",
    "Contracts.pdf"
]

CANARY_CONTENT_TEMPLATES = {
    ".docx": b"PK\x03\x04\x14\x00\x06\x00\x08\x00\x00\x00!CanaryGuard Decoy Document Data\x00\x00\x00",
    ".xlsx": b"PK\x03\x04\x14\x00\x06\x00\x08\x00\x00\x00!CanaryGuard Financial Worksheet\x00\x00\x00",
    ".pdf": b"%PDF-1.7\n%CanaryGuard Decoy Confidential Document\n1 0 obj\n<< /Type /Catalog >>\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF"
}

class CanaryDeploymentEngine:
    """Manages the creation, hidden attributes, verification, and auto-redeployment of canary files."""

    @staticmethod
    def calculate_file_hash(file_path: str) -> str:
        """Computes SHA-256 hash of a canary file."""
        sha256 = hashlib.sha256()
        try:
            with open(file_path, 'rb') as f:
                while chunk := f.read(65536):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except Exception as e:
            error_logger.error(f"Failed to calculate canary hash for {file_path}: {e}")
            return ""

    @classmethod
    def set_hidden_attribute(cls, file_path: str):
        """Sets hidden attribute on Windows systems or appropriate permissions on POSIX."""
        try:
            if sys.platform.startswith('win'):
                subprocess.run(['attrib', '+h', file_path], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            else:
                os.chmod(file_path, 0o600)
        except Exception as e:
            error_logger.warning(f"Could not set hidden attribute on canary {file_path}: {e}")

    @classmethod
    def deploy_canaries_in_directory(cls, target_dir: str) -> List[Dict[str, Any]]:
        """Deploys standard decoy canary files in the specified directory."""
        directory = Path(target_dir).resolve()
        directory.mkdir(parents=True, exist_ok=True)

        deployed_records = []

        for filename in CANARY_FILENAMES:
            file_path = str(directory / filename)
            ext = Path(filename).suffix.lower()
            content = CANARY_CONTENT_TEMPLATES.get(ext, b"CanaryGuard Decoy File Data Payload\n")

            # Write file if not existing or zero-sized
            if not os.path.exists(file_path) or os.path.getsize(file_path) == 0:
                try:
                    with open(file_path, 'wb') as f:
                        f.write(content)
                    cls.set_hidden_attribute(file_path)
                    logger.info(f"Deployed canary decoy file: {file_path}")
                except Exception as e:
                    error_logger.error(f"Error writing canary file {file_path}: {e}")
                    continue

            # Compute hash & file stats
            file_hash = cls.calculate_file_hash(file_path)
            file_size = os.path.getsize(file_path)

            # Sync with database
            canary_record = CanaryFile.query.filter_by(file_path=file_path).first()
            if not canary_record:
                canary_record = CanaryFile(
                    filename=filename,
                    file_path=file_path,
                    directory=str(directory),
                    original_hash=file_hash,
                    current_hash=file_hash,
                    file_size_bytes=file_size,
                    is_hidden=True,
                    is_active=True
                )
                db.session.add(canary_record)
            else:
                canary_record.original_hash = file_hash
                canary_record.current_hash = file_hash
                canary_record.file_size_bytes = file_size
                canary_record.is_active = True

            deployed_records.append({
                'filename': filename,
                'file_path': file_path,
                'hash': file_hash
            })

        db.session.commit()
        return deployed_records

    @classmethod
    def verify_canary_integrity(cls, file_path: str) -> Optional[Dict[str, Any]]:
        """
        Checks if a touched file is a known canary and if it has been tampered with or deleted.
        Returns detailed alert dictionary if triggered, else None.
        """
        canary = CanaryFile.query.filter_by(file_path=file_path, is_active=True).first()
        if not canary:
            return None

        # Check if deleted or modified
        if not os.path.exists(file_path):
            canary.trigger_count += 1
            canary.last_triggered_at = datetime.now(timezone.utc)
            canary.is_active = False
            db.session.commit()
            
            logger.warning(f"CANARY DELETED TRIGGERED: {file_path}")
            # Automatically redeploy the missing canary
            cls.redeploy_canary(canary.id)
            return {
                'event': 'CANARY_DELETED',
                'canary': canary.to_dict(),
                'message': f"Canary decoy file deleted: {file_path}"
            }

        new_hash = cls.calculate_file_hash(file_path)
        if new_hash != canary.original_hash:
            canary.current_hash = new_hash
            canary.trigger_count += 1
            canary.last_triggered_at = datetime.now(timezone.utc)
            db.session.commit()

            logger.warning(f"CANARY MODIFIED TRIGGERED: {file_path}")
            return {
                'event': 'CANARY_MODIFIED',
                'canary': canary.to_dict(),
                'message': f"Canary decoy file modified/encrypted: {file_path}"
            }

        return None

    @classmethod
    def redeploy_canary(cls, canary_id: int) -> bool:
        """Redeploys a specific canary file after a trigger/tampering event."""
        canary = CanaryFile.query.get(canary_id)
        if not canary:
            return False

        ext = Path(canary.filename).suffix.lower()
        content = CANARY_CONTENT_TEMPLATES.get(ext, b"CanaryGuard Decoy File Data Payload\n")
        
        try:
            with open(canary.file_path, 'wb') as f:
                f.write(content)
            cls.set_hidden_attribute(canary.file_path)
            new_hash = cls.calculate_file_hash(canary.file_path)

            canary.original_hash = new_hash
            canary.current_hash = new_hash
            canary.is_active = True
            db.session.commit()

            logger.info(f"Redeployed canary file successfully: {canary.file_path}")
            return True
        except Exception as e:
            error_logger.error(f"Failed to redeploy canary {canary.file_path}: {e}")
            return False
