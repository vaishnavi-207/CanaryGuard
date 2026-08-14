import math
import os
from pathlib import Path
from typing import Dict, Any, Tuple
from app.logging.logger import get_entropy_logger, get_error_logger

logger = get_entropy_logger()
error_logger = get_error_logger()

class ShannonEntropyEngine:
    """Calculates Shannon Entropy on files to detect encryption signatures."""

    @staticmethod
    def calculate_entropy(file_path: str) -> float:
        """
        Calculates Shannon Entropy (0.0 to 8.0 bits/byte) for a given file.
        High entropy (> 7.2) strongly indicates encryption or compressed payload.
        """
        path = Path(file_path)
        if not path.exists() or not path.is_file():
            logger.warning(f"Entropy calculation skipped: File does not exist ({file_path})")
            return 0.0

        file_size = path.stat().st_size
        if file_size == 0:
            return 0.0

        byte_counts = [0] * 256
        total_bytes = 0

        try:
            with open(path, 'rb') as f:
                while chunk := f.read(65536): # 64KB chunking for efficiency
                    for byte in chunk:
                        byte_counts[byte] += 1
                    total_bytes += len(chunk)

            if total_bytes == 0:
                return 0.0

            entropy = 0.0
            for count in byte_counts:
                if count > 0:
                    probability = count / total_bytes
                    entropy -= probability * math.log2(probability)

            return round(entropy, 4)

        except PermissionError:
            error_logger.error(f"Permission denied while reading for entropy calculation: {file_path}")
            return 0.0
        except Exception as e:
            error_logger.exception(f"Unexpected error calculating entropy for {file_path}: {e}")
            return 0.0

    @classmethod
    def evaluate_threat(cls, file_path: str, threshold: float = 7.2) -> Tuple[float, bool, Dict[str, Any]]:
        """
        Evaluates a file's entropy against the threshold.
        Returns (entropy_value, is_threat, metadata_dict).
        """
        entropy = cls.calculate_entropy(file_path)
        is_threat = entropy >= threshold
        
        file_size = 0
        file_ext = ""
        if os.path.exists(file_path):
            file_size = os.path.getsize(file_path)
            file_ext = os.path.splitext(file_path)[1]

        metadata = {
            'file_path': file_path,
            'entropy': entropy,
            'threshold': threshold,
            'file_size': file_size,
            'extension': file_ext,
            'is_high_entropy': is_threat
        }

        if is_threat:
            logger.warning(f"HIGH ENTROPY DETECTED: {file_path} (Entropy: {entropy} / Threshold: {threshold})")
        else:
            logger.debug(f"Normal entropy calculated: {file_path} (Entropy: {entropy})")

        return entropy, is_threat, metadata
