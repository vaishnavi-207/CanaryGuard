# CanaryGuard Testing Guide

## Running Automated Tests

Run the complete test suite using Pytest:
```bash
python -m pytest tests/ -v
```

## Test Coverage Overview

- `test_entropy.py`: Validates Shannon entropy calculation accuracy on empty files, plain text, and encrypted binary data.
- `test_canary.py`: Tests decoy file generation, SHA-256 hashing, and tampering detection.
- `test_api.py`: Validates HTTP status codes and JSON structure across REST endpoints.
- `test_integration.py`: End-to-end integration test simulating ransomware behavior, confidence scoring, and incident recording.
