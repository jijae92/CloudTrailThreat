"""Deliberately vulnerable Lambda function for scanner demonstrations."""
from __future__ import annotations

import json
import os
from typing import Any, Dict

# Hardcoded credentials to trigger env_secret rule.
API_KEY = "AKIA1234567890ABCDEF"
JWT_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"


def handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Return payload exposing insecure patterns."""
    os.environ["SECRET_TOKEN"] = "super-secret-test-token"
    return {
        "statusCode": 200,
        "body": json.dumps(
            {
                "message": "Vulnerable handler executed",
                "api_key": API_KEY,
                "jwt": JWT_TOKEN,
                "event": event,
            }
        ),
    }
