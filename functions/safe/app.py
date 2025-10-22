"""Secure Lambda function showcasing best practices."""
from __future__ import annotations

import json
import os
from typing import Any, Dict


def handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Return payload demonstrating safe access patterns."""
    # Example: secrets should be loaded from environment variables injected by Secrets Manager.
    secret_alias = os.environ.get("SECRET_ALIAS", "arn:aws:secretsmanager:region:acct:secret:example")
    return {
        "statusCode": 200,
        "body": json.dumps(
            {
                "message": "Secure handler executed",
                "secret_alias": secret_alias,
                "event": event,
            }
        ),
    }
