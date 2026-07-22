#!/usr/bin/env python3
"""
BARBAROSSA: Web Application Security Inspection and Authorized Testing Toolkit
Deterministic | Non-destructive | Authorized-only

Configuration: Customize these settings before running.
"""

import sys
import asyncio
from pathlib import Path

# ============================================================================
# CONFIGURATION SECTION
# ============================================================================

# Target URL for active probes
TARGET_URL = "http://127.0.0.1:8000"

# Source directory for static inspection
SOURCE_DIRECTORY = "./examples/vulnerable_demo_app"

# Authorized targets (localhost/private IPs are allowed by default)
AUTHORIZED_TARGETS = [
    "localhost",
    "127.0.0.1",
]

# Enable/disable major stages
RUN_STATIC_INSPECTION = True
RUN_ACTIVE_PROBES = True

# Rate limiting and safety
REQUESTS_PER_SECOND = 2
MAX_REQUESTS = 150
REQUEST_TIMEOUT_SECONDS = 10

# Output formats: console, json, html, sarif
OUTPUT_FORMATS = ["console", "json", "html", "sarif"]

# Learning mode: explain each test and remediation
LEARNING_MODE = False

# Verbosity
VERBOSE = False

# ============================================================================
# END CONFIGURATION SECTION
# ============================================================================


async def main() -> int:
    """Main entry point."""
    from barbarossa.cli import app
    
    try:
        app()
        return 0
    except KeyboardInterrupt:
        print("\n[*] Scan interrupted by user.", file=sys.stderr)
        return 130
    except Exception as e:
        print(f"[!] Fatal error: {e}", file=sys.stderr)
        if VERBOSE:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
