"""Shared limits for uploads and standalone analysis; configure before startup."""

import os


def positive_setting(name, default):
    value = int(os.environ.get(name, default))
    if value < 1:
        raise ValueError(f"{name} must be a positive integer")
    return value


MAX_UPLOAD_MB = positive_setting("IOTGUARD_MAX_UPLOAD_MB", 100)
MAX_UPLOAD_BYTES = MAX_UPLOAD_MB * 1024 * 1024
MAX_ROWS = positive_setting("IOTGUARD_MAX_ANALYSIS_ROWS", 100_000)
UPLOAD_LIMIT_MESSAGE = f"Choose a file no larger than {MAX_UPLOAD_MB} MiB"
