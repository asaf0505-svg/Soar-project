"""Non-secret settings for the optional live API integration."""
import os


def get_abuseipdb_api_key() -> str:
    """The key is never embedded in source code or demo fixtures."""
    return os.environ.get("ABUSEIPDB_API_KEY", "").strip()
