"""AbuseIPDB HTTP adapter. Business decisions belong in services.py."""
from dataclasses import dataclass
import ipaddress
import logging
import time
from typing import Optional

import requests

LOGGER = logging.getLogger(__name__)
CHECK_URL = "https://api.abuseipdb.com/api/v2/check"


class ExternalAPIError(RuntimeError):
    """Base type for failures outside our own domain model."""


class ExternalConnectionFailure(ExternalAPIError):
    """Timeout or connection error after the retry budget is exhausted."""


class ExternalHTTPFailure(ExternalAPIError):
    """An unsuccessful HTTP response; not automatically retried."""


class ExternalJSONFailure(ExternalAPIError):
    """The server returned an unreadable JSON document."""


class ExternalDataFailure(ExternalAPIError):
    """The parsed JSON does not match the required schema."""


def require_public_ip(value: str) -> str:
    """Reject malformed, private, loopback and documentation-only addresses."""
    if not isinstance(value, str):
        raise ValueError("IP must be text")
    try:
        address = ipaddress.ip_address(value)
    except ValueError as error:
        raise ValueError("Invalid IP address") from error
    if not address.is_global:
        raise ValueError("A globally routable public IP address is required")
    return str(address)


def _optional_text(data: dict, field: str) -> str:
    value = data.get(field)
    if value is None:
        return ""
    if not isinstance(value, str):
        raise ExternalDataFailure(f"Invalid {field}")
    return value.strip()


def _optional_nullable_text(data: dict, field: str) -> Optional[str]:
    value = data.get(field)
    if value is None:
        return None
    if not isinstance(value, str):
        raise ExternalDataFailure(f"Invalid {field}")
    return value.strip() or None


def _optional_non_negative_int(data: dict, field: str) -> int:
    value = data.get(field, 0)
    if type(value) is not int or value < 0:
        raise ExternalDataFailure(f"Invalid {field}")
    return value


def _optional_bool(data: dict, field: str, *, default=None):
    value = data.get(field, default)
    if value is None:
        return None
    if type(value) is not bool:
        raise ExternalDataFailure(f"Invalid {field}")
    return value


@dataclass(frozen=True)
class IPReputation:
    ip_address: str
    abuse_confidence_score: int
    is_whitelisted: Optional[bool] = None
    total_reports: int = 0
    num_distinct_users: int = 0
    isp: str = ""
    usage_type: str = ""
    domain: str = ""
    country_code: str = ""
    is_tor: Optional[bool] = None
    last_reported_at: Optional[str] = None

    @classmethod
    def from_payload(cls, payload: object, requested_ip: str) -> "IPReputation":
        if not isinstance(payload, dict) or not isinstance(payload.get("data"), dict):
            raise ExternalDataFailure("Missing or invalid data object")

        data = payload["data"]
        returned_ip = data.get("ipAddress")

        try:
            normalized_ip = require_public_ip(returned_ip)
        except ValueError as error:
            raise ExternalDataFailure("Missing or invalid returned IP") from error

        if normalized_ip != requested_ip:
            raise ExternalDataFailure("Returned IP does not match requested IP")

        score = data.get("abuseConfidenceScore")
        if type(score) is not int or not (0 <= score <= 100):
            raise ExternalDataFailure("Missing or invalid abuse confidence score")

        return cls(
            ip_address=normalized_ip,
            abuse_confidence_score=score,
            is_whitelisted=_optional_bool(data, "isWhitelisted"),
            total_reports=_optional_non_negative_int(data, "totalReports"),
            num_distinct_users=_optional_non_negative_int(data, "numDistinctUsers"),
            isp=_optional_text(data, "isp"),
            usage_type=_optional_text(data, "usageType"),
            domain=_optional_text(data, "domain"),
            country_code=_optional_text(data, "countryCode"),
            is_tor=_optional_bool(data, "isTor"),
            last_reported_at=_optional_nullable_text(data, "lastReportedAt"),
        )


class AbuseIPDBClient:
    """Inject session and sleep to make failure tests deterministic and offline."""

    def __init__(
        self,
        api_key: str,
        *,
        session=None,
        timeout: float = 5.0,
        max_attempts: int = 3,
        retry_delay: float = 0.2,
        sleep=time.sleep,
    ):
        if not isinstance(api_key, str) or not api_key.strip():
            raise ValueError("ABUSEIPDB_API_KEY must be set for live checks")
        if timeout <= 0 or max_attempts not in (1, 2, 3) or retry_delay < 0:
            raise ValueError("Invalid timeout/retry settings")
        self._api_key = api_key.strip()
        self._session = session if session is not None else requests
        self._timeout = timeout
        self._max_attempts = max_attempts
        self._retry_delay = retry_delay
        self._sleep = sleep

    def check_ip(self, ip_address: str) -> IPReputation:
        ip_address = require_public_ip(ip_address)

        for attempt in range(1, self._max_attempts + 1):
            try:
                response = self._session.get(
                    CHECK_URL,
                    params={"ipAddress": ip_address, "maxAgeInDays": 90},
                    headers={"Accept": "application/json", "Key": self._api_key},
                    timeout=self._timeout,
                )
            except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as error:
                LOGGER.warning(
                    "Reputation API transport failure on attempt %s/%s",
                    attempt,
                    self._max_attempts,
                )
                if attempt == self._max_attempts:
                    raise ExternalConnectionFailure(
                        "Reputation service unreachable after retry budget"
                    ) from error
                self._sleep(self._retry_delay)
                continue

            try:
                response.raise_for_status()
            except requests.exceptions.HTTPError as error:
                LOGGER.warning(
                    "Reputation API HTTP failure: status=%s",
                    getattr(response, "status_code", "unknown"),
                )
                raise ExternalHTTPFailure(
                    "Reputation service returned an HTTP error"
                ) from error

            try:
                payload = response.json()
            except ValueError as error:
                LOGGER.warning("Reputation API returned non-JSON content")
                raise ExternalJSONFailure(
                    "Reputation response is not valid JSON"
                ) from error

            return IPReputation.from_payload(payload, ip_address)

        raise AssertionError("Unreachable retry state")
