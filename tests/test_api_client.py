"""Offline API contract tests with fake HTTP responses (no live network)."""
from unittest.mock import Mock
import pytest
import requests

from soc_case_manager.api_client import (
    AbuseIPDBClient, ExternalConnectionFailure, ExternalHTTPFailure,
    ExternalJSONFailure, ExternalDataFailure, IPReputation,
)


IP = "8.8.8.8"


def response_for(score=85):
    response = Mock()
    response.status_code = 200
    response.raise_for_status.return_value = None
    response.json.return_value = {"data": {"ipAddress": IP, "abuseConfidenceScore": score}}
    return response


@pytest.fixture
def fake_session():
    return Mock()


@pytest.mark.parametrize("score", [0, 80, 100])
def test_valid_score_cases(fake_session, score):
    fake_session.get.return_value = response_for(score)
    client = AbuseIPDBClient("fake-test-key", session=fake_session, sleep=lambda _: None)
    assert client.check_ip(IP) == IPReputation(IP, score)
    assert fake_session.get.call_args.kwargs["timeout"] > 0
    assert fake_session.get.call_args.kwargs["params"]["ipAddress"] == IP


def test_timeout_then_success(fake_session):
    fake_session.get.side_effect = [requests.exceptions.Timeout(), response_for(85)]
    sleep = Mock()
    result = AbuseIPDBClient("fake", session=fake_session, sleep=sleep).check_ip(IP)
    assert result.abuse_confidence_score == 85
    assert fake_session.get.call_count == 2
    sleep.assert_called_once()


def test_connection_errors_stop_after_three_attempts(fake_session):
    fake_session.get.side_effect = requests.exceptions.ConnectionError()
    client = AbuseIPDBClient("fake", session=fake_session, sleep=lambda _: None)
    with pytest.raises(ExternalConnectionFailure):
        client.check_ip(IP)
    assert fake_session.get.call_count == 3


def test_http_error_is_not_retried(fake_session):
    response = response_for()
    response.status_code = 401
    response.raise_for_status.side_effect = requests.exceptions.HTTPError()
    fake_session.get.return_value = response
    with pytest.raises(ExternalHTTPFailure):
        AbuseIPDBClient("fake", session=fake_session, sleep=lambda _: None).check_ip(IP)
    assert fake_session.get.call_count == 1


def test_invalid_json_is_not_retried(fake_session):
    fake_session.get.return_value = response_for()
    fake_session.get.return_value.json.side_effect = ValueError("bad JSON")
    with pytest.raises(ExternalJSONFailure):
        AbuseIPDBClient("fake", session=fake_session).check_ip(IP)
    assert fake_session.get.call_count == 1


def test_required_field_is_checked(fake_session):
    response = response_for()
    response.json.return_value = {"data": {"ipAddress": IP}}
    fake_session.get.return_value = response
    with pytest.raises(ExternalDataFailure):
        AbuseIPDBClient("fake", session=fake_session).check_ip(IP)
    assert fake_session.get.call_count == 1


def test_private_ip_is_never_sent(fake_session):
    with pytest.raises(ValueError):
        AbuseIPDBClient("fake", session=fake_session).check_ip("192.168.1.5")
    fake_session.get.assert_not_called()
