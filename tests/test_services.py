"""Business integration tests with a stubbed external adapter."""
from unittest.mock import Mock
import pytest

from soc_case_manager.api_client import IPReputation, ExternalConnectionFailure
from soc_case_manager.models import Incident
from soc_case_manager.processing import IncidentProcessor
from soc_case_manager.reports import RemediationManager
from soc_case_manager.services import ReputationService


@pytest.fixture
def setup_service():
    processor = IncidentProcessor()
    incident = Incident("INC-X", "Test incident", "Medium")
    processor.build_index([incident])
    manager = RemediationManager(processor)
    return incident, manager


def test_high_score_creates_one_review_task(setup_service):
    incident, manager = setup_service
    client = Mock()
    client.check_ip.return_value = IPReputation("8.8.8.8", 85)
    service = ReputationService(client, manager)
    assert service.evaluate(incident.incident_id, "8.8.8.8").status == "high-risk"
    assert manager.generate_open_tasks_report() == {"Security": 1}
    assert service.evaluate(incident.incident_id, "8.8.8.8").task_id == "IP-REVIEW-INC-X"
    assert manager.generate_open_tasks_report() == {"Security": 1}
    assert incident.severity == "Medium"


@pytest.mark.parametrize("score", [0, 40, 79])
def test_low_score_does_not_create_task(setup_service, score):
    incident, manager = setup_service
    client = Mock()
    client.check_ip.return_value = IPReputation("8.8.8.8", score)
    assert ReputationService(client, manager).evaluate(incident.incident_id, "8.8.8.8").status == "low-risk"
    assert manager.plans == {}


def test_api_failure_does_not_mutate_business_state(setup_service):
    incident, manager = setup_service
    client = Mock()
    client.check_ip.side_effect = ExternalConnectionFailure("offline")
    decision = ReputationService(client, manager).evaluate(incident.incident_id, "8.8.8.8")
    assert decision.status == "unavailable"
    assert incident.status == "Open"
    assert incident.severity == "Medium"
    assert manager.plans == {}


def test_nonexistent_incident_is_not_sent_to_api(setup_service):
    _, manager = setup_service
    client = Mock()
    decision = ReputationService(client, manager).evaluate("missing", "8.8.8.8")
    assert decision.status == "invalid"
    client.check_ip.assert_not_called()


def test_completed_review_reopens_on_new_high_risk_result(setup_service):
    incident, manager = setup_service
    client = Mock()
    client.check_ip.return_value = IPReputation("8.8.8.8", 90)
    service = ReputationService(client, manager)
    service.evaluate(incident.incident_id, "8.8.8.8")
    task = manager.plans["RP-INC-X"].tasks[0]
    task.mark_completed()
    assert task.is_completed
    service.evaluate(incident.incident_id, "8.8.8.8")
    assert len(manager.plans["RP-INC-X"].tasks) == 1
    assert not task.is_completed
