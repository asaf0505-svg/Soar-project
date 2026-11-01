"""Four extra tests required for four-person integrated extension."""
from unittest.mock import Mock

from soc_case_manager.api_client import IPReputation, ExternalConnectionFailure
from soc_case_manager.integrated_reports import high_risk_open_review_report
from soc_case_manager.models import Incident
from soc_case_manager.processing import IncidentProcessor
from soc_case_manager.reports import RemediationManager
from soc_case_manager.services import ReputationService


def setup_case():
    incident = Incident("INC-1", "Potential intrusion", "High")
    processor = IncidentProcessor()
    processor.build_index([incident])
    manager = RemediationManager(processor)
    return incident, manager


def test_integrated_success_updates_remediation_and_report():
    incident, manager = setup_case()
    client = Mock()
    client.check_ip.return_value = IPReputation("8.8.8.8", 90)
    service = ReputationService(client, manager)
    assert service.evaluate("INC-1", "8.8.8.8").status == "high-risk"
    assert len(manager.plans["RP-INC-1"].tasks) == 1
    assert high_risk_open_review_report(manager, service.audit.high_risk_scores) == {
        "high_risk_with_open_review": 1
    }
    assert incident.severity == "High"


def test_integrated_api_failure_leaves_system_unchanged():
    incident, manager = setup_case()
    client = Mock()
    client.check_ip.side_effect = ExternalConnectionFailure("outage")
    service = ReputationService(client, manager)
    assert service.evaluate("INC-1", "8.8.8.8").status == "unavailable"
    assert manager.plans == {}
    assert service.audit.high_risk_scores == {}
    assert incident.status == "Open"


def test_integrated_invalid_relation_never_creates_orphan():
    _, manager = setup_case()
    client = Mock()
    service = ReputationService(client, manager)
    assert service.evaluate("INC-missing", "8.8.8.8").status == "invalid"
    client.check_ip.assert_not_called()
    assert manager.plans == {}


def test_integrated_metric_falls_after_task_completion():
    _, manager = setup_case()
    client = Mock()
    client.check_ip.return_value = IPReputation("8.8.8.8", 95)
    service = ReputationService(client, manager)
    service.evaluate("INC-1", "8.8.8.8")
    assert high_risk_open_review_report(manager, service.audit.high_risk_scores)["high_risk_with_open_review"] == 1
    manager.plans["RP-INC-1"].tasks[0].mark_completed()
    assert high_risk_open_review_report(manager, service.audit.high_risk_scores)["high_risk_with_open_review"] == 0
