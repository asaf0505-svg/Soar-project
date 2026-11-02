from unittest.mock import Mock

from soc_case_manager.api_client import IPReputation
from soc_case_manager.models import (
    Incident,
    NetworkEvent,
)
from soc_case_manager.processing import IncidentProcessor
from soc_case_manager.reports import RemediationManager
from soc_case_manager.services import ReputationService


def build_service():
    incident = Incident(
        "INC-NET-001",
        "Suspicious network activity",
        "High",
    )

    processor = IncidentProcessor()
    processor.build_index([incident])

    manager = RemediationManager(
        processor
    )

    client = Mock()
    client.check_ip.return_value = IPReputation(
        "8.8.8.8",
        90,
    )

    service = ReputationService(
        client,
        manager,
    )

    return incident, manager, client, service


def test_linked_network_event_uses_its_ip():
    incident, manager, client, service = build_service()

    event = NetworkEvent(
        "NET-001",
        "2026-11-02T12:00:00",
        "Firewall",
        "8.8.8.8",
        443,
    )

    incident.add_event(event)

    decision = service.evaluate_network_event(
        incident.incident_id,
        event,
    )

    assert decision.status == "high-risk"

    client.check_ip.assert_called_once_with(
        "8.8.8.8"
    )

    assert (
        manager.generate_open_tasks_report()
        == {"Security": 1}
    )


def test_unlinked_network_event_is_rejected():
    incident, manager, client, service = build_service()

    event = NetworkEvent(
        "NET-002",
        "2026-11-02T12:00:00",
        "Firewall",
        "8.8.8.8",
        443,
    )

    decision = service.evaluate_network_event(
        incident.incident_id,
        event,
    )

    assert decision.status == "invalid"

    assert (
        decision.reason
        == "Network event is not linked to incident"
    )

    client.check_ip.assert_not_called()
    assert manager.plans == {}