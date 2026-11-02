import pytest

from soc_case_manager.models import Incident


def test_incident_can_be_assigned_to_analyst():
    incident = Incident(
        "INC-ASSIGN-001",
        "Suspicious activity",
        "High"
    )

    incident.assign_to("Dana")

    assert incident.assigned_analyst == "Dana"


def test_incident_can_be_transferred_between_analysts():
    incident = Incident(
        "INC-ASSIGN-002",
        "Potential compromise",
        "Critical"
    )

    incident.assign_to("Dana")
    incident.transfer_to("Noam")

    assert incident.assigned_analyst == "Noam"


def test_unassigned_incident_cannot_be_transferred():
    incident = Incident(
        "INC-ASSIGN-003",
        "Investigation",
        "Medium"
    )

    with pytest.raises(
        ValueError,
        match="assigned before transfer"
    ):
        incident.transfer_to("Noam")


def test_incident_cannot_be_assigned_twice():
    incident = Incident(
        "INC-ASSIGN-004",
        "Investigation",
        "Low"
    )

    incident.assign_to("Dana")

    with pytest.raises(
        ValueError,
        match="already assigned"
    ):
        incident.assign_to("Noam")