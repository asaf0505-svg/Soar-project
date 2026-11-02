import pytest

from soc_case_manager.models import Incident


def test_close_incident_saves_summary():
    incident = Incident("INC-TDD-001", "Test incident", "High")

    incident.close("Blocked the source and completed analyst review")

    assert incident.status == "Closed"
    assert incident.resolution_summary == (
        "Blocked the source and completed analyst review"
    )


@pytest.mark.parametrize("summary", ["", "   ", None])
def test_close_incident_requires_summary(summary):
    incident = Incident("INC-TDD-002", "Test incident", "Medium")

    with pytest.raises(ValueError, match="resolution_summary"):
        incident.close(summary)