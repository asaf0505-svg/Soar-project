"""Verify both Strategy alternatives and both Observer reactions."""
import pytest

from soc_case_manager.models import Incident
from soc_case_manager.processing import IncidentProcessor
from soc_case_manager.reports import RemediationManager
from soc_case_manager.observers import (
    HighRiskPublisher, HighRiskDetected, ReviewTaskObserver, RiskAuditObserver
)
from soc_case_manager.strategies import ThresholdRiskStrategy, StrictRiskStrategy


@pytest.mark.parametrize("score,default,strict", [
    (50, False, False),
    (65, False, True),
    (85, True, True),
])
def test_two_strategy_alternatives(score, default, strict):
    assert ThresholdRiskStrategy().requires_review(score) is default
    assert StrictRiskStrategy().requires_review(score) is strict


def test_observer_event_updates_both_remediation_and_audit():
    processor = IncidentProcessor()
    processor.build_index([Incident("INC-X", "test", "High")])
    manager = RemediationManager(processor)
    audit = RiskAuditObserver()
    bus = HighRiskPublisher([ReviewTaskObserver(manager), audit])
    event = HighRiskDetected("INC-X", "8.8.8.8", 85)
    bus.publish(event)
    bus.publish(event)
    assert audit.events == [event, event]
    assert audit.high_risk_scores == {"INC-X": 85}
    assert manager.generate_open_tasks_report() == {"Security": 1}
