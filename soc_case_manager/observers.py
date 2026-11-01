"""Observer pattern: one high-risk event notifies two independent handlers."""
from dataclasses import dataclass
from typing import List

from .models import RemediationPlan, Task
from .reports import RemediationManager


@dataclass(frozen=True)
class HighRiskDetected:
    incident_id: str
    ip_address: str
    score: int


class HighRiskPublisher:
    def __init__(self, observers=()):
        self._observers = list(observers)

    def subscribe(self, observer):
        self._observers.append(observer)

    def publish(self, event: HighRiskDetected):
        for observer in self._observers:
            observer.on_high_risk(event)


class ReviewTaskObserver:
    """Connects the central incident process to existing remediation plans."""

    def __init__(self, manager: RemediationManager):
        self.manager = manager

    def on_high_risk(self, event: HighRiskDetected):
        if self.manager.processor.get_incident(event.incident_id) is None:
            raise ValueError("Cannot create remediation for an unknown incident")
        plan_id = f"RP-{event.incident_id}"
        task_id = f"IP-REVIEW-{event.incident_id}"
        plan = self.manager.plans.get(plan_id)
        if plan is None:
            plan = RemediationPlan(plan_id, event.incident_id)
            self.manager.plans[plan_id] = plan
        for task in plan.tasks:
            if task.task_id == task_id:
                task.is_completed = False
                return
        plan.add_task(Task(
            task_id,
            f"Review external IP reputation for incident {event.incident_id}",
            "Security",
        ))


class RiskAuditObserver:
    """Second independent reaction: keep a non-secret audit of high-risk decisions."""

    def __init__(self):
        self.events: List[HighRiskDetected] = []
        self.high_risk_scores = {}

    def on_high_risk(self, event: HighRiskDetected):
        self.events.append(event)
        self.high_risk_scores[event.incident_id] = event.score
