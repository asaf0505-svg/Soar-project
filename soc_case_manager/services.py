"""Business behavior for external IP reputation checks."""
from dataclasses import dataclass
from typing import Optional

from .api_client import IPReputation, ExternalAPIError, require_public_ip
from .models import Incident, Task
from .reports import RemediationManager


@dataclass(frozen=True)
class ReputationDecision:
    incident_id: str
    status: str
    score: Optional[int] = None
    task_id: Optional[str] = None
    reason: str = ""


class ReputationService:
    """API transport is injected and never constructed inside business logic."""

    THRESHOLD = 80

    def __init__(self, client, remediation_manager: RemediationManager):
        self.client = client
        self.manager = remediation_manager

    def evaluate(self, incident_id: str, ip_address: str) -> ReputationDecision:
        incident = self.manager.processor.get_incident(incident_id)
        if not isinstance(incident, Incident):
            return ReputationDecision(incident_id, "invalid", reason="Incident not found")
        try:
            normalized_ip = require_public_ip(ip_address)
            reputation: IPReputation = self.client.check_ip(normalized_ip)
        except (ExternalAPIError, ValueError) as error:
            return ReputationDecision(incident_id, "unavailable", reason=type(error).__name__)

        if reputation.ip_address != normalized_ip or type(reputation.abuse_confidence_score) is not int or not 0 <= reputation.abuse_confidence_score <= 100:
            return ReputationDecision(incident_id, "unavailable", reason="Invalid reputation")

        score = reputation.abuse_confidence_score
        if score < self.THRESHOLD:
            return ReputationDecision(incident_id, "low-risk", score=score)

        # Review requests do not change the incident's existing status/severity.
        plan_id = f"RP-{incident_id}"
        existing = self.manager.plans.get(plan_id)
        task_id = f"IP-REVIEW-{incident_id}"
        if existing is not None:
            if any(task.task_id == task_id for task in existing.tasks):
                return ReputationDecision(incident_id, "high-risk", score=score, task_id=task_id)

        # Reuse the stage-1 remediation model and report.
        from .models import RemediationPlan
        if existing is None:
            existing = RemediationPlan(plan_id, incident_id)
            self.manager.plans[plan_id] = existing
        existing.add_task(Task(task_id, f"Review external IP reputation for incident {incident_id}", "Security"))
        return ReputationDecision(incident_id, "high-risk", score=score, task_id=task_id)
