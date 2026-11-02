"""Business behavior for external IP reputation checks."""

from dataclasses import dataclass
from typing import Optional

from .api_client import (
    IPReputation,
    ExternalAPIError,
    require_public_ip,
)
from .models import Incident, NetworkEvent
from .reports import RemediationManager
from .strategies import ThresholdRiskStrategy
from .observers import (
    HighRiskPublisher,
    HighRiskDetected,
    ReviewTaskObserver,
    RiskAuditObserver,
)


@dataclass(frozen=True)
class ReputationDecision:
    incident_id: str
    status: str
    score: Optional[int] = None
    task_id: Optional[str] = None
    reason: str = ""
    reputation: Optional[IPReputation] = None


class ReputationService:
    """Business logic for external IP reputation checks."""

    THRESHOLD = 80

    def __init__(
        self,
        client,
        remediation_manager: RemediationManager,
        strategy=None,
        publisher=None,
        audit=None,
    ):
        self.client = client
        self.manager = remediation_manager

        self.strategy = (
            strategy
            if strategy is not None
            else ThresholdRiskStrategy()
        )

        self.audit = (
            audit
            if audit is not None
            else RiskAuditObserver()
        )

        self.publisher = (
            publisher
            if publisher is not None
            else HighRiskPublisher(
                [
                    ReviewTaskObserver(remediation_manager),
                    self.audit,
                ]
            )
        )

    def evaluate(
        self,
        incident_id: str,
        ip_address: str
    ) -> ReputationDecision:
        """
        Evaluate an IP for an existing incident.
        Kept for existing tests and direct service usage.
        """

        incident = self.manager.processor.get_incident(
            incident_id
        )

        if not isinstance(incident, Incident):
            return ReputationDecision(
                incident_id,
                "invalid",
                reason="Incident not found",
            )

        try:
            normalized_ip = require_public_ip(
                ip_address
            )

            reputation: IPReputation = (
                self.client.check_ip(normalized_ip)
            )

        except (ExternalAPIError, ValueError) as error:
            return ReputationDecision(
                incident_id,
                "unavailable",
                reason=type(error).__name__,
            )

        if (
            reputation.ip_address != normalized_ip
            or type(reputation.abuse_confidence_score) is not int
            or not 0 <= reputation.abuse_confidence_score <= 100
        ):
            return ReputationDecision(
                incident_id,
                "unavailable",
                reason="Invalid reputation",
            )

        score = reputation.abuse_confidence_score

        if not self.strategy.requires_review(score):
            return ReputationDecision(
                incident_id,
                "low-risk",
                score=score,
                reputation=reputation,
            )

        self.publisher.publish(
            HighRiskDetected(
                incident_id,
                normalized_ip,
                score,
            )
        )

        return ReputationDecision(
            incident_id,
            "high-risk",
            score=score,
            task_id=f"IP-REVIEW-{incident_id}",
            reputation=reputation,
        )

    def evaluate_network_event(
        self,
        incident_id: str,
        event: NetworkEvent
    ) -> ReputationDecision:
        """
        Evaluate the suspicious IP from a NetworkEvent
        that belongs to the requested Incident.
        """

        incident = self.manager.processor.get_incident(
            incident_id
        )

        if not isinstance(incident, Incident):
            return ReputationDecision(
                incident_id,
                "invalid",
                reason="Incident not found",
            )

        if not isinstance(event, NetworkEvent):
            return ReputationDecision(
                incident_id,
                "invalid",
                reason="NetworkEvent required",
            )

        if event not in incident.events:
            return ReputationDecision(
                incident_id,
                "invalid",
                reason="Network event is not linked to incident",
            )

        return self.evaluate(
            incident_id,
            event.suspicious_ip,
        )
