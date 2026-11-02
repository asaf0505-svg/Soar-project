"""Stage 2 extension demo: offline by default, opt-in live API via env."""

import asyncio
import os

from .api_client import IPReputation, AbuseIPDBClient
from .async_processing import (
    SimulatedCheck,
    collect_sequential,
    collect_concurrent,
)
from .config import get_abuseipdb_api_key
from .integrated_reports import (
    high_risk_open_review_report,
)
from .models import NetworkEvent
from .processing import IncidentProcessor
from .reports import RemediationManager
from .services import ReputationService
from .threaded_processing import race_to_claim


class OfflineReputationClient:
    """Synthetic response used without HTTP."""

    def check_ip(self, ip_address):
        return IPReputation(
            ip_address,
            85,
        )


def run_stage2_demo(
    incidents,
    *,
    live=False,
    incident_id=None,
    ip_address=None,
):
    print(
        "\n=== Stage 2 - External Reputation / Remediation ==="
    )

    processor = IncidentProcessor()
    processor.build_index(incidents)

    manager = RemediationManager(processor)

    manager.load_tasks(
        os.path.join(
            "data",
            "remediation_tasks.jsonl",
        )
    )

    if not incidents:
        print("No incidents for stage 2 demo.")
        return

    selected = (
        incident_id
        if incident_id is not None
        else incidents[0].incident_id
    )

    selected_incident = processor.get_incident(
        selected
    )

    if selected_incident is None:
        print(
            f"Incident {selected} was not found; "
            "no business update."
        )
        return

    if live:
        api_key = get_abuseipdb_api_key()

        if not api_key:
            print(
                "LIVE MODE: ABUSEIPDB_API_KEY "
                "missing; no business update."
            )
            return

        if not ip_address:
            print(
                "LIVE MODE: provide --ip with "
                "a public IP; no business update."
            )
            return

        client = AbuseIPDBClient(api_key)
        source = "LIVE AbuseIPDB API"

    else:
        client = OfflineReputationClient()
        ip_address = "8.8.8.8"
        source = "SIMULATED LOCAL DATA (no network)"

    network_event = NetworkEvent(
        event_id="STAGE2-NET-001",
        timestamp="2026-11-02T12:00:00",
        source="Stage 2 Demo",
        suspicious_ip=ip_address,
        port=443,
    )

    selected_incident.add_event(
        network_event
    )

    service = ReputationService(
        client,
        manager,
    )

    print(
        "Network event linked to incident: "
        f"{network_event.event_id} -> "
        f"{selected_incident.incident_id}; "
        f"IP={network_event.suspicious_ip}"
    )

    before_report = high_risk_open_review_report(
        manager,
        service.audit.high_risk_scores,
    )

    print(
        "Combined report before enrichment:",
        before_report,
    )

    decision = service.evaluate_network_event(
        selected_incident.incident_id,
        network_event,
    )

    print(
        f"Source: {source}; "
        f"incident: {selected}; "
        f"decision: {decision.status}; "
        f"score: {decision.score}"
    )

    after_report = high_risk_open_review_report(
        manager,
        service.audit.high_risk_scores,
    )

    print(
        "Combined report after enrichment:",
        after_report,
    )

    print(
        "Remediation tasks by team:",
        manager.generate_open_tasks_report(),
    )

    if live:
        return

    review_plan = manager.plans.get(
        f"RP-{selected}"
    )

    if review_plan is not None:
        review_task = next(
            (
                task
                for task in review_plan.tasks
                if task.task_id
                == f"IP-REVIEW-{selected}"
            ),
            None,
        )

        if review_task is not None:
            review_task.mark_completed()

            completed_report = (
                high_risk_open_review_report(
                    manager,
                    service.audit.high_risk_scores,
                )
            )

            print(
                "Combined report after manual review completion:",
                completed_report,
            )

    checks = [
        SimulatedCheck("INC-001", 85, 0.01),
        SimulatedCheck("INC-002", 40, 0.0),
        SimulatedCheck("INC-003", 65, 0.005),
    ]

    sequential = asyncio.run(
        collect_sequential(checks)
    )

    concurrent = asyncio.run(
        collect_concurrent(checks)
    )

    print(
        "Simulated sequential:",
        sequential,
    )

    print(
        "Simulated concurrent:",
        concurrent,
    )

    results, assignments = race_to_claim(
        selected,
        [
            "Analyst-A",
            "Analyst-B",
        ],
    )

    print(
        "Protected claim confirmations: "
        f"{sum(results)}; "
        f"final assignments: {assignments}"
    )