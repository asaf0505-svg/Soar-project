"""Stage 2 extension demo: offline by default, opt-in live API via env."""
import asyncio
import os

from .api_client import IPReputation, AbuseIPDBClient, ExternalAPIError
from .async_processing import SimulatedCheck, collect_sequential, collect_concurrent
from .config import get_abuseipdb_api_key
from .integrated_reports import high_risk_open_review_report
from .processing import IncidentProcessor
from .reports import RemediationManager
from .services import ReputationService
from .threaded_processing import race_to_claim


class OfflineReputationClient:
    """Clearly labeled synthetic response; never performs HTTP."""

    def check_ip(self, ip_address):
        return IPReputation(ip_address, 85)


def run_stage2_demo(incidents, *, live=False, incident_id=None, ip_address=None):
    print("\\n=== Stage 2 - External Reputation / Remediation ===")
    processor = IncidentProcessor()
    processor.build_index(incidents)
    manager = RemediationManager(processor)
    manager.load_tasks(os.path.join("data", "remediation_tasks.jsonl"))

    if not incidents:
        print("No incidents for stage 2 demo.")
        return

    selected = incident_id if incident_id is not None else incidents[0].incident_id
    if live:
        api_key = get_abuseipdb_api_key()
        if not api_key:
            print("LIVE MODE: ABUSEIPDB_API_KEY missing; no business update.")
            return
        if not ip_address:
            print("LIVE MODE: provide --ip with a public IP; no business update.")
            return
        client = AbuseIPDBClient(api_key)
        source = "LIVE AbuseIPDB API"
    else:
        client = OfflineReputationClient()
        ip_address = "8.8.8.8"  # Example public address; never sent in offline mode.
        source = "SIMULATED LOCAL DATA (no network)"

    service = ReputationService(client, manager)
    decision = service.evaluate(selected, ip_address)
    print(f"Source: {source}; incident: {selected}; decision: {decision.status}; score: {decision.score}")
    print("Combined report:", high_risk_open_review_report(manager, service.audit.high_risk_scores))
    print("Remediation tasks by team:", manager.generate_open_tasks_report())
    if live:
        return

    checks = [
        SimulatedCheck("INC-001", 85, 0.01),
        SimulatedCheck("INC-002", 40, 0.0),
        SimulatedCheck("INC-003", 65, 0.005),
    ]
    sequential = asyncio.run(collect_sequential(checks))
    concurrent = asyncio.run(collect_concurrent(checks))
    print("Simulated sequential:", sequential)
    print("Simulated concurrent:", concurrent)
    results, assignments = race_to_claim(selected, ["Analyst-A", "Analyst-B"])
    print(f"Protected claim confirmations: {sum(results)}; final assignments: {assignments}")
