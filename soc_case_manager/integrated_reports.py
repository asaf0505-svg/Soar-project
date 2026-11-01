"""New combined metric; does not change the existing Stage 1 reports."""
from .reports import RemediationManager


def high_risk_open_review_report(manager: RemediationManager, risk_scores, threshold=80):
    """Count high-risk incidents that still have an open manual review task."""
    count = 0
    for incident_id, score in risk_scores.items():
        if type(score) is not int or score < threshold:
            continue
        if manager.processor.get_incident(incident_id) is None:
            continue
        plan = manager.plans.get(f"RP-{incident_id}")
        if plan and any(
            task.task_id == f"IP-REVIEW-{incident_id}" and not task.is_completed
            for task in plan.tasks
        ):
            count += 1
    return {"high_risk_with_open_review": count}
