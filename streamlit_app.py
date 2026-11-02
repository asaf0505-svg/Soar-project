from datetime import datetime
from html import escape
from pathlib import Path
import os

import streamlit as st

from soc_case_manager.api_client import (
    AbuseIPDBClient,
    IPReputation,
    require_public_ip,
)
from soc_case_manager.models import (
    InvestigationAction,
    NetworkEvent,
    EndpointEvent,
    RemediationPlan,
    Task,
)
from soc_case_manager.observers import RiskAuditObserver
from soc_case_manager.processing import IncidentProcessor
from soc_case_manager.repository import load_incidents
from soc_case_manager.reports import RemediationManager
from soc_case_manager.services import ReputationService


# =========================================================
# CONFIG
# =========================================================

st.set_page_config(
    page_title="SOC Case Manager",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

ROOT_DIR = Path(__file__).resolve().parent
DATA_DIR = ROOT_DIR / "data"

UI_STATE_VERSION = 5

CASE_STATES = [
    "New",
    "In Progress",
    "On Hold",
    "Resolved",
    "Closed",
]

CASE_GROUPS = [
    "SOC Tier 1",
    "SOC Tier 2",
    "Incident Response",
    "Threat Hunting",
]

CASE_CATEGORIES = [
    "Identity & Access",
    "Endpoint / Malware",
    "Network Security",
    "Email Security",
    "Application Security",
    "Data Security",
    "Other",
]

SEVERITY_ICON = {
    "Critical": "🔴",
    "High": "🟠",
    "Medium": "🟡",
    "Low": "🟢",
}

SLA_TARGET = {
    "Critical": "15 min",
    "High": "1 hour",
    "Medium": "4 hours",
    "Low": "24 hours",
}

RUNBOOK_TEMPLATE = [
    "Validate alert context and scope",
    "Review linked events and observables",
    "Enrich suspicious indicators",
    "Document analyst findings",
    "Complete remediation / containment",
    "Document resolution and close case",
]


# =========================================================
# STYLE
# =========================================================

st.html(
    """
    <style>
        :root {
            --bg: #090e14;
            --panel: #0f1620;
            --panel2: #121b27;
            --border: #223043;
            --muted: #8291a5;
            --text: #edf4fb;
            --blue: #4cb8ff;
            --green: #46d39a;
            --yellow: #f4cf59;
            --orange: #ff9f43;
            --red: #ff5e6d;
            --purple: #a987ff;
        }

        .stApp {
            background:
                radial-gradient(
                    circle at 82% 3%,
                    rgba(76,184,255,.055),
                    transparent 24%
                ),
                var(--bg);
        }

        header[data-testid="stHeader"] {
            background: rgba(9,14,20,.96);
            border-bottom: 1px solid rgba(34,48,67,.45);
        }

        .block-container {
            padding-top: 5rem !important;
            padding-bottom: 2rem !important;
            max-width: 1900px !important;
        }

        #MainMenu {
            visibility: hidden;
        }

        footer {
            visibility: hidden;
        }

        div[data-testid="stVerticalBlockBorderWrapper"] {
            background: rgba(15,22,32,.92);
            border: 1px solid var(--border) !important;
            border-radius: 12px;
        }

        div[data-testid="stMetric"] {
            background: #101822;
            border: 1px solid var(--border);
            border-radius: 9px;
            padding: 10px 12px;
            min-height: 78px;
        }

        div[data-testid="stMetricLabel"] {
            color: var(--muted);
            font-size: 10px;
            text-transform: uppercase;
            letter-spacing: .06em;
        }

        div[data-testid="stMetricValue"] {
            color: var(--text);
            font-size: 23px;
            font-weight: 700;
        }

        div[data-baseweb="input"] > div,
        div[data-baseweb="select"] > div,
        div[data-baseweb="textarea"] > div {
            background: #111925;
            border-color: #2a394d;
        }

        div[data-testid="stDataFrame"] {
            border: 1px solid var(--border);
            border-radius: 9px;
            overflow: hidden;
        }

        div.stButton > button,
        div[data-testid="stPopover"] > button {
            border-color: #2a394d;
            background: #111925;
            color: #e8eef6;
        }

        div.stButton > button:hover,
        div[data-testid="stPopover"] > button:hover {
            border-color: #3c9fd8;
            color: #71caff;
        }

        .soc-brand {
            font-size: 28px;
            font-weight: 760;
            color: var(--text);
            line-height: 1.1;
        }

        .soc-subtitle {
            color: #718198;
            font-size: 11px;
            letter-spacing: .12em;
            text-transform: uppercase;
            margin-top: 4px;
        }

        .soc-kicker {
            color: #65778f;
            font-size: 10px;
            font-weight: 800;
            letter-spacing: .13em;
            text-transform: uppercase;
        }

        .soc-section-title {
            color: var(--text);
            font-size: 17px;
            font-weight: 740;
            margin: 2px 0 8px 0;
        }

        .soc-case-id {
            color: var(--blue);
            font-size: 11px;
            font-weight: 800;
            letter-spacing: .08em;
        }

        .soc-case-title {
            color: var(--text);
            font-size: 25px;
            font-weight: 760;
            line-height: 1.22;
            margin: 3px 0 9px 0;
        }

        .soc-chip {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 999px;
            border: 1px solid #2a394d;
            background: #101822;
            color: #a9b6c7;
            font-size: 11px;
            margin-right: 5px;
            margin-bottom: 4px;
        }

        .soc-statebar {
            display: grid;
            grid-template-columns: repeat(5, 1fr);
            gap: 6px;
            margin: 12px 0 10px 0;
        }

        .soc-state {
            border: 1px solid #27364a;
            background: #101822;
            color: #718198;
            border-radius: 7px;
            padding: 7px 6px;
            font-size: 10px;
            font-weight: 700;
            text-align: center;
        }

        .soc-state.current {
            color: #eaf7ff;
            border-color: rgba(76,184,255,.65);
            background: rgba(76,184,255,.12);
        }

        .soc-state.done {
            color: #82dcb6;
            border-color: rgba(70,211,154,.22);
            background: rgba(70,211,154,.055);
        }

        .soc-note {
            border: 1px solid #243246;
            border-left: 3px solid #4cb8ff;
            border-radius: 8px;
            background: #101822;
            padding: 11px 12px;
            margin-bottom: 9px;
        }

        .soc-note.enrichment {
            border-left-color: var(--purple);
        }

        .soc-note.system {
            border-left-color: #65778f;
        }

        .soc-note.key {
            box-shadow:
                inset 0 0 0 1px rgba(244,207,89,.14);
        }

        .soc-note-meta {
            color: #718198;
            font-size: 9px;
            text-transform: uppercase;
            letter-spacing: .055em;
            margin-bottom: 6px;
        }

        .soc-note-body {
            color: #dce6f1;
            font-size: 13px;
            line-height: 1.55;
            white-space: pre-wrap;
        }

        .soc-callout {
            border: 1px solid rgba(255,159,67,.25);
            background: rgba(255,159,67,.06);
            color: #eab777;
            border-radius: 8px;
            padding: 9px 11px;
            font-size: 12px;
            margin: 6px 0 10px 0;
        }

        .soc-enrichment {
            border: 1px solid rgba(169,135,255,.25);
            background: rgba(169,135,255,.055);
            border-radius: 9px;
            padding: 12px;
        }

        .soc-timeline {
            border-left: 2px solid #26364a;
            padding: 1px 0 13px 14px;
            margin-left: 5px;
        }

        .soc-timeline-time {
            color: #687b92;
            font-size: 9px;
        }

        .soc-timeline-title {
            color: #e7eef7;
            font-size: 13px;
            font-weight: 700;
            margin-top: 2px;
        }

        .soc-timeline-detail {
            color: #94a4b8;
            font-size: 12px;
            margin-top: 2px;
        }

        hr {
            border-color: #1e2a39;
        }
    </style>
    """
)


# =========================================================
# HELPERS
# =========================================================

def guess_category(title):
    text = title.lower()

    if any(
        word in text
        for word in [
            "malware",
            "ransomware",
            "endpoint",
            "antivirus",
        ]
    ):
        return "Endpoint / Malware"

    if any(
        word in text
        for word in [
            "login",
            "credential",
            "access",
            "vpn",
            "privilege",
        ]
    ):
        return "Identity & Access"

    if any(
        word in text
        for word in [
            "network",
            "traffic",
            "firewall",
            "ssh",
        ]
    ):
        return "Network Security"

    if any(
        word in text
        for word in [
            "mail",
            "email",
            "phishing",
        ]
    ):
        return "Email Security"

    if any(
        word in text
        for word in [
            "web",
            "sql",
            "application",
        ]
    ):
        return "Application Security"

    return "Other"


def get_api_key():
    env_key = os.getenv(
        "ABUSEIPDB_API_KEY",
        "",
    ).strip()

    if env_key:
        return env_key

    try:
        return str(
            st.secrets.get(
                "ABUSEIPDB_API_KEY",
                "",
            )
        ).strip()
    except Exception:
        return ""


class OfflineReputationClient:
    def __init__(self, score):
        self.score = score

    def check_ip(self, ip_address):
        return IPReputation(
            ip_address=ip_address,
            abuse_confidence_score=self.score,
        )


def clear_app_state():
    keys = [
        key
        for key in list(st.session_state.keys())
        if key.startswith("soc_")
    ]

    for key in keys:
        del st.session_state[key]


def add_note(
    incident_id,
    body,
    *,
    author="System",
    note_type="Analyst Note",
    key=False,
):
    st.session_state.soc_note_counter += 1

    note = {
        "id": st.session_state.soc_note_counter,
        "time": datetime.now(),
        "author": author,
        "type": note_type,
        "body": body,
        "key": key,
    }

    st.session_state.soc_notes[
        incident_id
    ].append(note)


def add_activity(
    incident_id,
    title,
    detail,
):
    st.session_state.soc_activity.append(
        {
            "time": datetime.now(),
            "incident_id": incident_id,
            "title": title,
            "detail": detail,
        }
    )


def set_flash(
    message,
    level="success",
):
    st.session_state.soc_flash = {
        "message": message,
        "level": level,
    }


def render_flash():
    flash = st.session_state.pop(
        "soc_flash",
        None,
    )

    if not flash:
        return

    if flash["level"] == "success":
        st.toast(
            flash["message"],
            icon="✅",
        )

    elif flash["level"] == "warning":
        st.toast(
            flash["message"],
            icon="⚠️",
        )

    else:
        st.toast(
            flash["message"],
            icon="❌",
        )


def current_state(incident_id):
    return st.session_state.soc_meta[
        incident_id
    ]["state"]


def count_open_tasks(
    incident_id=None,
):
    count = 0

    for plan in (
        st.session_state.soc_manager.plans.values()
    ):
        if (
            incident_id is not None
            and plan.incident_id != incident_id
        ):
            continue

        count += len(
            plan.get_open_tasks()
        )

    return count


def get_plan(
    incident_id,
):
    return st.session_state.soc_manager.plans.get(
        f"RP-{incident_id}"
    )


def assign_case(
    incident,
    analyst_name,
):
    analyst_name = analyst_name.strip()

    if not analyst_name:
        raise ValueError(
            "Analyst name is required"
        )

    old_owner = incident.assigned_analyst

    if old_owner is None:
        incident.assign_to(
            analyst_name
        )

        action = (
            f"Case assigned to {analyst_name}"
        )

    elif old_owner == analyst_name:
        return

    else:
        incident.transfer_to(
            analyst_name
        )

        action = (
            f"Case transferred from "
            f"{old_owner} to {analyst_name}"
        )

    add_activity(
        incident.incident_id,
        "Assignment",
        action,
    )

    add_note(
        incident.incident_id,
        action,
        author="System",
        note_type="System",
    )


def change_state(
    incident,
    new_state,
):
    incident_id = incident.incident_id

    old_state = current_state(
        incident_id
    )

    if old_state == "Closed":
        raise ValueError(
            "Closed cases cannot change state"
        )

    if new_state == "Closed":
        raise ValueError(
            "Use Close Case to close the incident"
        )

    st.session_state.soc_meta[
        incident_id
    ]["state"] = new_state

    if new_state == "New":
        incident.status = "Open"

    elif new_state in [
        "In Progress",
        "On Hold",
        "Resolved",
    ]:
        incident.status = "In Progress"

    message = (
        f"State changed from "
        f"{old_state} to {new_state}"
    )

    add_activity(
        incident_id,
        "State Change",
        message,
    )

    add_note(
        incident_id,
        message,
        author="System",
        note_type="System",
    )


def render_state_bar(
    current,
):
    current_index = (
        CASE_STATES.index(current)
    )

    items = []

    for index, state in enumerate(
        CASE_STATES
    ):
        css = "soc-state"

        if state == current:
            css += " current"

        elif index < current_index:
            css += " done"

        items.append(
            f'<div class="{css}">'
            f"{escape(state)}"
            f"</div>"
        )

    st.html(
        '<div class="soc-statebar">'
        + "".join(items)
        + "</div>"
    )


def render_note(note):
    css = "soc-note"

    if note["type"] == "Enrichment":
        css += " enrichment"

    elif note["type"] == "System":
        css += " system"

    if note["key"]:
        css += " key"

    key_text = (
        " • KEY"
        if note["key"]
        else ""
    )

    meta = (
        f"{note['type']}{key_text} • "
        f"{note['author']} • "
        f"{note['time'].strftime('%Y-%m-%d %H:%M:%S')}"
    )

    st.html(
        f'<div class="{css}">'
        f'<div class="soc-note-meta">'
        f"{escape(meta)}"
        f"</div>"
        f'<div class="soc-note-body">'
        f"{escape(note['body'])}"
        f"</div>"
        f"</div>"
    )


def build_enrichment_note(
    decision,
    source_name,
):
    reputation = decision.reputation

    if reputation is None:
        return (
            "IP Reputation Enrichment\n"
            f"Source: {source_name}\n"
            f"Decision: {decision.status}\n"
            f"Reason: {decision.reason or 'N/A'}"
        )

    whitelist_text = (
        "Yes"
        if reputation.is_whitelisted is True
        else (
            "No"
            if reputation.is_whitelisted is False
            else "Unknown"
        )
    )

    tor_text = (
        "Yes"
        if reputation.is_tor is True
        else (
            "No"
            if reputation.is_tor is False
            else "Unknown"
        )
    )

    lines = [
        "IP Reputation Enrichment",
        f"Observable: {reputation.ip_address}",
        f"Source: {source_name}",
        f"Decision: {decision.status}",
        (
            "Abuse confidence score: "
            f"{reputation.abuse_confidence_score}%"
        ),
        (
            "Reports in 90-day window: "
            f"{reputation.total_reports}"
        ),
        (
            "Distinct reporters: "
            f"{reputation.num_distinct_users}"
        ),
        f"Whitelisted: {whitelist_text}",
        f"ISP: {reputation.isp or 'N/A'}",
        (
            "Usage type: "
            f"{reputation.usage_type or 'N/A'}"
        ),
        f"Domain: {reputation.domain or 'N/A'}",
        (
            "Country: "
            f"{reputation.country_code or 'N/A'}"
        ),
        f"Tor exit node: {tor_text}",
        (
            "Last reported: "
            f"{reputation.last_reported_at or 'Never / unavailable'}"
        ),
    ]

    if (
        reputation.total_reports > 0
        and reputation.abuse_confidence_score < 80
    ):
        lines.extend(
            [
                "",
                (
                    "Reported activity exists, but "
                    "the current AbuseIPDB confidence "
                    "score remains below the review threshold."
                ),
            ]
        )

    return "\n".join(lines)


def update_observable(
    incident_id,
    decision,
    source_name,
):
    reputation = decision.reputation

    if reputation is None:
        return

    rows = (
        st.session_state.soc_observables[
            incident_id
        ]
    )

    existing = next(
        (
            item
            for item in rows
            if item["Value"]
            == reputation.ip_address
        ),
        None,
    )

    whitelist_text = (
        "Yes"
        if reputation.is_whitelisted is True
        else (
            "No"
            if reputation.is_whitelisted is False
            else "Unknown"
        )
    )

    row = {
        "Type": "IP",
        "Value": reputation.ip_address,
        "Verdict": decision.status,
        "Score": reputation.abuse_confidence_score,
        "Reports": reputation.total_reports,
        "Whitelisted": whitelist_text,
        "ISP": reputation.isp or "N/A",
        "Country": (
            reputation.country_code
            or "N/A"
        ),
        "Source": source_name,
        "Last Enriched": (
            datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            )
        ),
    }

    if existing:
        existing.update(row)
    else:
        rows.append(row)


def initialize_state():
    if (
        st.session_state.get(
            "soc_ui_version"
        )
        == UI_STATE_VERSION
    ):
        return

    clear_app_state()

    incidents = load_incidents(
        str(
            DATA_DIR
            / "sample_data.jsonl"
        )
    )

    processor = IncidentProcessor()
    processor.build_index(
        incidents
    )

    manager = RemediationManager(
        processor
    )

    manager.load_tasks(
        str(
            DATA_DIR
            / "remediation_tasks.jsonl"
        )
    )

    st.session_state.soc_ui_version = (
        UI_STATE_VERSION
    )

    st.session_state.soc_incidents = (
        incidents
    )

    st.session_state.soc_processor = (
        processor
    )

    st.session_state.soc_manager = (
        manager
    )

    st.session_state.soc_audit = (
        RiskAuditObserver()
    )

    st.session_state.soc_meta = {}
    st.session_state.soc_notes = {}
    st.session_state.soc_observables = {}
    st.session_state.soc_activity = []
    st.session_state.soc_last_reputation = {}
    st.session_state.soc_runbooks = {}

    st.session_state.soc_note_counter = 0
    st.session_state.soc_event_counter = 0
    st.session_state.soc_action_counter = 0
    st.session_state.soc_task_counter = 0

    for incident in incidents:
        if incident.status == "Closed":
            state = "Closed"

        elif incident.status == "In Progress":
            state = "In Progress"

        else:
            state = "New"

        st.session_state.soc_meta[
            incident.incident_id
        ] = {
            "state": state,
            "group": "SOC Tier 1",
            "category": guess_category(
                incident.title
            ),
            "reviewer": "",
            "resolution_reason": "",
        }

        st.session_state.soc_notes[
            incident.incident_id
        ] = []

        st.session_state.soc_observables[
            incident.incident_id
        ] = []

        st.session_state.soc_runbooks[
            incident.incident_id
        ] = {
            step: False
            for step in RUNBOOK_TEMPLATE
        }

    if incidents:
        st.session_state.soc_selected_case = (
            incidents[0].incident_id
        )

    else:
        st.session_state.soc_selected_case = None

    st.session_state.soc_workspace_view = (
        "Notes"
    )


# =========================================================
# INITIALIZE
# =========================================================

initialize_state()
render_flash()

incidents = (
    st.session_state.soc_incidents
)

processor = (
    st.session_state.soc_processor
)

manager = (
    st.session_state.soc_manager
)

api_key = get_api_key()
api_ready = bool(api_key)


# =========================================================
# HEADER
# =========================================================

header_left, header_right = (
    st.columns([4.5, 1.3])
)

with header_left:
    st.html(
        """
        <div class="soc-brand">
            🛡️ SOC Case Manager
        </div>
        <div class="soc-subtitle">
            Security Operations • Analyst Workbench
        </div>
        """
    )

with header_right:
    if api_ready:
        st.success(
            "● SYSTEM ONLINE · AbuseIPDB READY"
        )
    else:
        st.warning(
            "● SYSTEM ONLINE · AbuseIPDB OFFLINE"
        )


# =========================================================
# GLOBAL STATUS
# =========================================================

active_cases = [
    incident
    for incident in incidents
    if current_state(
        incident.incident_id
    ) != "Closed"
]

critical_cases = [
    incident
    for incident in active_cases
    if incident.severity
    == "Critical"
]

unassigned_cases = [
    incident
    for incident in active_cases
    if incident.assigned_analyst
    is None
]

m1, m2, m3, m4 = st.columns(4)

m1.metric(
    "Active Cases",
    len(active_cases),
)

m2.metric(
    "Critical",
    len(critical_cases),
)

m3.metric(
    "Unassigned",
    len(unassigned_cases),
)

m4.metric(
    "Open Response Tasks",
    count_open_tasks(),
)

st.divider()


# =========================================================
# FILTERS
# =========================================================

search_col, severity_col, state_col, owner_col, reset_col = (
    st.columns(
        [2.6, 1.05, 1.05, 1.15, .7]
    )
)

with search_col:
    search_text = st.text_input(
        "Search",
        placeholder=(
            "Search ID, title, owner, "
            "note or observable..."
        ),
        label_visibility="collapsed",
    )

with severity_col:
    severity_filter = st.selectbox(
        "Severity",
        [
            "All severities",
            "Critical",
            "High",
            "Medium",
            "Low",
        ],
        label_visibility="collapsed",
    )

with state_col:
    state_filter = st.selectbox(
        "State",
        [
            "Active states",
            "All states",
        ]
        + CASE_STATES,
        label_visibility="collapsed",
    )

owners = sorted(
    {
        incident.assigned_analyst
        for incident in incidents
        if incident.assigned_analyst
    }
)

with owner_col:
    owner_filter = st.selectbox(
        "Owner",
        [
            "All owners",
            "Unassigned",
        ]
        + owners,
        label_visibility="collapsed",
    )

with reset_col:
    if st.button(
        "↻ Reset",
        width="stretch",
    ):
        clear_app_state()
        st.rerun()


# =========================================================
# FILTER CASES
# =========================================================

query = (
    search_text.strip().lower()
)

filtered = []

for incident in incidents:
    incident_id = (
        incident.incident_id
    )

    meta = (
        st.session_state.soc_meta[
            incident_id
        ]
    )

    if (
        severity_filter
        != "All severities"
        and incident.severity
        != severity_filter
    ):
        continue

    if (
        state_filter
        == "Active states"
        and meta["state"] == "Closed"
    ):
        continue

    if (
        state_filter
        not in [
            "Active states",
            "All states",
        ]
        and meta["state"]
        != state_filter
    ):
        continue

    if (
        owner_filter
        == "Unassigned"
        and incident.assigned_analyst
        is not None
    ):
        continue

    if (
        owner_filter
        not in [
            "All owners",
            "Unassigned",
        ]
        and incident.assigned_analyst
        != owner_filter
    ):
        continue

    if query:
        notes_blob = " ".join(
            note["body"]
            for note in (
                st.session_state.soc_notes[
                    incident_id
                ]
            )
        )

        observable_blob = " ".join(
            item["Value"]
            for item in (
                st.session_state.soc_observables[
                    incident_id
                ]
            )
        )

        haystack = " ".join(
            [
                incident_id,
                incident.title,
                (
                    incident.assigned_analyst
                    or ""
                ),
                meta["category"],
                meta["group"],
                notes_blob,
                observable_blob,
            ]
        ).lower()

        if query not in haystack:
            continue

    filtered.append(
        incident
    )


filtered.sort(
    key=lambda incident: (
        current_state(
            incident.incident_id
        )
        == "Closed",
        -incident.SEVERITY_SCORES[
            incident.severity
        ],
        incident.incident_id,
    )
)


if not filtered:
    st.warning(
        "No cases match the current filters."
    )
    st.stop()


# =========================================================
# QUEUE + WORKSPACE
# =========================================================

queue_col, workspace_col = (
    st.columns(
        [1.0, 1.72],
        gap="large",
    )
)


# =========================================================
# QUEUE
# =========================================================

with queue_col:
    with st.container(
        border=True
    ):
        st.html(
            """
            <div class="soc-kicker">
                Cases
            </div>
            <div class="soc-section-title">
                Analyst Queue
            </div>
            """
        )

        st.caption(
            f"{len(filtered)} cases"
        )

        queue_rows = []

        for incident in filtered:
            incident_id = (
                incident.incident_id
            )

            meta = (
                st.session_state.soc_meta[
                    incident_id
                ]
            )

            queue_rows.append(
                {
                    "Severity": (
                        f"{SEVERITY_ICON[incident.severity]} "
                        f"{incident.severity}"
                    ),
                    "ID": incident_id,
                    "Case": incident.title,
                    "State": meta["state"],
                    "Owner": (
                        incident.assigned_analyst
                        or "Unassigned"
                    ),
                    "Tasks": (
                        count_open_tasks(
                            incident_id
                        )
                    ),
                }
            )

        queue_event = st.dataframe(
            queue_rows,
            key="soc_case_queue",
            width="stretch",
            height=610,
            hide_index=True,
            on_select="rerun",
            selection_mode="single-row",
        )

        if (
            queue_event.selection.rows
        ):
            row_index = (
                queue_event.selection.rows[0]
            )

            st.session_state.soc_selected_case = (
                filtered[
                    row_index
                ].incident_id
            )

        visible_ids = {
            incident.incident_id
            for incident in filtered
        }

        if (
            st.session_state.soc_selected_case
            not in visible_ids
        ):
            st.session_state.soc_selected_case = (
                filtered[0].incident_id
            )


# =========================================================
# SELECTED CASE
# =========================================================

selected = processor.get_incident(
    st.session_state.soc_selected_case
)

if selected is None:
    st.error(
        "Selected case does not exist."
    )
    st.stop()


incident_id = (
    selected.incident_id
)

meta = (
    st.session_state.soc_meta[
        incident_id
    ]
)

notes = (
    st.session_state.soc_notes[
        incident_id
    ]
)

observables = (
    st.session_state.soc_observables[
        incident_id
    ]
)

latest_rep = (
    st.session_state.soc_last_reputation.get(
        incident_id
    )
)


# =========================================================
# CASE WORKSPACE
# =========================================================

with workspace_col:
    with st.container(
        border=True
    ):
        st.html(
            f"""
            <div class="soc-case-id">
                CASE / {escape(incident_id)}
            </div>
            <div class="soc-case-title">
                {escape(selected.title)}
            </div>
            """
        )

        chips = [
            (
                "Severity: "
                f"{selected.severity}"
            ),
            (
                "State: "
                f"{meta['state']}"
            ),
            (
                "Owner: "
                f"{selected.assigned_analyst or 'Unassigned'}"
            ),
            (
                "Group: "
                f"{meta['group']}"
            ),
            (
                "Category: "
                f"{meta['category']}"
            ),
            (
                "SLA: "
                f"{SLA_TARGET[selected.severity]}"
            ),
        ]

        st.html(
            "".join(
                (
                    '<span class="soc-chip">'
                    f"{escape(item)}"
                    "</span>"
                )
                for item in chips
            )
        )

        render_state_bar(
            meta["state"]
        )

        if (
            selected.assigned_analyst
            is None
            and meta["state"]
            != "Closed"
        ):
            st.html(
                """
                <div class="soc-callout">
                    ⚠ Active case has no assigned analyst.
                </div>
                """
            )

        # =================================================
        # MAIN ACTIONS
        # =================================================

        (
            assign_col,
            state_col,
            note_col,
            enrich_col,
            more_col,
        ) = st.columns(
            [1, 1, 1, 1.2, .8]
        )

        # ---------------- ASSIGN ----------------

        with assign_col:
            assign_pop = st.popover(
                "👤 Assign",
                width="stretch",
            )

            with assign_pop:
                with st.form(
                    f"assign_{incident_id}"
                ):
                    analyst_name = (
                        st.text_input(
                            "Analyst",
                            value=(
                                selected.assigned_analyst
                                or ""
                            ),
                        )
                    )

                    group_name = (
                        st.selectbox(
                            "Group",
                            CASE_GROUPS,
                            index=(
                                CASE_GROUPS.index(
                                    meta["group"]
                                )
                            ),
                        )
                    )

                    assign_submit = (
                        st.form_submit_button(
                            "Apply assignment",
                            width="stretch",
                        )
                    )

                if assign_submit:
                    try:
                        assign_case(
                            selected,
                            analyst_name,
                        )

                        meta["group"] = (
                            group_name
                        )

                        set_flash(
                            "Assignment updated"
                        )

                        st.rerun()

                    except ValueError as error:
                        st.error(
                            str(error)
                        )

        # ---------------- STATE ----------------

        with state_col:
            state_pop = st.popover(
                "⇢ State",
                width="stretch",
            )

            with state_pop:
                available_states = [
                    state
                    for state in CASE_STATES
                    if state != "Closed"
                ]

                current_non_closed = (
                    meta["state"]
                    if meta["state"]
                    in available_states
                    else "New"
                )

                new_state = st.selectbox(
                    "Move case to",
                    available_states,
                    index=(
                        available_states.index(
                            current_non_closed
                        )
                    ),
                )

                if st.button(
                    "Update state",
                    width="stretch",
                    key=(
                        f"state_button_"
                        f"{incident_id}"
                    ),
                    disabled=(
                        meta["state"]
                        == "Closed"
                    ),
                ):
                    try:
                        change_state(
                            selected,
                            new_state,
                        )

                        set_flash(
                            f"State changed to {new_state}"
                        )

                        st.rerun()

                    except ValueError as error:
                        st.error(
                            str(error)
                        )

        # ---------------- ADD NOTE ----------------

        with note_col:
            note_pop = st.popover(
                "✎ Add Note",
                width="stretch",
            )

            with note_pop:
                with st.form(
                    f"note_{incident_id}"
                ):
                    note_author = (
                        st.text_input(
                            "Analyst",
                            value=(
                                selected.assigned_analyst
                                or ""
                            ),
                        )
                    )

                    note_body = (
                        st.text_area(
                            "Note",
                            placeholder=(
                                "Document findings, "
                                "context or analyst reasoning..."
                            ),
                        )
                    )

                    key_note = (
                        st.checkbox(
                            "Mark as key note"
                        )
                    )

                    note_submit = (
                        st.form_submit_button(
                            "Add note",
                            width="stretch",
                        )
                    )

                if note_submit:
                    if not note_body.strip():
                        st.error(
                            "Note text is required"
                        )

                    else:
                        add_note(
                            incident_id,
                            note_body.strip(),
                            author=(
                                note_author.strip()
                                or "Analyst"
                            ),
                            note_type="Analyst Note",
                            key=key_note,
                        )

                        add_activity(
                            incident_id,
                            "Analyst Note",
                            note_body.strip(),
                        )

                        st.session_state.soc_workspace_view = (
                            "Notes"
                        )

                        set_flash(
                            "Note added"
                        )

                        st.rerun()

        # ---------------- ENRICH ----------------

        with enrich_col:
            enrich_pop = st.popover(
                "🌐 Enrich IP",
                width="stretch",
            )

            with enrich_pop:
                st.caption(
                    "Run IP reputation enrichment "
                    "and automatically add the result "
                    "to case Notes."
                )

                mode_options = [
                    "Offline simulation",
                ]

                if api_ready:
                    mode_options.append(
                        "LIVE AbuseIPDB"
                    )

                mode = st.radio(
                    "Source",
                    mode_options,
                    horizontal=False,
                )

                with st.form(
                    f"enrich_{incident_id}"
                ):
                    ip_value = (
                        st.text_input(
                            "Public IP",
                            value="1.1.1.1",
                        )
                    )

                    simulated_score = 85

                    if (
                        mode
                        == "Offline simulation"
                    ):
                        simulated_score = (
                            st.slider(
                                "Synthetic score",
                                0,
                                100,
                                85,
                            )
                        )

                    enrich_submit = (
                        st.form_submit_button(
                            (
                                "Run LIVE enrichment"
                                if mode
                                == "LIVE AbuseIPDB"
                                else "Run simulation"
                            ),
                            type=(
                                "primary"
                                if mode
                                == "LIVE AbuseIPDB"
                                else "secondary"
                            ),
                            width="stretch",
                        )
                    )

                if not api_ready:
                    st.info(
                        "Configure ABUSEIPDB_API_KEY "
                        "to enable LIVE enrichment."
                    )

                if enrich_submit:
                    try:
                        normalized_ip = (
                            require_public_ip(
                                ip_value
                            )
                        )

                    except ValueError as error:
                        st.error(
                            str(error)
                        )

                    else:
                        (
                            st.session_state.soc_event_counter
                        ) += 1

                        event = NetworkEvent(
                            event_id=(
                                "GUI-NET-"
                                f"{st.session_state.soc_event_counter:03d}"
                            ),
                            timestamp=(
                                datetime.now().isoformat(
                                    timespec="seconds"
                                )
                            ),
                            source=(
                                "AbuseIPDB"
                                if mode
                                == "LIVE AbuseIPDB"
                                else "Offline Simulation"
                            ),
                            suspicious_ip=(
                                normalized_ip
                            ),
                            port=443,
                        )

                        selected.add_event(
                            event
                        )

                        if (
                            mode
                            == "LIVE AbuseIPDB"
                        ):
                            client = (
                                AbuseIPDBClient(
                                    api_key
                                )
                            )

                            source_name = (
                                "AbuseIPDB (LIVE)"
                            )

                        else:
                            client = (
                                OfflineReputationClient(
                                    simulated_score
                                )
                            )

                            source_name = (
                                "Offline Simulation"
                            )

                        service = (
                            ReputationService(
                                client,
                                manager,
                                audit=(
                                    st.session_state.soc_audit
                                ),
                            )
                        )

                        decision = (
                            service.evaluate_network_event(
                                incident_id,
                                event,
                            )
                        )

                        st.session_state.soc_last_reputation[
                            incident_id
                        ] = {
                            "decision": decision,
                            "source": source_name,
                            "time": datetime.now(),
                        }

                        update_observable(
                            incident_id,
                            decision,
                            source_name,
                        )

                        enrichment_note = (
                            build_enrichment_note(
                                decision,
                                source_name,
                            )
                        )

                        add_note(
                            incident_id,
                            enrichment_note,
                            author="Automation",
                            note_type="Enrichment",
                            key=(
                                decision.status
                                == "high-risk"
                            ),
                        )

                        add_activity(
                            incident_id,
                            "IP Enrichment",
                            (
                                f"{normalized_ip} → "
                                f"{decision.status}"
                                + (
                                    f" / score "
                                    f"{decision.score}"
                                    if decision.score
                                    is not None
                                    else ""
                                )
                            ),
                        )

                        st.session_state.soc_workspace_view = (
                            "Notes"
                        )

                        set_flash(
                            (
                                "LIVE enrichment completed "
                                "and added to Notes"
                                if mode
                                == "LIVE AbuseIPDB"
                                else (
                                    "Simulation completed "
                                    "and added to Notes"
                                )
                            )
                        )

                        st.rerun()

        # ---------------- MORE ----------------

        with more_col:
            more_pop = st.popover(
                "•••",
                width="stretch",
            )

            with more_pop:
                st.write(
                    "**Case fields**"
                )

                with st.form(
                    f"fields_{incident_id}"
                ):
                    severity = st.selectbox(
                        "Severity",
                        [
                            "Critical",
                            "High",
                            "Medium",
                            "Low",
                        ],
                        index=(
                            [
                                "Critical",
                                "High",
                                "Medium",
                                "Low",
                            ].index(
                                selected.severity
                            )
                        ),
                    )

                    category = st.selectbox(
                        "Category",
                        CASE_CATEGORIES,
                        index=(
                            CASE_CATEGORIES.index(
                                meta["category"]
                            )
                        ),
                    )

                    reviewer = st.text_input(
                        "Reviewer",
                        value=(
                            meta["reviewer"]
                        ),
                    )

                    fields_submit = (
                        st.form_submit_button(
                            "Save fields",
                            width="stretch",
                        )
                    )

                if fields_submit:
                    selected.severity = (
                        severity
                    )

                    meta["category"] = (
                        category
                    )

                    meta["reviewer"] = (
                        reviewer.strip()
                    )

                    add_activity(
                        incident_id,
                        "Case Fields",
                        (
                            "Case metadata updated"
                        ),
                    )

                    set_flash(
                        "Case fields updated"
                    )

                    st.rerun()

                st.divider()

                with st.popover(
                    "➕ Create response task",
                    width="stretch",
                ):
                    with st.form(
                        f"task_{incident_id}"
                    ):
                        task_description = (
                            st.text_input(
                                "Task description"
                            )
                        )

                        assigned_team = (
                            st.text_input(
                                "Assigned team",
                                value="Security",
                            )
                        )

                        create_task = (
                            st.form_submit_button(
                                "Create task",
                                width="stretch",
                            )
                        )

                    if create_task:
                        if not (
                            task_description.strip()
                            and assigned_team.strip()
                        ):
                            st.error(
                                "Description and team are required"
                            )

                        else:
                            plan = get_plan(
                                incident_id
                            )

                            if plan is None:
                                plan_id = (
                                    f"RP-{incident_id}"
                                )

                                plan = (
                                    RemediationPlan(
                                        plan_id,
                                        incident_id,
                                    )
                                )

                                manager.plans[
                                    plan_id
                                ] = plan

                            (
                                st.session_state.soc_task_counter
                            ) += 1

                            task = Task(
                                task_id=(
                                    "GUI-TASK-"
                                    f"{st.session_state.soc_task_counter:03d}"
                                ),
                                description=(
                                    task_description.strip()
                                ),
                                assigned_team=(
                                    assigned_team.strip()
                                ),
                            )

                            plan.add_task(
                                task
                            )

                            add_activity(
                                incident_id,
                                "Response Task",
                                (
                                    f"{task.task_id} created"
                                ),
                            )

                            add_note(
                                incident_id,
                                (
                                    "Response task created\n"
                                    f"Task: {task.task_id}\n"
                                    f"Team: {task.assigned_team}\n"
                                    f"Description: {task.description}"
                                ),
                                author="System",
                                note_type="System",
                            )

                            set_flash(
                                "Response task created"
                            )

                            st.rerun()

                st.divider()

                close_pop = st.popover(
                    "✓ Close Case",
                    width="stretch",
                )

                with close_pop:
                    if (
                        meta["state"]
                        == "Closed"
                    ):
                        st.success(
                            "Case is already closed."
                        )

                    else:
                        with st.form(
                            f"close_{incident_id}"
                        ):
                            resolution_reason = (
                                st.selectbox(
                                    "Resolution reason",
                                    [
                                        "Benign / False Positive",
                                        "Contained",
                                        "Remediated",
                                        "Accepted Risk",
                                        "Duplicate",
                                        "Other",
                                    ],
                                )
                            )

                            summary = (
                                st.text_area(
                                    "Resolution summary"
                                )
                            )

                            close_submit = (
                                st.form_submit_button(
                                    "Close case",
                                    type="primary",
                                    width="stretch",
                                )
                            )

                        if close_submit:
                            try:
                                selected.close(
                                    summary
                                )

                                meta[
                                    "resolution_reason"
                                ] = (
                                    resolution_reason
                                )

                                meta["state"] = (
                                    "Closed"
                                )

                                message = (
                                    "Case closed\n"
                                    f"Reason: {resolution_reason}\n"
                                    f"Summary: {summary.strip()}"
                                )

                                add_note(
                                    incident_id,
                                    message,
                                    author="System",
                                    note_type="System",
                                    key=True,
                                )

                                add_activity(
                                    incident_id,
                                    "Case Closed",
                                    resolution_reason,
                                )

                                set_flash(
                                    "Case closed"
                                )

                                st.rerun()

                            except ValueError as error:
                                st.error(
                                    str(error)
                                )

        st.divider()

        # =================================================
        # CASE QUICK STATUS
        # =================================================

        k1, k2, k3, k4 = (
            st.columns(4)
        )

        k1.metric(
            "Internal Risk",
            selected.calculate_total_risk(),
        )

        k2.metric(
            "Observables",
            len(observables),
        )

        k3.metric(
            "Open Tasks",
            count_open_tasks(
                incident_id
            ),
        )

        latest_score = "—"

        if latest_rep:
            decision = (
                latest_rep["decision"]
            )

            if (
                decision.score
                is not None
            ):
                latest_score = (
                    decision.score
                )

        k4.metric(
            "AbuseIPDB Score",
            latest_score,
        )

        # =================================================
        # WORKSPACE NAVIGATION
        # =================================================

        views = [
            "Notes",
            "Observables",
            "Tasks",
            "Timeline",
            "Runbook",
            "Summary",
        ]

        if (
            st.session_state.soc_workspace_view
            not in views
        ):
            st.session_state.soc_workspace_view = (
                "Notes"
            )

        view = st.radio(
            "Case workspace",
            views,
            horizontal=True,
            key="soc_workspace_view",
            label_visibility="collapsed",
        )

        st.divider()

        # =================================================
        # NOTES
        # =================================================

        if view == "Notes":
            st.html(
                """
                <div class="soc-kicker">
                    Investigation Thread
                </div>
                <div class="soc-section-title">
                    Case Notes
                </div>
                """
            )

            if latest_rep:
                decision = (
                    latest_rep["decision"]
                )

                rep = (
                    decision.reputation
                )

                if rep:
                    st.html(
                        f"""
                        <div class="soc-enrichment">
                            <b>Latest IP Enrichment</b><br>
                            {escape(rep.ip_address)}
                            &nbsp;•&nbsp;
                            Score: {rep.abuse_confidence_score}
                            &nbsp;•&nbsp;
                            Reports: {rep.total_reports}
                            &nbsp;•&nbsp;
                            Verdict: {escape(decision.status)}
                            &nbsp;•&nbsp;
                            Source: {escape(latest_rep["source"])}
                        </div>
                        """
                    )

                    st.write("")

            if not notes:
                st.info(
                    "No case notes yet."
                )

            else:
                sorted_notes = sorted(
                    notes,
                    key=lambda item: (
                        item["time"]
                    ),
                    reverse=True,
                )

                key_notes = [
                    note
                    for note in sorted_notes
                    if note["key"]
                ]

                other_notes = [
                    note
                    for note in sorted_notes
                    if not note["key"]
                ]

                if key_notes:
                    st.caption(
                        "KEY NOTES"
                    )

                    for note in key_notes:
                        render_note(
                            note
                        )

                    st.divider()

                for note in other_notes:
                    render_note(
                        note
                    )

        # =================================================
        # OBSERVABLES
        # =================================================

        elif view == "Observables":
            st.html(
                """
                <div class="soc-kicker">
                    Indicators
                </div>
                <div class="soc-section-title">
                    Observables & Enrichment
                </div>
                """
            )

            if not observables:
                st.info(
                    "No observables enriched yet. "
                    "Use 🌐 Enrich IP."
                )

            else:
                st.dataframe(
                    observables,
                    width="stretch",
                    hide_index=True,
                )

                st.caption(
                    "AbuseIPDB report counts use "
                    "the configured 90-day window."
                )

                if latest_rep:
                    decision = (
                        latest_rep["decision"]
                    )

                    rep = (
                        decision.reputation
                    )

                    if rep:
                        e1, e2, e3, e4 = (
                            st.columns(4)
                        )

                        e1.metric(
                            "Confidence",
                            (
                                f"{rep.abuse_confidence_score}%"
                            ),
                        )

                        e2.metric(
                            "Reports",
                            rep.total_reports,
                        )

                        e3.metric(
                            "Distinct Reporters",
                            rep.num_distinct_users,
                        )

                        whitelist_value = (
                            "YES"
                            if rep.is_whitelisted
                            is True
                            else (
                                "NO"
                                if rep.is_whitelisted
                                is False
                                else "UNKNOWN"
                            )
                        )

                        e4.metric(
                            "Whitelisted",
                            whitelist_value,
                        )

                        details = {
                            "IP": rep.ip_address,
                            "Verdict": decision.status,
                            "ISP": rep.isp or "N/A",
                            "Usage Type": (
                                rep.usage_type
                                or "N/A"
                            ),
                            "Domain": (
                                rep.domain
                                or "N/A"
                            ),
                            "Country": (
                                rep.country_code
                                or "N/A"
                            ),
                            "Tor": (
                                "Yes"
                                if rep.is_tor
                                is True
                                else (
                                    "No"
                                    if rep.is_tor
                                    is False
                                    else "Unknown"
                                )
                            ),
                            "Last Reported": (
                                rep.last_reported_at
                                or "Never / unavailable"
                            ),
                            "Source": (
                                latest_rep["source"]
                            ),
                        }

                        st.dataframe(
                            [
                                {
                                    "Field": key,
                                    "Value": value,
                                }
                                for key, value
                                in details.items()
                            ],
                            width="stretch",
                            hide_index=True,
                        )

        # =================================================
        # TASKS
        # =================================================

        elif view == "Tasks":
            st.html(
                """
                <div class="soc-kicker">
                    Response
                </div>
                <div class="soc-section-title">
                    Remediation Tasks
                </div>
                """
            )

            plan = get_plan(
                incident_id
            )

            if (
                plan is None
                or not plan.tasks
            ):
                st.info(
                    "No response tasks for this case."
                )

            else:
                for task in plan.tasks:
                    left, right = (
                        st.columns([5, 1])
                    )

                    with left:
                        state_text = (
                            "✅ Done"
                            if task.is_completed
                            else "⏳ Pending"
                        )

                        st.write(
                            f"**{task.task_id}** "
                            f"— {state_text}"
                        )

                        st.caption(
                            f"{task.description} · "
                            f"Team: {task.assigned_team}"
                        )

                    with right:
                        if not task.is_completed:
                            if st.button(
                                "Complete",
                                key=(
                                    f"complete_"
                                    f"{incident_id}_"
                                    f"{task.task_id}"
                                ),
                                width="stretch",
                            ):
                                task.mark_completed()

                                message = (
                                    f"Task {task.task_id} completed"
                                )

                                add_activity(
                                    incident_id,
                                    "Remediation",
                                    message,
                                )

                                add_note(
                                    incident_id,
                                    message,
                                    author="System",
                                    note_type="System",
                                )

                                set_flash(
                                    "Task completed"
                                )

                                st.rerun()

                    st.divider()

        # =================================================
        # TIMELINE
        # =================================================

        elif view == "Timeline":
            st.html(
                """
                <div class="soc-kicker">
                    History
                </div>
                <div class="soc-section-title">
                    Case Timeline
                </div>
                """
            )

            timeline = [
                item
                for item in (
                    st.session_state.soc_activity
                )
                if item["incident_id"]
                == incident_id
            ]

            for action in selected.actions:
                timeline.append(
                    {
                        "time": action.action_time,
                        "incident_id": incident_id,
                        "title": (
                            "Investigation Action"
                        ),
                        "detail": (
                            f"{action.analyst_name}: "
                            f"{action.description}"
                        ),
                    }
                )

            timeline.sort(
                key=lambda item: (
                    item["time"]
                ),
                reverse=True,
            )

            if not timeline:
                st.info(
                    "No timeline events yet."
                )

            else:
                for item in timeline:
                    st.html(
                        f"""
                        <div class="soc-timeline">
                            <div class="soc-timeline-time">
                                {
                                    item["time"].strftime(
                                        "%Y-%m-%d %H:%M:%S"
                                    )
                                }
                            </div>
                            <div class="soc-timeline-title">
                                {escape(item["title"])}
                            </div>
                            <div class="soc-timeline-detail">
                                {escape(item["detail"])}
                            </div>
                        </div>
                        """
                    )

        # =================================================
        # RUNBOOK
        # =================================================

        elif view == "Runbook":
            st.html(
                """
                <div class="soc-kicker">
                    Workflow
                </div>
                <div class="soc-section-title">
                    Analyst Runbook
                </div>
                """
            )

            runbook = (
                st.session_state.soc_runbooks[
                    incident_id
                ]
            )

            completed = sum(
                runbook.values()
            )

            st.progress(
                completed
                / len(RUNBOOK_TEMPLATE)
            )

            st.caption(
                f"{completed} / "
                f"{len(RUNBOOK_TEMPLATE)} steps completed"
            )

            changed = False

            for step in RUNBOOK_TEMPLATE:
                value = st.checkbox(
                    step,
                    value=runbook[step],
                    key=(
                        f"runbook_"
                        f"{incident_id}_"
                        f"{step}"
                    ),
                )

                if (
                    value
                    != runbook[step]
                ):
                    runbook[step] = value
                    changed = True

            if changed:
                st.rerun()

        # =================================================
        # SUMMARY
        # =================================================

        elif view == "Summary":
            st.html(
                """
                <div class="soc-kicker">
                    Case
                </div>
                <div class="soc-section-title">
                    Case Summary
                </div>
                """
            )

            s1, s2 = st.columns(2)

            with s1:
                st.write(
                    f"**ID:** {incident_id}"
                )
                st.write(
                    f"**Severity:** {selected.severity}"
                )
                st.write(
                    f"**State:** {meta['state']}"
                )
                st.write(
                    "**Owner:** "
                    f"{selected.assigned_analyst or 'Unassigned'}"
                )
                st.write(
                    f"**Group:** {meta['group']}"
                )
                st.write(
                    f"**Category:** {meta['category']}"
                )
                st.write(
                    f"**Reviewer:** {meta['reviewer'] or 'None'}"
                )

            with s2:
                st.write(
                    f"**Security Events:** {len(selected.events)}"
                )
                st.write(
                    f"**Observables:** {len(observables)}"
                )
                st.write(
                    f"**Notes:** {len(notes)}"
                )
                st.write(
                    "**Open Tasks:** "
                    f"{count_open_tasks(incident_id)}"
                )
                st.write(
                    f"**SLA Target:** {SLA_TARGET[selected.severity]}"
                )

                if meta[
                    "resolution_reason"
                ]:
                    st.write(
                        "**Resolution Reason:** "
                        f"{meta['resolution_reason']}"
                    )

            if (
                selected.resolution_summary
            ):
                st.success(
                    "Resolution Summary\n\n"
                    + selected.resolution_summary
                )


# =========================================================
# FOOTER
# =========================================================

st.caption(
    "SOC Case Manager • Demonstration environment • "
    "Session-backed changes are not persisted to JSONL."
)