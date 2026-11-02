import json

from soc_case_manager.repository import load_incidents


def test_load_incidents_with_tmp_path(tmp_path):
    file_path = tmp_path / "incidents.jsonl"

    records = [
        {
            "id": "TMP-001",
            "title": "Temporary test incident",
            "severity": "High",
            "status": "Open",
        },
        {
            "id": "TMP-002",
            "title": "Second temporary incident",
            "severity": "Medium",
            "status": "In Progress",
        },
    ]

    file_path.write_text(
        "\n".join(json.dumps(record) for record in records),
        encoding="utf-8",
    )

    incidents = load_incidents(file_path)

    assert len(incidents) == 2
    assert incidents[0].incident_id == "TMP-001"
    assert incidents[0].severity == "High"
    assert incidents[1].incident_id == "TMP-002"
    assert incidents[1].status == "In Progress"