import json
from typing import List
from .models import Incident


def load_incidents(file_path: str) -> List[Incident]:
    """
    טוען תיקי חקירה מקובץ JSONL בצורה הדרגתית.
    מדלג על שורות ריקות או רשומות לא חוקיות.
    """
    incidents = []
    seen_ids = set()

    # שימוש ב-with open לפי הדרישות לפתיחה בטוחה של הקובץ
    with open(file_path, 'r', encoding='utf-8') as file:
        for line_num, line in enumerate(file, 1):
            line = line.strip()
            if not line:
                continue

            try:
                # המרה למילון
                data = json.loads(line)
                # שימוש בבנאי החלופי שיצרנו
                incident = Incident.from_dict(data)
                if incident.incident_id in seen_ids:
                    raise ValueError(f"Duplicate incident ID: {incident.incident_id}; keeping first record")
                seen_ids.add(incident.incident_id)
                incidents.append(incident)

            except json.JSONDecodeError:
                print(f"Warning: Line {line_num} is not a valid JSON. Skipping.")
            except KeyError as e:
                print(f"Warning: Line {line_num} is missing required field {e}. Skipping.")
            except ValueError as e:
                print(f"Warning: Line {line_num} has invalid data ({e}). Skipping.")

    return incidents
