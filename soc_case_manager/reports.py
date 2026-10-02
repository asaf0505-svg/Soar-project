import json
from typing import List, Dict
from .models import Task, RemediationPlan, Incident
from .processing import IncidentProcessor


class RemediationManager:
    """מנהל את תת-המערכת של תוכניות הטיפול והמשימות (הרחבה ל-4 סטודנטים)"""

    def __init__(self, incident_processor: IncidentProcessor):
        # המערכת מקבלת רפרנס למערכת התיקים המרכזית כדי לבדוק קשרים
        self.processor = incident_processor
        self.plans: Dict[str, RemediationPlan] = {}

    def load_tasks(self, file_path: str):
        """טוען משימות מקובץ, מוודא קשר לתיק קיים ובונה תוכניות טיפול"""
        with open(file_path, 'r', encoding='utf-8') as file:
            for line_num, line in enumerate(file, 1):
                line = line.strip()
                if not line:
                    continue

                try:
                    data = json.loads(line)
                    task_id = str(data['task_id'])
                    incident_id = str(data['incident_id'])
                    description = str(data['description'])
                    assigned_team = str(data['assigned_team'])

                    # --- בדיקת קשרים ממשיים בין נתונים ---
                    if not self.processor.get_incident(incident_id):
                        print(f"[Warning] Task {task_id} skipped: Linked Incident {incident_id} does not exist.")
                        continue

                    # יצירת המשימה
                    task = Task(task_id, description, assigned_team)

                    # יצירה או עדכון של תוכנית הטיפול עבור התיק
                    plan_id = f"RP-{incident_id}"
                    if plan_id not in self.plans:
                        self.plans[plan_id] = RemediationPlan(plan_id, incident_id)

                    self.plans[plan_id].add_task(task)

                except (json.JSONDecodeError, KeyError, ValueError) as e:
                    print(f"Error reading task line {line_num}: {e}")

    def generate_open_tasks_report(self) -> Dict[str, int]:
        """
        דוח עסקי: סיכום פעילות ומשימות פתוחות לפי צוות.
        כלי תומך החלטה לזיהוי עומס בצוותי ה-IT השונים.
        """
        team_load = {}
        for plan in self.plans.values():
            for task in plan.get_open_tasks():
                team_load[task.assigned_team] = team_load.get(task.assigned_team, 0) + 1

        return team_load

    def display_report(self):
        """הדפסה קריאה של הדוח העסקי"""
        print("\n--- דוח מנהלים: עומס משימות מנע פתוחות לפי צוות ---")
        report_data = self.generate_open_tasks_report()

        if not report_data:
            print("אין משימות פתוחות כרגע. הכל מטופל!")
            return

        # מיון הצוותים לפי כמות המשימות (מהעמוס ביותר לפנוי ביותר)
        sorted_teams = sorted(report_data.items(), key=lambda x: x[1], reverse=True)
        for team, count in sorted_teams:
            print(f"צוות: {team.ljust(10)} | משימות פתוחות: {count}")
        print("--------------------------------------------------")