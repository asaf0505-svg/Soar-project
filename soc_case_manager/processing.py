from collections import deque
from typing import List, Dict, Set, Tuple, Optional
import heapq
from .models import Incident

class IncidentProcessor:
    """מחלקה המרכזת את כל עיבוד האוספים ומבני הנתונים של המערכת"""

    def __init__(self):
        self.fifo_queue = deque()
        self.priority_queue = []
        self.incidents_by_id: Dict[str, Incident] = {}

    # --- 1. תור FIFO באמצעות deque ---
    def add_to_fifo(self, incident: Incident):
        """מוסיף תיק לתור טיפול לפי סדר הגעה"""
        self.fifo_queue.append(incident)

    def process_next_fifo(self) -> Optional[Incident]:
        """שולף את התיק הבא. מטפל במצב של תור ריק כדי למנוע קריסה"""
        if not self.fifo_queue:
            return None
        return self.fifo_queue.popleft()

    # --- 2. תור עדיפויות באמצעות heapq ---
    def add_to_priority(self, incident: Incident):
        """
        מוסיף לתור עדיפויות. הדחיפות קודמת לזמן ההגעה.
        המיון מתבסס על מתודת __lt__ שהגדרנו במחלקת Incident
        """
        heapq.heappush(self.priority_queue, incident)

    def process_next_priority(self) -> Optional[Incident]:
        if not self.priority_queue:
            return None
        return heapq.heappop(self.priority_queue)

    # --- 3. מילונים (dict) ---
    def build_index(self, incidents: List[Incident]):
        """
        Dict Comprehension ליצירת אינדקס לאיתור אובייקט לפי מזהה.
        החלטה: אם מזהה קיים, הוא יידרס על ידי הרשומה החדשה.
        """
        self.incidents_by_id = {inc.incident_id: inc for inc in incidents}

    def get_incident(self, incident_id: str) -> Optional[Incident]:
        """שימוש ב-get למצב צפוי שבו המפתח אינו קיים (ללא קריסה)"""
        return self.incidents_by_id.get(incident_id)

    def group_by_severity(self) -> Dict[str, int]:
        """מילון לקיבוץ וספירה של פריטים לפי רמת חומרה"""
        counts = {}
        for incident in self.incidents_by_id.values():
            # שימוש ב-get כדי לאתחל ערך אם המפתח לא קיים
            counts[incident.severity] = counts.get(incident.severity, 0) + 1
        return counts

    def display_severity_counts(self):
        """מעבר על items() תוך שימוש ב-unpacking"""
        counts = self.group_by_severity()
        for severity, count in counts.items():
            print(f"Severity: {severity} | Count: {count}")

    # --- 4. קבוצות (set) ---
    def get_unique_severities(self, incidents: List[Incident]) -> Set[str]:
        """Set Comprehension להפקת ערכים ייחודיים"""
        return {inc.severity for inc in incidents}

    def demonstrate_set_operations(self) -> Set[str]:
        """הדגמת פעולות על קבוצות לפי דרישות הפרויקט"""
        active_ids = {"INC-001", "INC-002"}
        active_ids.add("INC-003")  # הוספה
        active_ids.discard("INC-999")  # הסרה בטוחה שלא קורסת אם הערך חסר

        # איחוד קבוצות
        other_ids = {"INC-002", "INC-004"}
        all_ids = active_ids | other_ids
        return all_ids

    # --- 5. מיון, Comprehensions ו-Unpacking ---
    def filter_critical_incidents(self, incidents: List[Incident]) -> List[Incident]:
        """List Comprehension לסינון"""
        return [inc for inc in incidents if inc.severity == "Critical"]

    def sort_by_status_lambda(self, incidents: List[Incident]) -> List[Incident]:
        """מיון באמצעות lambda קצרה"""
        return sorted(incidents, key=lambda inc: inc.status)

    def sort_by_severity_and_id(self, incidents: List[Incident]) -> List[Incident]:
        """מיון לפי שני שדות באמצעות tuple. שימוש בפונקציה רגילה כ-key"""

        def sort_key(inc: Incident) -> Tuple[int, str]:
            # חומרה בסדר יורד (מספר גבוה יותר יופיע קודם), ואז לפי ID
            return (-Incident.SEVERITY_SCORES[inc.severity], inc.incident_id)

        return sorted(incidents, key=sort_key)

    def extract_first_and_rest(self, incidents: List[Incident]) -> Tuple[Optional[Incident], List[Incident]]:
        """שימוש ב-* כדי לאסוף ערכים שנותרו (Unpacking)"""
        if not incidents:
            return None, []
        first, *rest = incidents
        return first, rest