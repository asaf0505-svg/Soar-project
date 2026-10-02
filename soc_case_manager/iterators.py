from typing import List, Iterator, Iterable
from .models import Incident


# --- 1. Iterable ו-Iterator מותאמים אישית ---

class IncidentIterator(Iterator):
    """
    מחלקת Iterator שומרת את מצב המעבר על האוסף.
    מממשת את __iter__ ו-__next__ וזורקת StopIteration בסיום.
    """

    def __init__(self, incidents: List[Incident]):
        self._incidents = incidents
        self._index = 0

    def __iter__(self):
        return self

    def __next__(self) -> Incident:
        if self._index >= len(self._incidents):
            raise StopIteration

        incident = self._incidents[self._index]
        self._index += 1
        return incident


class IncidentCollection(Iterable):
    """
    מחלקת אוסף (Iterable) ששומרת את הנתונים עצמם.
    """

    def __init__(self):
        self._incidents: List[Incident] = []

    def add_incident(self, incident: Incident):
        self._incidents.append(incident)

    def __iter__(self) -> IncidentIterator:
        # כל קריאה ל-iter מחזירה Iterator חדש, מה שמאפשר כמה מעברים עצמאיים במקביל
        return IncidentIterator(self._incidents)


# --- 2. Generator עם yield ---

def generate_open_incidents(incidents: List[Incident]):
    """
    פונקציית Generator שמחזירה בהדרגה רק תיקי חקירה שעומדים בתנאי עסקי (סטטוס פתוח).
    השימוש ב-yield אומר שהפונקציה לא מחשבת את הכל מראש, אלא 'משהה' את עצמה
    עד שמבקשים את הפריט הבא.
    """
    for inc in incidents:
        if inc.status == "Open":
            yield inc


# --- 3. Generator Expression וצינור עיבוד עצל (Lazy Pipeline) ---

def create_lazy_pipeline(incidents: List[Incident]):
    """
    צינור עיבוד עצל בעל 3 שלבים (ללא יצירת רשימות ביניים):
    1. סינון ראשון: תיקים ברמת חומרה קריטית בלבד.
    2. סינון נוסף: רק תיקים שנמצאים בסטטוס "In Progress".
    3. החזרת שדה מסכם: מזהה התיק בלבד.
    """

    # שלב 1: סינון לפי תנאי ראשון
    critical_incidents = (inc for inc in incidents if inc.severity == "Critical")

    # שלב 2: סינון נוסף / המרה נוספת
    in_progress_criticals = (inc for inc in critical_incidents if inc.status == "In Progress")

    # שלב 3: החזרת שדה מזהה (Generator Expression)
    incident_ids_pipeline = (inc.incident_id for inc in in_progress_criticals)

    return incident_ids_pipeline