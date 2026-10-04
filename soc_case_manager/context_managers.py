from .models import Incident


class IncidentInvestigationContext:
    """
    Context Manager המנהל חקירת תיק:
    מעביר זמנית את הסטטוס ל-'In Progress' בעת הכניסה.
    ביציאה, אם מתרחשת שגיאה - מחזיר את הסטטוס לקדמותו כדי לא להשאיר את המערכת במצב לא אמין.
    """

    def __init__(self, incident: Incident):
        self.incident = incident
        self.original_status = incident.status

    def __enter__(self):
        self.original_status = self.incident.status
        print(f"[Context Manager] מתחיל חקירה לתיק {self.incident.incident_id}. סטטוס שונה זמנית ל-In Progress.")
        self.incident.status = "In Progress"
        return self.incident

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is not None:
            print(f"[Context Manager] חריגה זוהתה: {exc_type.__name__}. מחזיר סטטוס ל-{self.original_status}.")
            self.incident.status = self.original_status
        else:
            print(f"[Context Manager] החקירה הסתיימה בהצלחה. הסטטוס נשאר: {self.incident.status}.")

        # החזרת False גורמת לכך שהחריגה תמשיך לבעבע החוצה (לא מוסתרת), כנדרש בהוראות.
        return False
