from abc import ABC, abstractmethod
from datetime import datetime
from typing import List, Dict


def _require_record(data):
    if not isinstance(data, dict):
        raise ValueError("Record must be a JSON object")


def _required_text(value, field):
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a non-empty string")
    return value.strip()


class SecurityEvent(ABC):
    """מחלקה אבסטרקטית המייצגת אירוע אבטחה בסיסי"""

    def __init__(self, event_id: str, timestamp: str, source: str):
        self.event_id = event_id
        # נשמור כמחרוזת בשביל הפשטות של הטעינה מה-JSON, או נמיר ל-datetime
        self.timestamp = timestamp
        self.source = source

    @abstractmethod
    def get_risk_level(self) -> int:
        pass

    def __str__(self):
        return f"Event {self.event_id} from {self.source}"

    def __repr__(self):
        return f"<{self.__class__.__name__} id={self.event_id}>"


class NetworkEvent(SecurityEvent):
    """אירוע רשתי (יורש מ-SecurityEvent)"""

    def __init__(self, event_id: str, timestamp: str, source: str, suspicious_ip: str, port: int):
        super().__init__(event_id, timestamp, source)
        self.suspicious_ip = suspicious_ip
        self.port = port

    @classmethod
    def from_dict(cls, data):
        _require_record(data)
        return cls(data['event_id'], data['timestamp'], data['source'], data['suspicious_ip'], data['port'])

    def get_risk_level(self) -> int:
        # פולימורפיזם: אירועי רשת מקבלים ציון סיכון שונה בהתאם לפורט
        if self.port in [22, 3389]:  # SSH או RDP
            return 8
        return 4


class EndpointEvent(SecurityEvent):
    """אירוע תחנת קצה (יורש מ-SecurityEvent)"""

    def __init__(self, event_id: str, timestamp: str, source: str, malware_signature: str):
        super().__init__(event_id, timestamp, source)
        self.malware_signature = malware_signature

    @classmethod
    def from_dict(cls, data):
        _require_record(data)
        return cls(data['event_id'], data['timestamp'], data['source'], data['malware_signature'])

    def get_risk_level(self) -> int:
        # פולימורפיזם: נוזקה בתחנת קצה היא ברמת סיכון גבוהה
        return 9


class InvestigationAction:
    """פעולת חקירה שבוצעה על ידי אנליסט"""

    def __init__(self, action_id: str, description: str, analyst_name: str):
        self.action_id = action_id
        self.description = description
        self.analyst_name = analyst_name
        self.action_time = datetime.now()

    @classmethod
    def from_dict(cls, data):
        _require_record(data)
        return cls(data['action_id'], data['description'], data['analyst_name'])

    def __str__(self):
        return f"[{self.action_time.strftime('%Y-%m-%d %H:%M')}] {self.analyst_name}: {self.description}"

    def __repr__(self):
        return f"<InvestigationAction id={self.action_id}>"


class Incident:
    """תיק חקירה המאגד אירועים ופעולות (הרכבה/הכלה)"""

    VALID_STATUSES = {"Open", "In Progress", "Closed"}
    VALID_SEVERITIES = {"Low", "Medium", "High", "Critical"}
    SEVERITY_SCORES = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}

    def __init__(self, incident_id: str, title: str, severity: str):
        self.incident_id = _required_text(incident_id, 'incident_id')
        self.title = _required_text(title, 'title')

        # אתחול דרך ה-Setters כדי להפעיל את הולידציה
        self._severity = None
        self.severity = severity
        self._status = "Open"

        # הרכבה: התיק מכיל אוספים של פעולות ואירועים
        self.actions: List[InvestigationAction] = []
        self.events: List[SecurityEvent] = []

    @property
    def status(self) -> str:
        return self._status

    @status.setter
    def status(self, new_status: str):
        if not isinstance(new_status, str) or new_status not in self.VALID_STATUSES:
            raise ValueError(f"Invalid status '{new_status}'. Must be one of: {self.VALID_STATUSES}")
        self._status = new_status

    @property
    def severity(self) -> str:
        return self._severity

    @severity.setter
    def severity(self, new_severity: str):
        if not isinstance(new_severity, str) or new_severity not in self.VALID_SEVERITIES:
            raise ValueError(f"Invalid severity '{new_severity}'. Must be one of: {self.VALID_SEVERITIES}")
        self._severity = new_severity

    # --- פעולות על האוספים (הרכבה) ---

    def add_action(self, action: InvestigationAction):
        self.actions.append(action)

    def add_event(self, event: SecurityEvent):
        self.events.append(event)

    def get_actions_by_analyst(self, analyst_name: str) -> List[InvestigationAction]:
        """חיפוש באוסף הפריטים"""
        return [action for action in self.actions if action.analyst_name == analyst_name]

    def calculate_total_risk(self) -> int:
        """
        חישוב נתון מסכם תוך שימוש בפולימורפיזם:
        אנו קוראים ל-get_risk_level ללא צורך לדעת אם זה NetworkEvent או EndpointEvent
        """
        return sum(event.get_risk_level() for event in self.events)

    @classmethod
    def from_dict(cls, data: Dict) -> 'Incident':
        """בנאי אלטרנטיבי ליצירת אובייקט ממילון (לקראת טעינת ה-JSON)"""
        _require_record(data)
        incident = cls(
            incident_id=data['id'],
            title=data['title'],
            severity=data['severity']
        )
        if 'status' in data:
            incident.status = data['status']
        return incident

    def __lt__(self, other: 'Incident') -> bool:
        """
        השוואה בין תיקים לצורך תור עדיפויות בהמשך.
        תיק 'קטן' יותר (שייצא ראשון מהתור) הוא תיק עם חומרה *גבוהה* יותר.
        """
        if self.SEVERITY_SCORES[self.severity] == self.SEVERITY_SCORES[other.severity]:
            # שובר שוויון: אם החומרה זהה, נמיין לפי המזהה
            return self.incident_id < other.incident_id

        return self.SEVERITY_SCORES[self.severity] > self.SEVERITY_SCORES[other.severity]

    def __str__(self):
        return f"Incident {self.incident_id}: {self.title} [Severity: {self.severity}, Status: {self.status}]"

    def __repr__(self):
        return f"<Incident id={self.incident_id} severity={self.severity} status={self.status}>"

class Task:
    """משימת המשך כחלק מתוכנית טיפול (הרחבה ל-4 סטודנטים)"""
    def __init__(self, task_id: str, description: str, assigned_team: str):
        self.task_id = _required_text(task_id, 'task_id')
        self.description = _required_text(description, 'description')
        self.assigned_team = _required_text(assigned_team, 'assigned_team')
        self.is_completed = False

    @classmethod
    def from_dict(cls, data):
        _require_record(data)
        return cls(data['task_id'], data['description'], data['assigned_team'])

    def mark_completed(self):
        self.is_completed = True

    def __str__(self):
        status = "Done" if self.is_completed else "Pending"
        return f"Task {self.task_id} [{self.assigned_team}]: {self.description} ({status})"

    def __repr__(self):
        return f"<Task id={self.task_id} completed={self.is_completed}>"


class RemediationPlan:
    """תוכנית טיפול המאגדת משימות המשך (הרחבה ל-4 סטודנטים)"""
    def __init__(self, plan_id: str, incident_id: str):
        self.plan_id = _required_text(plan_id, 'plan_id')
        self.incident_id = _required_text(incident_id, 'incident_id')
        # הרכבה: תוכנית מכילה רשימת משימות
        self.tasks: List[Task] = []

    @classmethod
    def from_dict(cls, data):
        _require_record(data)
        plan = cls(data['plan_id'], data['incident_id'])
        for task_data in data.get('tasks', []):
            plan.add_task(Task.from_dict(task_data))
        return plan

    def __repr__(self):
        return f"<RemediationPlan id={self.plan_id} incident={self.incident_id} tasks={len(self.tasks)}>"

    def add_task(self, task: Task):
        self.tasks.append(task)

    def get_open_tasks(self) -> List[Task]:
        """מחזיר רק משימות שטרם הושלמו"""
        return [task for task in self.tasks if not task.is_completed]

    def __str__(self):
        return f"Remediation Plan {self.plan_id} for Incident {self.incident_id} ({len(self.tasks)} tasks)"
