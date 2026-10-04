import os
from soc_case_manager.repository import load_incidents
from soc_case_manager.processing import IncidentProcessor
from soc_case_manager.iterators import IncidentCollection, create_lazy_pipeline, generate_open_incidents
from soc_case_manager.context_managers import IncidentInvestigationContext
from soc_case_manager.models import InvestigationAction, NetworkEvent, EndpointEvent
from soc_case_manager.reports import RemediationManager


def main():
    print("=== SOC Case Manager - תרחיש הדגמה ===")

    # --- 1. טעינת נתונים והמרה לאובייקטים ---
    file_path = os.path.join("data", "sample_data.jsonl")
    print(f"\n--- 1. טעינת נתונים הדרגתית (כולל ולידציה) ---")
    incidents = load_incidents(file_path)
    print(f"נטענו {len(incidents)} תיקים תקינים.")
    if not incidents:
        print("אין תיקים תקינים להדגמה.")
        return

    # --- 2. הדגמת OOP ---
    print("\n--- 2. מודל מונחה עצמים (OOP) ---")
    if incidents:
        first_incident = incidents[0]
        action = InvestigationAction(action_id="ACT-001", description="Initial IP block", analyst_name="Gal")
        first_incident.add_action(action)
        net_event = NetworkEvent(event_id="EV-100", timestamp="2026-09-28", source="Firewall",
                                 suspicious_ip="192.168.1.5", port=22)
        first_incident.add_event(net_event)
        first_incident.add_event(EndpointEvent("EV-101", "2026-09-28", "EDR", "DemoSignature"))
        print(f"התיק {first_incident.incident_id} עודכן. סיכון משוקלל: {first_incident.calculate_total_risk()}")

    # --- 3. עיבוד אוספים ומבני נתונים ---
    print("\n--- 3. עיבוד אוספים ומבני נתונים ---")
    processor = IncidentProcessor()
    processor.build_index(incidents)

    print("א. ספירה מתוך מילון:")
    processor.display_severity_counts()

    print("\nב. תור הגעה (FIFO) באמצעות deque:")
    for inc in incidents[:3]:
        processor.add_to_fifo(inc)
    while processor.fifo_queue:
        print(f"נשלף לפי סדר הגעה: {processor.process_next_fifo().incident_id}")
    print(f"שליפה מתור ריק: {processor.process_next_fifo()}")

    print("\nג. תור עדיפויות (heapq):")
    for inc in incidents[:5]:
        processor.add_to_priority(inc)
    print(f"נשלף ראשון (הכי דחוף): {processor.process_next_priority().incident_id}")

    print("\nד. פעולות על קבוצות (Set):")
    print(f"הדגמת איחוד והסרה: {sorted(processor.demonstrate_set_operations())}")
    print("רמות חומרה ייחודיות:", sorted(processor.get_unique_severities(incidents)))
    critical = processor.filter_critical_incidents(incidents)
    print("תיקים קריטיים:", [inc.incident_id for inc in critical])

    print("\nה. מיון באמצעות lambda ו-tuple:")
    status_sorted = processor.sort_by_status_lambda(incidents[:3])
    print(f"מיון לפי סטטוס: {[inc.incident_id for inc in status_sorted]}")
    multi_sorted = processor.sort_by_severity_and_id(incidents[:3])
    print(f"מיון חומרה ו-ID: {[inc.incident_id for inc in multi_sorted]}")
    first, rest = processor.extract_first_and_rest(incidents)
    incident_summary = (first.incident_id, first.severity)
    print(f"רשומת סיכום קבועה (tuple): {incident_summary}; יתר התיקים: {len(rest)}")

    # --- 4. איטרטורים וגנרטורים ---
    print("\n--- 4. איטרטורים וגנרטורים ---")
    collection = IncidentCollection()
    for inc in incidents[:3]:
        collection.add_incident(inc)
    iter1, iter2 = iter(collection), iter(collection)
    print(f"איטרטור 1: {next(iter1).incident_id}")
    print(f"איטרטור 2 עצמאי: {next(iter2).incident_id}")
    second = next(iter1, None)
    print(f"איטרטור 1 מתקדם שוב: {second.incident_id if second else 'הסתיים'}")

    print("א. גנרטור (yield) - המחשת next, לולאה, מיצוי ויצירה מחדש:")
    gen = generate_open_incidents(incidents)
    first_open = next(gen, None)
    print(f"קריאה ראשונה (next): {first_open.incident_id if first_open else 'אין תיקים פתוחים'}")
    for inc in gen:
        print(f"המשך המעבר (for): {inc.incident_id}")
        break  # מדגים חזרה ללולאה ועצירה

    list(gen)  # מיצוי הגנרטור
    try:
        next(gen)
    except StopIteration:
        print("הגנרטור מוצה ונזרקה שגיאת StopIteration כצפוי.")
    print("מעבר חוזר על הגנרטור שמוצה:", list(gen))
    gen_new = generate_open_incidents(incidents)
    print("נוצר גנרטור חדש למעבר חוזר:", [inc.incident_id for inc in gen_new])

    print("\nב. צינור עיבוד עצל (Lazy Pipeline):")
    pipeline = create_lazy_pipeline(incidents)
    print(f"תוצאה 1: {next(pipeline, 'אין תוצאות נוספות')}")
    print(f"תוצאה 2: {next(pipeline, 'אין תוצאות נוספות')}")

    # --- 5. Context Manager ---
    print("\n--- 5. Context Manager ---")
    test_incident = incidents[-1]
    print("תרחיש א': יציאה תקינה")
    with IncidentInvestigationContext(test_incident) as inc:
        inc.status = "Closed"
        print(f"החקירה הסתיימה: {inc.status}")
    print("תרחיש ב': יציאה עם חריגה")
    try:
        with IncidentInvestigationContext(test_incident) as inc:
            print("מנסה לבצע חקירה שמקריסה את התהליך...")
            raise RuntimeError("שגיאת שרת מדומה!")
    except RuntimeError:
        print(f"החריגה נתפסה. חזר לסטטוס קודם: {test_incident.status}")

    # --- 6. תת-מערכת למשימות מנע (הרחבה) ---
    print("\n--- 6. תת-מערכת למשימות מנע (הרחבה ל-4 סטודנטים) ---")
    remediation_manager = RemediationManager(processor)
    tasks_file = os.path.join("data", "remediation_tasks.jsonl")
    remediation_manager.load_tasks(tasks_file)

    for plan in remediation_manager.plans.values():
        print(f"תוכנית: {plan}; תיק מקושר: {processor.get_incident(plan.incident_id)}")
        for task in plan.get_open_tasks():
            print(f"  {task}")
    print("דוח לפני השלמת משימה:")
    remediation_manager.display_report()

    # הדגמת תהליך עסקי: טיפול במשימה ושינוי הדוח
    plan = next(iter(remediation_manager.plans.values()), None)
    if plan and plan.tasks:
        print(f"\n>> מבצע פעולה עסקית: סגירת המשימה {plan.tasks[0].task_id} בצוות {plan.tasks[0].assigned_team}...")
        plan.tasks[0].mark_completed()
        print(f"אחרי טיפול: {plan.tasks[0]}")
        print(">> דוח אחרי השלמת משימה:")
        remediation_manager.display_report()

    print("\n=== סיום ההדגמה ===")


if __name__ == "__main__":
    main()
