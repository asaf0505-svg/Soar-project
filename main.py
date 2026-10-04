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
    print(f"\n--- 1. טעינת נתונים הדרגתית מהקובץ: {file_path} ---")
    incidents = load_incidents(file_path)
    print(f"נטענו {len(incidents)} תיקים בהצלחה.")
    if not incidents:
        print("אין תיקים תקינים להדגמה.")
        return

    # --- 2. הדגמת OOP (הרכבה, פולימורפיזם) ---
    print("\n--- 2. מודל מונחה עצמים (OOP) ---")
    if incidents:
        first_incident = incidents[0]
        # הוספת פעולת חקירה (הרכבה)
        action = InvestigationAction(action_id="ACT-001", description="Initial IP block", analyst_name="Gal")
        first_incident.add_action(action)
        # הוספת אירוע רשת לחשב סיכון (פולימורפיזם)
        net_event = NetworkEvent(event_id="EV-100", timestamp="2026-09-28", source="Firewall",
                                 suspicious_ip="192.168.1.5", port=22)
        first_incident.add_event(net_event)
        first_incident.add_event(EndpointEvent("EV-101", "2026-09-28", "EDR", "DemoSignature"))

        print(f"התיק {first_incident.incident_id} עודכן עם פעולות.")
        print(f"סיכון כולל מחושב מתוך האירועים (Polymorphism): {first_incident.calculate_total_risk()}")

    # --- 3. עיבוד אוספים ומבני נתונים ---
    print("\n--- 3. עיבוד אוספים (מילונים ותור עדיפויות) ---")
    processor = IncidentProcessor()
    processor.build_index(incidents)

    print("ספירת תיקים לפי חומרה (Dict & Unpacking):")
    processor.display_severity_counts()

    print("\nהכנסת 5 תיקים לתור עדיפויות (heapq) ושליפת הדחוף ביותר:")
    for inc in incidents[:5]:
        processor.add_to_priority(inc)

    top_priority = processor.process_next_priority()
    print(f"התיק הדחוף ביותר שנשלף: {top_priority}")

    print("\nFIFO: טיפול בשלושה תיקים לפי סדר הגעתם, בלי לדלג על תיק ותיק:")
    for inc in incidents[:3]:
        processor.add_to_fifo(inc)
    while processor.fifo_queue:
        print(processor.process_next_fifo())
    print(f"שליפה מתור ריק: {processor.process_next_fifo()}")

    print("רמות חומרה ייחודיות:", sorted(processor.get_unique_severities(incidents)))
    print("הוספה, הסרה ואיחוד קבוצות:", sorted(processor.demonstrate_set_operations()))
    critical = processor.filter_critical_incidents(incidents)
    print("תיקים קריטיים (list comprehension):", [inc.incident_id for inc in critical])
    print("מיון לפי סטטוס (lambda):", [inc.incident_id for inc in processor.sort_by_status_lambda(incidents)])
    print("מיון לפי חומרה ומזהה:", [inc.incident_id for inc in processor.sort_by_severity_and_id(incidents)])
    first, rest = processor.extract_first_and_rest(incidents)
    incident_summary = (first.incident_id, first.severity)
    print(f"רשומת סיכום קבועה (tuple): {incident_summary}; יתר התיקים: {len(rest)}")
    print("איתור לפי מזהה:", processor.get_incident(first.incident_id))

    # --- 4. איטרטורים וגנרטורים ---
    print("\n--- 4. איטרטורים וצינור עיבוד עצל (Lazy Pipeline) ---")
    collection = IncidentCollection()
    for inc in incidents[:3]:
        collection.add_incident(inc)

    iter1 = iter(collection)
    iter2 = iter(collection)
    print(f"איטרטור 1 מתקדם: {next(iter1).incident_id}")
    print(f"איטרטור 2 מתקדם (עצמאי לחלוטין): {next(iter2).incident_id}")
    second = next(iter1, None)
    print(f"איטרטור 1 מתקדם שוב: {second.incident_id if second else 'הסתיים'}")

    print("\nGenerator עם yield: יצירה ללא עיבוד, next ואז המשך באותו מעבר:")
    open_incidents = generate_open_incidents(incidents)
    first_open = next(open_incidents, None)
    print(f"תוצאה ראשונה: {first_open}")
    for inc in open_incidents:
        print(f"המשך מאותה נקודה: {inc.incident_id}")
    print("מעבר חוזר על הגנרטור שמוצה:", list(open_incidents))
    print("מעבר חדש מההתחלה:", [inc.incident_id for inc in generate_open_incidents(incidents)])

    print("\nצינור עיבוד עצל - צורך רק שתי תוצאות ועוצר:")
    pipeline = create_lazy_pipeline(incidents)
    try:
        print(f"תוצאה 1 מצינור העיבוד: {next(pipeline)}")
        print(f"תוצאה 2 מצינור העיבוד: {next(pipeline)}")
    except StopIteration:
        print("אין יותר תוצאות בצינור.")

    # --- 5. Context Manager ---
    print("\n--- 5. Context Manager ---")
    test_incident = incidents[-1]
    print("תרחיש א': יציאה תקינה")
    with IncidentInvestigationContext(test_incident) as inc:
        inc.status = "Closed"
        print("החקירה מתבצעת כסדרה...")

    print("\nתרחיש ב': יציאה עם חריגה (התרסקות מדומה)")
    try:
        with IncidentInvestigationContext(test_incident) as inc:
            print("מנסה לבצע חקירה שמקריסה את התהליך...")
            raise RuntimeError("שגיאת שרת פתאומית!")
    except RuntimeError as e:
        print(f"החריגה נתפסה מחוץ ל-Context Manager: {e}")
        print(f"בדיקת הסטטוס לאחר הקריסה: {test_incident.status}")

    # --- 6. הרחבה לרביעייה: תוכניות טיפול ומשימות ---
    print("\n--- 6. תוכניות טיפול ומשימות מנע ---")
    remediation = RemediationManager(processor)
    remediation.load_tasks(os.path.join("data", "remediation_tasks.jsonl"))
    for plan in remediation.plans.values():
        print(f"תוכנית: {plan}; תיק מקושר: {processor.get_incident(plan.incident_id)}")
        for task in plan.get_open_tasks():
            print(f"  {task}")

    print("\nדוח לפני השלמת משימה:")
    remediation.display_report()
    for plan in remediation.plans.values():
        open_tasks = plan.get_open_tasks()
        if open_tasks:
            task = open_tasks[0]
            print(f"לפני טיפול: {task}")
            task.mark_completed()
            print(f"אחרי טיפול: {task}")
            print(f"נותרו בתוכנית {len(plan.get_open_tasks())} משימות פתוחות.")
            break
    print("\nדוח אחרי השלמת משימה:")
    remediation.display_report()

    print("\n=== סיום ההדגמה ===")


if __name__ == "__main__":
    main()
