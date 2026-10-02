import os
from soc_case_manager.repository import load_incidents
from soc_case_manager.processing import IncidentProcessor
from soc_case_manager.iterators import IncidentCollection, create_lazy_pipeline
from soc_case_manager.context_managers import IncidentInvestigationContext
from soc_case_manager.models import InvestigationAction, NetworkEvent


def main():
    print("=== SOC Case Manager - תרחיש הדגמה ===")

    # --- 1. טעינת נתונים והמרה לאובייקטים ---
    file_path = os.path.join("data", "sample_data.jsonl")
    print(f"\n--- 1. טעינת נתונים הדרגתית מהקובץ: {file_path} ---")
    incidents = load_incidents(file_path)
    print(f"נטענו {len(incidents)} תיקים בהצלחה.")

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

    # --- 4. איטרטורים וגנרטורים ---
    print("\n--- 4. איטרטורים וצינור עיבוד עצל (Lazy Pipeline) ---")
    collection = IncidentCollection()
    for inc in incidents[:3]:
        collection.add_incident(inc)

    iter1 = iter(collection)
    iter2 = iter(collection)
    print(f"איטרטור 1 מתקדם: {next(iter1).incident_id}")
    print(f"איטרטור 2 מתקדם (עצמאי לחלוטין): {next(iter2).incident_id}")
    print(f"איטרטור 1 מתקדם שוב: {next(iter1).incident_id}")

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

    print("\n=== סיום ההדגמה ===")


if __name__ == "__main__":
    main()