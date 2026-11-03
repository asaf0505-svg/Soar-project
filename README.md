# SOC Case Manager

מערכת מקומית לניהול, תיעוד ותעדוף תיקי חקירה של אירועי אבטחת מידע.

הפרויקט נבנה במסגרת קורס **תכנות מתקדם** ומדגים OOP, מבני נתונים, Iterators ו־Generators, Context Managers, שירות חיצוני, Design Patterns, בדיקות ו־TDD, Async, Threads וסנכרון.

## מטרת המערכת

צוות SOC מטפל במספר רב של אירועי אבטחה במקביל. מטרת המערכת היא לרכז את המידע והפעולות סביב Incident אחד, לאפשר תיעוד מסודר של החקירה, לתעדף תיקים ולנהל משימות המשך.

המערכת אינה מבצעת חקירת סייבר או containment אוטומטי. היא מספקת מידע ותהליך עבודה שתומכים בהחלטת האנליסט.

### משתמשים מרכזיים

- **SOC Analyst** — מנהל Incident, מתעד פעולות ומבצע בדיקות Enrichment.
- **SOC Lead** — בוחן תיקים דחופים ועומס משימות.
- **Remediation / IT Teams** — מטפלים במשימות המשך שנוצרו עבור Incident.

---

# שלב 1

## מודל המערכת

הישות המרכזית היא `Incident`.

Incident מכיל:

- אירועי אבטחה (`SecurityEvent`).
- פעולות חקירה (`InvestigationAction`).
- Severity ו־Status.
- אנליסט משויך.
- סיכום טיפול בעת סגירת התיק.

`SecurityEvent` היא מחלקת בסיס אבסטרקטית שממנה יורשים:

- `NetworkEvent`
- `EndpointEvent`

כל סוג Event מממש בעצמו את `get_risk_level()`, ולכן `Incident.calculate_total_risk()` יכול לחשב את הסיכון הכולל באמצעות פולימורפיזם ללא בדיקת סוג האובייקט.

בנוסף קיימת תת־מערכת Remediation הכוללת:

- `RemediationPlan`
- `Task`

כל תוכנית טיפול מקושרת ל־Incident ויכולה להכיל מספר משימות המשויכות לצוותים שונים.

---

## נתוני הדגמה

הנתונים נמצאים בתיקיית `data/`.

### `data/sample_data.jsonl`

מכיל 15 Incidents סינתטיים.

כל רשומה כוללת:

- `id`
- `title`
- `severity`
- `status`

### `data/remediation_tasks.jsonl`

מכיל משימות Remediation המקושרות ל־Incident באמצעות `incident_id`.

הרשומה `T-106` מפנה בכוונה ל־`INC-999`, שאינו קיים, כדי להדגים Validation של קשר לא תקין בין הישויות.

אין בפרויקט מידע אישי אמיתי.

---

## OOP

### הורשה ופולימורפיזם

`SecurityEvent` היא מחלקה אבסטרקטית.

`NetworkEvent` ו־`EndpointEvent` יורשות ממנה ומממשות באופן שונה:

`get_risk_level()`

`Incident.calculate_total_risk()` מפעיל את המתודה על כל Event בלי לדעת מה הסוג הספציפי שלו.

### Composition

`Incident` מחזיק אוספים של:

- `SecurityEvent`
- `InvestigationAction`

`RemediationPlan` מחזיק אוסף של `Task`.

---

## מבני נתונים

| צורך | מבנה | שימוש בפרויקט |
|---|---|---|
| שמירת אירועים ופעולות | `list` | אוספים בתוך Incident |
| טיפול לפי סדר הגעה | `deque` | FIFO Queue |
| טיפול לפי חומרה | `heapq` | Priority Queue |
| איתור Incident לפי ID | `dict` | אינדקס ב־`IncidentProcessor` |
| שמירת ערכים ייחודיים | `set` | לדוגמה Severity ייחודי |
| רשומת סיכום קבועה | `tuple` | מזהה + Severity |

המימוש המרכזי נמצא ב־`soc_case_manager/processing.py`.

---

## Iterators, Generators ו־Lazy Processing

ב־`soc_case_manager/iterators.py` קיימים:

### Iterator מותאם

- `IncidentCollection`
- `IncidentIterator`

`IncidentIterator` מממש `__iter__()` ו־`__next__()`, וכל קריאה ל־`iter()` יוצרת Iterator עצמאי.

### Generator

`generate_open_incidents()` משתמש ב־`yield` ומחזיר Incidents פתוחים אחד בכל פעם.

### Lazy Pipeline

`create_lazy_pipeline()` מבצע שלושה שלבים ללא יצירת רשימות ביניים:

1. סינון Incidents מסוג Critical.
2. סינון Incidents שנמצאים ב־`In Progress`.
3. החזרת `incident_id`.

---

## Context Manager

ב־`soc_case_manager/context_managers.py` מומש:

`IncidentInvestigationContext`

בכניסה לחקירה ה־Incident עובר זמנית ל־`In Progress`.

אם מתרחשת חריגה במהלך החקירה, `__exit__()` מחזיר את ה־Status שהיה לפני הכניסה, והחריגה ממשיכה החוצה לטיפול נוסף.

---

# שלב 2

## 1. הרחבה עסקית

בשלב 2 הורחב התהליך העסקי כך ש־`NetworkEvent` המקושר ל־Incident יכול לעבור בדיקת Reputation של כתובת IP מול שירות חיצוני אמיתי — **AbuseIPDB**.

זרימת המידע המרכזית:

```text
Incident
    ↓
NetworkEvent
    ↓
AbuseIPDB
    ↓
IPReputation
    ↓
ReputationService
    ↓
Risk Strategy
    ↓
Low Risk / High Risk
```

אם מתקבלת החלטת High Risk:

```text
HighRiskDetected
      ↓
Observer
      ↓
Remediation Review Task + Audit
```

המידע החיצוני משמש לקבלת החלטה עסקית ואינו מוצג בלבד.

המערכת אינה:

- חוסמת IP אוטומטית.
- משנה Severity אוטומטית.
- סוגרת Incident אוטומטית.

במקרה של כשל בשירות החיצוני, המערכת אינה יוצרת החלטת סיכון או משימת טיפול על בסיס מידע שלא התקבל.

---

## 2. שירות חיצוני — AbuseIPDB

התקשורת עם AbuseIPDB נמצאת ב־:

`soc_case_manager/api_client.py`

הלקוח מבצע:

- בקשת HTTP `GET`.
- שליחת Parameters.
- שימוש ב־`timeout`.
- `raise_for_status()`.
- פענוח JSON.
- אימות מבנה ושדות.
- אימות שה־IP שהוחזר הוא ה־IP שהתבקש.
- אימות ש־`abuseConfidenceScore` הוא מספר בין 0 ל־100.
- המרת התוצאה ל־`IPReputation`.

בנוסף נשמר Metadata כגון:

- Whitelist status.
- Total reports.
- Distinct reporters.
- ISP.
- Usage type.
- Domain.
- Country.
- Tor status.
- Last reported time.

### טיפול בכשלים

המערכת מבחינה בין:

- Timeout / Connection Error.
- HTTP Error.
- JSON לא תקין.
- נתונים לא תקינים.

רק `Timeout` ו־`ConnectionError` מקבלים Retry אוטומטי, עד **3 ניסיונות בסך הכול**.

HTTP Error או מידע לא תקין אינם מקבלים Retry אוטומטי.

---

## 3. הפרדת תקשורת מהלוגיקה העסקית

התקשורת החיצונית נמצאת ב־`api_client.py`.

הלוגיקה העסקית נמצאת ב־`services.py`.

`AbuseIPDBClient` אחראי להשגת המידע ולאימותו.

`ReputationService` אחראי להחליט מה לעשות עם המידע שכבר התקבל ונבדק.

הפרדה זו מאפשרת:

- להחליף שירות חיצוני בלי לשכתב את הלוגיקה העסקית.
- לבדוק את הלוגיקה באמצעות Mock.
- לשמור על אחריות ברורה לכל רכיב.

---

## 4. Design Patterns

### Strategy

מיקום:

`soc_case_manager/strategies.py`

ה־Strategy קובעת איזה Abuse Confidence Score דורש Review.

קיימות שתי אסטרטגיות:

- `ThresholdRiskStrategy`
- `StrictRiskStrategy`

ברירת המחדל של `ThresholdRiskStrategy` היא סף 80.

ברירת המחדל של `StrictRiskStrategy` היא סף 60.

כך ניתן לשנות את מדיניות הסיכון בלי לשנות את `ReputationService`.

### Observer

מיקום:

`soc_case_manager/observers.py`

כאשר מתקבלת החלטת High Risk נוצר:

`HighRiskDetected`

ה־`HighRiskPublisher` מודיע למספר Observers:

- `ReviewTaskObserver` — יוצר או פותח מחדש משימת Review.
- `RiskAuditObserver` — שומר את אירוע הסיכון לצורך Audit ודיווח.

Observer אינו מנגנון מקביליות. מטרתו לאפשר למספר רכיבים להגיב לאותו Event בלי ליצור תלות חזקה ביניהם.

---

## 5. Dependency Injection

`ReputationService` מקבל מבחוץ את התלויות המרכזיות שלו:

- API Client.
- Risk Strategy.
- Publisher / Observers.
- Remediation Manager.

כך ניתן, לדוגמה, להעביר Client מדומה בבדיקות במקום לבצע קריאת רשת אמיתית.

---

## 6. שילוב עם NetworkEvent ו־Remediation

בדיקת Reputation אינה מתבצעת על IP מנותק מהמערכת.

המתודה:

`ReputationService.evaluate_network_event()`

בודקת:

1. שה־Incident קיים.
2. שהאובייקט הוא `NetworkEvent`.
3. שה־NetworkEvent באמת שייך לאותו Incident.
4. רק לאחר מכן משתמשת ב־`event.suspicious_ip`.

כאשר מתקבלת החלטת High Risk, `ReviewTaskObserver` יוצר או פותח מחדש:

`IP-REVIEW-<incident_id>`

בתוך:

`RP-<incident_id>`

כלומר המידע החיצוני משפיע בפועל על תת־מערכת ה־Remediation.

אם השירות החיצוני נכשל, לא נוצרת משימת Review על בסיס מידע שלא התקבל.

---

## 7. תהליך Incident

בשלב 2 נוספו פעולות עסקיות מפורשות:

- `assign_to()`
- `transfer_to()`
- `close()`

### Assign

Incident פנוי יכול להיות משויך לאנליסט.

### Transfer

Incident שכבר משויך יכול לעבור לאנליסט אחר.

### Close

סגירת Incident דורשת `resolution_summary`.

לא ניתן לסגור תיק עם סיכום טיפול ריק.

---

## 8. Async

מיקום:

`soc_case_manager/async_processing.py`

מומשות לפחות שלוש בדיקות עצמאיות מדומות.

אותם נתונים מורצים בשתי דרכים:

- Sequential.
- Concurrent.

בגרסה המקבילית משתמשים ב־:

- `asyncio.create_task()`
- `asyncio.gather()`

המשימות יכולות להסתיים בזמנים שונים, אך התוצאות מוחזרות לפי סדר הקלט.

---

## 9. Threads ו־Lock

מיקום:

`soc_case_manager/threaded_processing.py`

התרחיש מדמה שני Analysts שמנסים לבצע Claim לאותו Incident באותו זמן.

המשאב המשותף הוא מילון `assignments`.

אותו `threading.Lock()` מגן על פעולת:

```text
Check → Update
```

לכן רק Analyst אחד יכול לקבל את אותו Incident.

הבדיקה אינה מניחה איזה Thread ינצח — רק שבסיום קיימת הקצאה אחת תקינה.

---

## 10. הדוח העסקי המשולב

מיקום:

`soc_case_manager/integrated_reports.py`

המדד החדש הוא:

`high_risk_with_open_review`

הוא מייצג:

**מספר Incidents שזוהו כ־High Risk ועדיין קיימת עבורם משימת Review פתוחה.**

דוגמת זרימה:

```text
לפני Enrichment: 0
High Risk + Review Task: 1
Review הושלם: 0
```

המדד מאפשר ל־SOC Lead לזהות כמה אירועים בסיכון גבוה עדיין ממתינים לטיפול ידני.

---

## 11. בדיקות

הפרויקט משתמש ב־`pytest`.

קיימות בדיקות עבור:

- התנהגויות של שלב 1.
- לוגיקה עסקית.
- ערכי קצה וקלט לא תקין.
- Fixtures.
- `pytest.raises`.
- `pytest.mark.parametrize`.
- `tmp_path`.
- Mock של שירות חיצוני.
- הצלחת API.
- Timeout ו־Retry.
- HTTP Error.
- JSON לא תקין.
- נתונים חסרים או שגויים.
- Strategy.
- Observer.
- Async.
- Threads + Lock.
- Incident assignment ו־transfer.
- Incident closure.
- NetworkEvent → Reputation.
- שילוב עם Remediation.
- הדוח העסקי המשולב.

בנוסף קיימות ארבע בדיקות האינטגרציה הנדרשות לרביעייה:

1. תהליך משולב שמסתיים בהצלחה.
2. כשל בשירות החיצוני והתגובה העסקית.
3. קשר לא תקין בין נתוני שתי המערכות.
4. נכונות המדד החדש בדוח.

### תוצאה סופית

הרצת הבדיקות הסופית בגרסה הנוכחית:

```cmd
.venv\Scripts\python.exe -m pytest -q --basetemp=.pytest_tmp
```

תוצאה:

```text
57 passed, 2 subtests passed in 3.36s
```

GitHub Actions שימש במהלך פיתוח שלב 2 לבדיקת Python 3.9 ו־Python 3.12.

ריצת ה־CI בוצעה לפני הרחבת ה־GUI וה־metadata האחרונה. לאחר השינויים האחרונים בוצעה הרצת הבדיקות המלאה מקומית והתוצאה הסופית היא זו המופיעה למעלה.

הבדיקות אינן תלויות ברשת, ב־API key אמיתי או בהמתנות Retry אמיתיות.

---

## 12. TDD

יכולת אחת פותחה בתהליך:

```text
Red → Green → Refactor
```

היכולת שנבחרה:

אם משימת IP Review כבר הושלמה ומתקבלת שוב תוצאת High Risk חדשה עבור אותו Incident, המשימה צריכה להיפתח מחדש במקום ליצור כפילות.

### Red

Commit:

`7939f1c`

נוספה בדיקה שהמחישה את ההתנהגות החסרה.

https://github.com/asaf0505-svg/Soar-project/commit/7939f1c418de46cd361e4645f72b83182821532e

### Green

Commit:

`2cb1433`

נוסף המימוש שפותח מחדש משימה קיימת.

https://github.com/asaf0505-svg/Soar-project/commit/2cb14331d0cd54c94836f5ee03634f3ef9a189b5

### Refactor

Commit:

`ba78002`

שופר איתור המשימה הקיימת ללא שינוי ההתנהגות.

https://github.com/asaf0505-svg/Soar-project/commit/ba78002a382041e2b9964b64c7f97150437db365

---

## 13. אימות מול AbuseIPDB אמיתי

בוצעו בדיקות אמיתיות מול AbuseIPDB.

### CLI

דוגמת הרצה:

```bash
python main.py --live --ip 8.8.8.8 --incident-id INC-001
```

בבדיקה התקבל:

```text
abuseConfidenceScore = 0
decision = low-risk
```

ולכן לא נוצרה משימת Review.

### Streamlit Workbench

בוצעה גם בדיקת Live עבור:

`1.1.1.1`

בזמן הבדיקה התקבלו בין היתר:

```text
Abuse Confidence Score: 0%
Total Reports: 204
Distinct Reporters: 61
Whitelisted: Yes
ISP: APNIC and Cloudflare DNS Resolver project
Usage Type: Content Delivery Network
Domain: cloudflare.com
Business Decision: low-risk
```

נתוני AbuseIPDB הם נתונים חיים ולכן הערכים יכולים להשתנות עם הזמן.

הבדיקה מדגימה גם שמספר דיווחים לבדו אינו מספיק כדי לקבוע ש־IP הוא זדוני; ההחלטה העסקית משתמשת בנתונים המאומתים ובמדיניות הסיכון.

---

## 14. Secrets

מפתח AbuseIPDB אינו נשמר ב־GitHub.

שם המשתנה:

`ABUSEIPDB_API_KEY`

קיים `.env.example` שמכיל רק את שם המשתנה וערך דוגמה.

בנוסף:

- `.env`
- `.streamlit/secrets.toml`
- `.streamlit/`

מוגנים באמצעות `.gitignore`.

---

## 15. התקנה והרצה

נדרשת:

`Python 3.9+`

### התקנת הפרויקט ובדיקות

```bash
python -m pip install -e ".[test]"
```

### הרצה ללא רשת

```bash
python main.py
```

הרצה זו מדגימה את התהליך ללא צורך במפתח API אמיתי.

### הרצה מול AbuseIPDB אמיתי

Windows CMD:

```cmd
set ABUSEIPDB_API_KEY=YOUR_KEY
python main.py --live --ip 8.8.8.8 --incident-id INC-001
```

PowerShell:

```powershell
$env:ABUSEIPDB_API_KEY="YOUR_KEY"
python main.py --live --ip 8.8.8.8 --incident-id INC-001
```

### הרצת הבדיקות

```bash
python -m pytest -q
```

### GUI אופציונלי

ה־GUI אינו חלק מדרישות החובה של הפרויקט, אך נוסף כ־Analyst Workbench אופציונלי.

להתקנת התלויות:

```bash
python -m pip install -r requirements.txt
```

להפעלה:

```bash
python -m streamlit run streamlit_app.py
```

ניתן להריץ בו Enrichment במצב Offline או Live.

נתוני GUI נוספים נשמרים ב־Streamlit Session בלבד; אין בפרויקט Database.

---

## 16. מבנה הפרויקט

```text
Soar-project/
│
├── data/
│   ├── sample_data.jsonl
│   └── remediation_tasks.jsonl
│
├── soc_case_manager/
│   ├── __init__.py
│   ├── api_client.py
│   ├── async_processing.py
│   ├── config.py
│   ├── context_managers.py
│   ├── integrated_reports.py
│   ├── iterators.py
│   ├── models.py
│   ├── observers.py
│   ├── processing.py
│   ├── reports.py
│   ├── repository.py
│   ├── services.py
│   ├── stage2_demo.py
│   ├── strategies.py
│   └── threaded_processing.py
│
├── tests/
│   ├── test_api_client.py
│   ├── test_async_processing.py
│   ├── test_incident_assignment.py
│   ├── test_incident_closure.py
│   ├── test_integration.py
│   ├── test_network_event_reputation.py
│   ├── test_patterns.py
│   ├── test_project.py
│   ├── test_repository_pytest.py
│   ├── test_services.py
│   └── test_threaded_processing.py
│
├── .env.example
├── .gitignore
├── AI_USAGE.md
├── main.py
├── pyproject.toml
├── README.md
├── requirements.txt
└── streamlit_app.py
```

### אחריות המודולים המרכזיים

| קובץ | אחריות |
|---|---|
| `models.py` | המודל העסקי: Incident, Events, Task ו־RemediationPlan |
| `repository.py` | קריאה ו־Validation של נתוני JSONL |
| `processing.py` | מבני נתונים, תורים ועיבוד אוספים |
| `iterators.py` | Iterator, Generator ו־Lazy Pipeline |
| `context_managers.py` | Context Manager לחקירה |
| `api_client.py` | תקשורת עם AbuseIPDB ואימות התגובה |
| `services.py` | הלוגיקה העסקית של Reputation |
| `strategies.py` | Strategy Pattern |
| `observers.py` | Observer Pattern |
| `async_processing.py` | עיבוד Async |
| `threaded_processing.py` | Threads ו־Lock |
| `reports.py` | ניהול Remediation ודוחות |
| `integrated_reports.py` | המדד העסקי המשולב |
| `stage2_demo.py` | תרחיש הדגמה של שלב 2 |
| `streamlit_app.py` | GUI אופציונלי |

---

## 17. חלוקת אחריות בקבוצה

הפרויקט פותח על ידי ארבעת חברי הקבוצה, תוך עבודה משותפת והיכרות עם התהליך הכולל.

- **טל** — העלאת הרעיון למערכת והגדרת הקווים הכלליים לבנייתה. בשלב 2 עסק בהרחבת המערכת, בחיבור ל־AbuseIPDB ובהכנת המצגת.
- **אסף** — בניית שלב 1 והרחבתו לפני ההגשה בהתאם לדרישות ולצרכים שהתגלו, וכן תכלול מקדים של שלב 2.
- **גל** — השלמת שלב 1, ניהול חלוקת המשימות בשלב 2 ותכלול השלמת הדרישות של השלב.
- **יניר** — תכלול מקדים ובניית שלב 2 יחד עם יתר חברי הקבוצה, וכן הרצת בדיקות וטסטים לצורך אימות המערכת.

כל חברי הקבוצה היו מעורבים בתהליך המשותף ונדרשים להכיר את רכיבי המערכת, זרימת המידע והחלטות התכנון המרכזיות.

---

## 18. שימוש ב־AI

השימוש ב־AI מתועד בנפרד ב־:

`AI_USAGE.md`

הקובץ מתאר:

- יצירת נתוני הדגמה סינתטיים.
- הצעות תכנון שנבדקו.
- בדיקות ותיקונים שבוצעו.
- תהליך ה־TDD.
- אימות המימוש לאחר שימוש ב־AI.

האחריות לבדיקת הקוד, הבנתו והתוצאה הסופית נשארת בידי חברי הקבוצה.

---

## Repository להגשה

Repository:

https://github.com/asaf0505-svg/Soar-project

הגרסה הסופית להגשה נמצאת בענף:

`gui/streamlit-dashboard`

קישור ישיר לגרסה הסופית:

https://github.com/asaf0505-svg/Soar-project/tree/gui/streamlit-dashboard