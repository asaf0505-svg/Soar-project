# הצעת הפרויקט

**שם ותיאור:** SOC Case Manager — מערכת מקומית לניהול ותעדוף תיקי חקירה של אירועי אבטחת מידע.

**הצורך העסקי:** צוותי אבטחה מטפלים באירועים רבים. ריכוז המידע והפעולות מסייע למנוע הזנחת תיקים ולהבחין בין טיפול שוטף לטיפול דחוף.

**משתמשים:** אנליסט מתעד אירועים ופעולות חקירה; מנהל צוות בוחן תיקים דחופים ועומס משימות; צוותי IT מטפלים במשימות מנע. בגרסה המקומית המשתמשים מיוצגים בשמות ובתפקידים, ללא מערכת הרשאות.

**התהליך המרכזי:** תיקי חקירה נטענים מנתוני דוגמה, מסווגים לפי חומרה וסטטוס ומועברים לטיפול לפי סדר הגעה או עדיפות. לחקירה מצורפים אירועי אבטחה ופעולות. שינוי הסטטוס מתאר התקדמות; במקרה של כשל במהלך חקירה מוחזר המצב הקודם. התוצאה היא מידע מסודר על התיקים ופעולות הטיפול.

**זרימת מידע:** הקלט הוא תיקי חקירה ומשימות סינתטיים מקובצי JSONL. האנליסט מוסיף פעולות ומשנה מצב; משימות מסומנות כהושלמו. הפלט כולל סדר טיפול, ספירת תיקים לפי חומרה ודוח משימות פתוחות לפי צוות. בשלב זה העדכונים נשמרים בזיכרון בלבד.

**ערך עסקי:** צמצום טעויות במעקב, תמיכה בתעדוף ועזרה למנהל בזיהוי עומס.

**ישויות וקשרים:** תיק חקירה מכיל אירועי רשת או תחנת קצה ופעולות חקירה. תוכנית טיפול מקושרת לתיק ומכילה משימות המשויכות לצוותים. שם האנליסט מתועד בפעולת החקירה.

**שני תרחישים:** (1) אנליסט מטפל בתיק דחוף, מתעד פעולה ומשנה את מצבו. (2) מנהל מזהה עומס בדוח משימות המנע, צוות משלים משימה והדוח משקף את הירידה בעומס.

**הרחבה עתידית:** קליטת אירועים משירות SIEM חיצוני ושמירה מתמשכת של העדכונים.

## הרחבה לקבוצה של ארבעה

שתי הישויות הנוספות הן `RemediationPlan` ו־`Task`. הקובץ `data/remediation_tasks.jsonl` מקשר כל משימה לתיק באמצעות `incident_id`. הטעינה בודקת שהתיק קיים ומאגדת משימות לתוכנית טיפול. שלוש פעולות עסקיות הן הוספת משימה לתוכנית, איתור משימות פתוחות והשלמת משימה; בנוסף מופק דוח עומס לפי צוות.

התהליך מתחיל בטעינת משימות תקינות לתוכנית הקשורה לתיק. כל משימה מתחילה ב־Pending ועוברת ל־Done באמצעות `mark_completed()`. ב־`main.py` מוצגים התוכניות והקשרים, דוח לפני טיפול, השלמת משימה ודוח מעודכן. התוצאה היא ירידה במספר המשימות הפתוחות של הצוות. רשומת T-106 מפנה בכוונה לתיק INC-999 שאינו קיים; היא מדגימה אזהרה ודילוג. הדוח מציג משימות פתוחות לפי צוות, לא איחורים: בגרסה הזאת אין תאריכי יעד.

<h2 dir="rtl">12. החלטות תכנון: מודל מונחה עצמים (OOP)</h2>
<p dir="rtl">
<strong>הורשה ופולימורפיזם:</strong> יצרנו מחלקת בסיס אבסטרקטית <code>SecurityEvent</code>, ממנה יורשות המחלקות <code>NetworkEvent</code> ו-<code>EndpointEvent</code>. הפולימורפיזם בא לידי ביטוי במתודה <code>calculate_total_risk</code> בתיק החקירה – היא עוברת על רשימת האירועים וקוראת ל-<code>get_risk_level()</code> של כל אירוע, מבלי להזדקק למשפטי <code>if/elif</code> לבדיקת סוג האובייקט.
<br>
<strong>הרכבה (Composition):</strong> מחלקת <code>Incident</code> מכילה בתוכה אוספים של פעולות חקירה (<code>InvestigationAction</code>) ושל אירועי אבטחה. האוספים מנוהלים דרך מתודות ייעודיות כמו <code>add_action</code>.
</p>

<h2 dir="rtl">13. טבלת מבני נתונים</h2>
<table dir="rtl">
  <tr>
    <th>צורך</th>
    <th>מבנה שנבחר</th>
    <th>מדוע הוא מתאים</th>
  </tr>
  <tr>
    <td>אחסון אוסף התיקים והפעולות</td>
    <td><code>List</code></td>
    <td>מאפשר סדר שמירה מוגדר, הוספה קלה בסוף הרשימה וגישה לפי אינדקס.</td>
  </tr>
  <tr>
    <td>ניהול תור טיפול לפי זמן הגעה</td>
    <td><code>deque</code> (FIFO)</td>
    <td>שליפה מראש התור (<code>popleft</code>) מתבצעת בסיבוכיות O(1), בניגוד לרשימה רגילה.</td>
  </tr>
  <tr>
    <td>ניהול תור טיפול דחוף</td>
    <td><code>heapq</code> (Priority Queue)</td>
    <td>מאפשר לשלוף תמיד את התיק בעל החומרה הגבוהה ביותר ביעילות (O(log n)), תוך שימוש בשובר שוויון (ID).</td>
  </tr>
  <tr>
    <td>איתור תיק לפי מזהה (ID)</td>
    <td><code>Dict</code></td>
    <td>מספק גישה מיידית ב-O(1) מבלי לסרוק את כל האוסף, וכן משמש לקיבוץ וספירה (כמו ספירת תיקים לפי חומרה).</td>
  </tr>
  <tr>
    <td>שמירת רמות חומרה ייחודיות</td>
    <td><code>Set</code></td>
    <td>מבטיח חוסר כפילויות ומאפשר בדיקת שייכות (<code>in</code>) ופעולות איחוד/חיתוך בצורה יעילה ומהירה.</td>
  </tr>
</table>

<h2 dir="rtl">14. טבלת פעולות המשנות אוסף לעומת יוצרות חדש</h2>
<table dir="rtl">
  <tr>
    <th>פעולה</th>
    <th>משנה את האוסף הקיים (In-Place)</th>
    <th>יוצרת אוסף חדש</th>
  </tr>
  <tr>
    <td><code>append()</code> / <code>popleft()</code> ב-deque</td>
    <td>כן</td>
    <td>לא</td>
  </tr>
  <tr>
    <td><code>heappush()</code> / <code>heappop()</code> ב-heapq</td>
    <td>כן</td>
    <td>לא</td>
  </tr>
  <tr>
    <td>List / Dict Comprehensions</td>
    <td>לא</td>
    <td>כן</td>
  </tr>
  <tr>
    <td>פעולת <code>sorted()</code></td>
    <td>לא</td>
    <td>כן</td>
  </tr>
</table>

<h2 dir="rtl">15. עיבוד הנתונים וניהול משאבים</h2>
<p dir="rtl">
<strong>טעינת נתונים (Lazy Reading):</strong> קריאת קובץ ה-JSONL מבוצעת שורה אחר שורה באופן הדרגתי בתוך בלוק <code>with open</code>, כאשר כל שורה מומרת לאובייקט עם טיפול שגיאות הדוק למניעת קריסה.
<br>
<strong>Iterables ו-Iterators:</strong> מומשו המחלקות <code>IncidentCollection</code> ו-<code>IncidentIterator</code> המאפשרות מעבר עצמאי על הנתונים כך שכל קריאה ל-<code>iter()</code> מחזירה מצביע חדש לחלוטין שרץ במקביל.
<br>
<strong>Generator ו-Pipeline עצל:</strong> ה-Pipeline מסנן תיקים קריטיים שנמצאים בטיפול ומחזיר רק את המזהה שלהם. העיבוד מתחיל רק כשקוראים ל-<code>next()</code>, ואינו יוצר רשימות ביניים בזיכרון.
<br>
<strong>Context Manager:</strong> המחלקה <code>IncidentInvestigationContext</code> מנהלת את הסטטוס של התיק. אם מתרחשת חריגה בזמן העבודה, פעולת היציאה תופסת אותה ומחזירה את הסטטוס לקדמותו כדי למנוע השחתת נתונים, ועדיין מאפשרת לחריגה להמשיך הלאה ולהיות מטופלת מחוץ לבלוק.
</p>

<h2 dir="rtl">16. הוראות הרצה</h2>
<p dir="rtl">
1. נדרשת סביבת Python בגרסה 3.9 ומעלה.<br>
2. ודאו שהתיקייה <code>data/</code> מכילה את הקובץ <code>sample_data.jsonl</code>.<br>
3. הריצו מהשורש את הפקודה: <code>python main.py</code>.<br>
4. אין צורך בהתקנת ספריות חיצוניות (requirements.txt אינו נדרש).
</p>

## מפת קבצים ואחריויות

<ul dir="rtl">
<li><code>main.py</code>: סקריפט הרצה מרכזי המדגים את כלל תרחישי המערכת.</li>
<li><code>README.md</code> ו-<code>AI_USAGE.md</code>: תיעוד, אפיון המערכת והסברים על יצירת הנתונים.</li>
<li><code>pyproject.toml</code> ו-<code>.gitignore</code>: הגדרות פרויקט וסביבת עבודה.</li>
<li><code>data/sample_data.jsonl</code>: קובץ הנתונים הראשי למודל תיקי החקירה.</li>
<li><code>data/remediation_tasks.jsonl</code>: קובץ נתונים משני להרחבת תוכניות הטיפול.</li>
<li><code>soc_case_manager/__init__.py</code>: הגדרת התיקייה כחבילת קוד (Package).</li>
<li><code>soc_case_manager/models.py</code>: מחלקות עסקיות (OOP, פולימורפיזם, תוכניות טיפול).</li>
<li><code>soc_case_manager/repository.py</code>: טעינה הדרגתית של קבצים ובדיקות תקינות (Validation).</li>
<li><code>soc_case_manager/processing.py</code>: ניהול אוספים, תור עדיפויות, מילונים ופעולות סט.</li>
<li><code>soc_case_manager/iterators.py</code>: מחלקות Iterators מותאמים, גנרטורים וצינורות עיבוד עצלים.</li>
<li><code>soc_case_manager/context_managers.py</code>: ניהול בטוח של משאבים באמצעות <code>with</code>.</li>
<li><code>soc_case_manager/reports.py</code>: הפקת הדוח העסקי וניהול משימות מנע.</li>
<li><code>tests/test_project.py</code>: בדיקות תפקוד, קלט שגוי והרצת ההדגמה.</li>
</ul>

החיפוש לפי מזהה מרוכז ב־`IncidentProcessor.get_incident` בתוך processing.py, כדי ששני התהליכים העסקיים ישתמשו באותו אינדקס. אין צורך בכפל אינדקס בתוך repository.py.

## הנתונים והבדיקות

לפי תיעוד יצירת הנתונים ב־AI_USAGE.md, קובץ התיקים נוצר באמצעות Gemini. כל שורה היא אובייקט JSON עם `id`, `title`, `severity`, `status`. המזהה והכותרת הם מחרוזות לא ריקות; חומרה היא Low/Medium/High/Critical וסטטוס הוא Open/In Progress/Closed. סטטוס חסר מקבל Open. השדות האחרים חובה. רשומת משימה כוללת `task_id`, `incident_id`, `description`, `assigned_team`, כולם טקסט לא ריק.

שורה נקראת בתוך `with open(..., encoding="utf-8")`, מומרת למילון ב־json.loads ואז לאובייקט בבנאי from_dict. JSON פגום, ערך שאינו אובייקט, שדות חובה חסרים וערכים לא חוקיים גורמים לאזהרה ולדילוג. הטעינה שומרת את הרשומה התקינה הראשונה לכל מזהה ומדלגת על כפילויות. אותו כלל חל על משימות, גם בטעינה חוזרת. קשר לתיק שאינו קיים מסונן. בבניית אינדקס מרשימה שסופקה ישירות ל־processing, המדיניות הנפרדת היא שהאובייקט האחרון לאותו מזהה מחליף את הקודם; הנתונים מהטוען כבר ייחודיים.

הקריאה מהקובץ היא שורה־שורה, אבל תוצאת load_incidents היא רשימה מלאה בזיכרון; זו אינה הבטחה שכל המערכת צורכת זיכרון קבוע.

## החלטות נוספות על אוספים

| צורך | מבנה | הסבר |
|---|---|---|
| רשומת סיכום של מזהה וחומרה | tuple | שני שדות קבועים שאינם משתנים במהלך ההצגה |
| סדר טיפול רגיל | deque | טיפול בתיקים לפי הגעה מונע דילוג על תיק ותיק; main מוסיף ושולף שלושה תיקים ובודק תור ריק |
| סדר טיפול דחוף | heapq | חומרה גבוהה קודמת; __lt__ מגדיר אובייקט חמור כקטן יותר עבור min-heap, ומזהה שובר שוויון. הרשימה הפנימית אינה ממוינת במלואה |

פעולות add/discard משנות set קיים; איחוד, set comprehension ו־sorted יוצרים אוספים חדשים. בפלט קבוצות ממוינות לצורכי תצוגה בלבד, ואין הסתמכות על סדר פנימי של set. `*rest` אוסף את יתר התיקים לאחר הפרדת הראשון.

## Generator ו־Pipeline — מה בדיוק מודגם

`generate_open_incidents` משתמש ב־yield. עצם יצירת הגנרטור אינה מריצה את הגוף. main צורך תוצאה ב־next ואז ממשיך באותו אובייקט עם for; מעבר חוזר לאחר מיצוי מחזיר אפס תוצאות. כדי להתחיל שוב יש ליצור גנרטור חדש.

ב־pipeline יש סינון לפי Critical, סינון לפי In Progress והמרה למזהה. next מתחיל או מחדש את העבודה בכל השלבים. main מבקש שתי תוצאות בלבד — בקובץ המצורף INC-002 ו־INC-011 — ולכן רשומות INC-012 עד INC-015 אינן מעובדות ב־pipeline לאחר העצירה. הן כבר נטענו לרשימה על ידי הטוען. list comprehension היה מעבד את כל האוסף ובונה רשימת תוצאות מיד; Generator Expression צורך נתונים לפי בקשה, ללא רשימות ביניים. האיטרטור מתקדם ואינו חוזר לאחור, ולכן מעבר נוסף מהתחלה דורש יצירת pipeline חדש.

## הרצה ובדיקות

יש להריץ משורש המאגר, כאשר שני קובצי data קיימים:

```sh
python main.py
python -m unittest discover -s tests -v
git log --oneline --graph --all
```

נדרשת Python 3.9 ומעלה. ההרצה והבדיקות אומתו ב־Python 3.12.14. אין תלות חיצונית להתקנה. הודעת RuntimeError בהדגמה ואזהרת המשימה המקושרת לתיק חסר הן תרחישים מכוונים; התוכנית ממשיכה ומסתיימת כרגיל.

לפני ההגשה יש לצרף את פלט Git לקישור המאגר ולוודא שהצעת חלק א הוגשה בנפרד ואושרה. בדיקות אוטומטיות אינן מחליפות הבנה והסבר אישי של הקוד.

## שלב 2

### 1. הרחבה עסקית

בשלב 2 הורחבה מערכת SOC Case Manager כך שאירוע רשת (`NetworkEvent`) המקושר ל־Incident יכול לעבור בדיקת מוניטין חיצונית לכתובת ה־IP שלו.

המערכת משתמשת ב־AbuseIPDB API לצורך קבלת `abuseConfidenceScore` עבור כתובת IP ציבורית. המידע החיצוני משמש כתמיכה בהחלטת האנליסט ואינו מבצע חקירה או תגובה אוטומטית.

כאשר הציון עומד במדיניות הסיכון שנבחרה, נוצרה משימת Review אנושית בתת־מערכת ה־Remediation. המערכת אינה חוסמת IP, אינה משנה Severity ואינה סוגרת Incident אוטומטית.

כשל בשירות החיצוני אינו גורם לעדכון עסקי שגוי: במקרה של Timeout, ConnectionError, HTTP error, JSON לא תקין או נתונים חסרים, לא נוצרת משימת Review חדשה ולא משתנים נתוני ה־Incident.

### 2. שירות חיצוני ו־Retry

התקשורת מול AbuseIPDB נמצאת ב־`soc_case_manager/api_client.py`, בנפרד מהלוגיקה העסקית שב־`services.py`.

לקוח ה־API מבצע:

- בקשת GET עם `params` ו־`timeout`.
- `raise_for_status()` עבור תגובות HTTP לא תקינות.
- פענוח JSON ואימות מבנה התשובה.
- אימות שה־IP שהוחזר תואם ל־IP שהתבקש.
- אימות ש־`abuseConfidenceScore` הוא מספר שלם בין 0 ל־100.
- המרת התוצאה לאובייקט `IPReputation`.

Timeout ו־ConnectionError מקבלים Retry של עד שלושה ניסיונות בסך הכול, עם המתנה בין ניסיונות. שגיאות HTTP או נתונים לא תקינים אינן עוברות Retry אוטומטי.

מפתח ה־API נקרא רק ממשתנה הסביבה `ABUSEIPDB_API_KEY` ואינו נשמר בקוד או במאגר.

### 3. Design Patterns

בשלב 2 מומשו שתי תבניות תכנון:

**Strategy** — מדיניות ההחלטה האם ציון AbuseIPDB דורש Review מופרדת מהשירות העסקי. קיימות לפחות שתי אסטרטגיות חלופיות עם ממשק משותף, וניתן להזריק את האסטרטגיה מבחוץ.

**Observer** — זיהוי אירוע סיכון גבוה מפעיל אירוע `HighRiskDetected`. האירוע נשלח ליותר ממגיב אחד: Observer אחד מנהל את משימת ה־Remediation ו־Observer נוסף מתעד את ציון הסיכון לצורך הדוח המשולב.

התלויות העיקריות מוזרקות מבחוץ ל־`ReputationService`, כך שהלוגיקה העסקית אינה יוצרת ישירות את לקוח ה־HTTP.

### 4. שילוב עם NetworkEvent ו־Remediation

כתובת ה־IP הנבדקת מגיעה מ־`NetworkEvent` המקושר ל־Incident.

`ReputationService.evaluate_network_event()` בודק שהאירוע אכן שייך ל־Incident לפני שהוא שולח את כתובת ה־IP לשירות החיצוני. אירוע שאינו מקושר לתיק נדחה ולא גורם לקריאת API או ליצירת משימה.

כאשר מתקבל ציון גבוה, Observer יוצר או פותח מחדש משימת Review מסוג:

```text
IP-REVIEW-<incident_id>
```

המשימה מקושרת ל־RemediationPlan של אותו Incident.

### 5. תהליך Incident

בשלב 2 נוספו גם פעולות עסקיות מפורשות ל־Incident:

- `assign_to()` — שיוך תיק לאנליסט.
- `transfer_to()` — העברת תיק מאנליסט אחד לאחר.
- `close(resolution_summary)` — סגירת תיק תוך חובה לשמור סיכום טיפול לא ריק.

פעולות אלה משלימות את תהליך העבודה של האנליסט ושומרות על Validation בתוך המודל העסקי.

### 6. Async ו־Threads

#### Async

מומשו שלוש משימות עצמאיות של בדיקות סיכון מדומות.

המערכת מריצה את אותם נתונים בשתי צורות:

- Sequential.
- Concurrent באמצעות `asyncio`.

בגרסה המקבילית כל המשימות מתוזמנות לפני איסוף התוצאות, והתוצאות מוחזרות בסדר הקלט גם כאשר זמני הסיום שונים.

#### Threads + Lock

מומש תרחיש שבו שני אנליסטים מנסים לתפוס את אותו Incident בו־זמנית.

אותו `Lock` מגן על פעולת ה־check-and-update כולה, ולכן רק אנליסט אחד יכול לקבל את התיק. בדיקות המקביליות אינן מניחות איזה Thread ינצח אלא בודקות שרק הקצאה אחת הצליחה ושהמצב הסופי תקין.

### 7. דוח עסקי משולב

`integrated_reports.py` מפיק את המדד:

```text
high_risk_with_open_review
```

המדד מייצג את מספר התיקים בעלי ציון סיכון חיצוני גבוה שעדיין קיימת עבורם משימת Review פתוחה.

ה־Stage 2 demo מציג את השינוי במדד לאורך התהליך:

```text
Before enrichment: 0
High-risk result + Review task created: 1
Manual review completed: 0
```

כך המידע החיצוני משפיע בפועל גם על תת־מערכת ה־Remediation וגם על דוח התומך בהחלטת מנהל הצוות.

### 8. בדיקות

הפרויקט משתמש ב־pytest עבור בדיקות שלב 2 ושומר גם את בדיקות שלב 1.

הבדיקות כוללות בין היתר:

- לוגיקה עסקית וערכי קצה.
- `pytest.raises`.
- `pytest.mark.parametrize`.
- `tmp_path`.
- Mock של השירות החיצוני.
- API success/failure.
- Timeout ו־Retry.
- HTTP error.
- JSON ומבנה נתונים לא תקינים.
- Strategy ו־Observer.
- Async.
- Threads ו־Lock.
- סגירת Incident עם resolution summary.
- שיוך והעברת Incident בין אנליסטים.
- קשר בין NetworkEvent ל־Incident.
- ארבע בדיקות האינטגרציה הנדרשות להרחבת רביעייה.

בריצה הסופית ב־GitHub Actions שתי גרסאות Python — 3.9 ו־3.12 — עברו בהצלחה. בריצת Python 3.12 התקבל:

```text
55 passed, 2 subtests passed
```

### 9. TDD

בוצע תהליך Red → Green → Refactor עבור היכולת לפתוח מחדש משימת IP Review שכבר הושלמה כאשר מתקבל אירוע סיכון גבוה חדש.

- Red — commit `7939f1c`
- Green — commit `2cb1433`
- Refactor — commit `ba78002`

קיים ב־GitHub Actions תיעוד של ריצת Red שנכשלה ושל הרצות Green ו־Refactor שעברו.

### 10. אימות AbuseIPDB אמיתי

בתאריך 2.11.2026 בוצעה הרצה אמיתית מול AbuseIPDB API.

הפקודה:

```bash
python main.py --live --ip 8.8.8.8 --incident-id INC-001
```

יצרה `NetworkEvent` המקושר ל־`INC-001` ושלחה את כתובת ה־IP מתוך האירוע לשירות.

התוצאה שהתקבלה:

```text
Network event linked to incident: STAGE2-NET-001 -> INC-001; IP=8.8.8.8
Source: LIVE AbuseIPDB API; incident: INC-001; decision: low-risk; score: 0
Combined report after enrichment: {'high_risk_with_open_review': 0}
```

התקבל `abuseConfidenceScore` של `0`, ולכן בהתאם למדיניות העסקית המערכת החזירה `low-risk` ולא יצרה משימת Review.

מפתח ה־API הוגדר במשתנה סביבה בלבד ולא נשמר בקוד או ב־Git.

### 11. התקנה והרצה

```bash
python -m pip install -e ".[test]"
python main.py
python -m pytest -q
```

הרצת API אמיתי:

```bash
python main.py --live --ip 8.8.8.8 --incident-id INC-001
```

לפני הרצה אמיתית יש להגדיר את משתנה הסביבה:

```text
ABUSEIPDB_API_KEY
```

### 12. מבנה רכיבי שלב 2

```text
soc_case_manager/
├── api_client.py
├── async_processing.py
├── config.py
├── integrated_reports.py
├── models.py
├── observers.py
├── services.py
├── stage2_demo.py
├── strategies.py
└── threaded_processing.py

tests/
├── test_api_client.py
├── test_async_processing.py
├── test_incident_assignment.py
├── test_incident_closure.py
├── test_integration.py
├── test_network_event_reputation.py
├── test_patterns.py
├── test_repository_pytest.py
├── test_services.py
└── test_threaded_processing.py
```

שלב 1 נשמר ולא הוחלף; שלב 2 מוסיף את השירות החיצוני, תבניות התכנון, המקביליות, תהליך ה־Incident והאינטגרציה עם Remediation.

### Streamlit Analyst Workbench

נוסף ממשק Streamlit אופציונלי שמציג את יכולות המערכת כ־SOC case-management workbench.

הממשק מאפשר:
- צפייה וסינון של תיקי חקירה.
- שיוך והעברת Incident בין אנליסטים.
- ניהול state של הקייס.
- הוספת Notes ותיעוד פעולות חקירה.
- צפייה ב־Observables ובמשימות Remediation.
- הרצת IP reputation enrichment במצב Offline או מול AbuseIPDB האמיתי.
- תיעוד אוטומטי של תוצאת ה־enrichment בתוך Notes של הקייס.

הממשק הוא שכבת הצגה מעל הלוגיקה העסקית הקיימת. נתוני GUI נוספים נשמרים ב־Streamlit session ואינם מהווים מסד נתונים קבוע.

להפעלת הממשק:

`python -m streamlit run streamlit_app.py`

לשימוש ב־Live AbuseIPDB יש להגדיר את המשתנה:

`ABUSEIPDB_API_KEY`

המפתח אינו נשמר במאגר.

### Live AbuseIPDB Validation

בוצעה בדיקה אמיתית בתאריך 2.11.2026 מול AbuseIPDB עבור הכתובת `1.1.1.1`.

בבדיקה התקבלו בין היתר:
- Abuse Confidence Score: `0%`
- Reports in the configured 90-day window: `204`
- Distinct reporters: `61`
- Whitelisted: `Yes`
- ISP: `APNIC and Cloudflare DNS Resolver project`
- Usage Type: `Content Delivery Network`
- Domain: `cloudflare.com`
- Business Decision: `low-risk`

הבדיקה ממחישה שמספר דיווחים לבדו אינו מספיק כדי להסיק ש־IP הוא זדוני. הערכים מגיעים משירות חיצוני חי ולכן עשויים להשתנות עם הזמן.

### Final Automated Test Result

פקודת הבדיקה הסופית:

`.venv\Scripts\python.exe -m pytest -q --basetemp=.pytest_tmp`

תוצאה:

`57 passed, 2 subtests passed in 3.36s`