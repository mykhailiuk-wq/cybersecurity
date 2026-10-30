# Лабораторна 10. Протокол реєстрації подій

Дата запуску: 2026-10-30T16:30:30

* Проєкт: `D:\cybersecurity\lab10`
* Сервер: `127.0.0.1:58820` (loopback)
* База даних: `D:\cybersecurity\lab10\data\lab10-demo\auth.db`
* Користувачі: alice (TOP_SECRET/admin), bob (SECRET), carol (CONFIDENTIAL), dave (UNCLASSIFIED)
* Події: успішні та невдалі входи, успішні та невдалі операції з об'єктами

## Таблиця «дія користувача — запис у журналі аудиту»

| Дія користувача | Відображення в журналі аудиту |
|---|---|
| 1. alice: реєстрація токена за одноразовим кодом (допуск TOP_SECRET, роль admin) | #1 \| 2026-10-30T14:30:30+00:00 \| alice \| ENROLL-SUCCESS — успішна реєстрація токена \| ALLOW \| peer=127.0.0.1:58821 \| details=algorithm=SHA256; level=TOP_SECRET; role=admin |
| 2. bob: реєстрація токена за одноразовим кодом (допуск SECRET, роль user) | #2 \| 2026-10-30T14:30:30+00:00 \| bob \| ENROLL-SUCCESS — успішна реєстрація токена \| ALLOW \| peer=127.0.0.1:58822 \| details=algorithm=SHA256; level=SECRET; role=user |
| 3. carol: реєстрація токена за одноразовим кодом (допуск CONFIDENTIAL, роль user) | #3 \| 2026-10-30T14:30:30+00:00 \| carol \| ENROLL-SUCCESS — успішна реєстрація токена \| ALLOW \| peer=127.0.0.1:58823 \| details=algorithm=SHA256; level=CONFIDENTIAL; role=user |
| 4. dave: реєстрація токена за одноразовим кодом (допуск UNCLASSIFIED, роль user) | #4 \| 2026-10-30T14:30:30+00:00 \| dave \| ENROLL-SUCCESS — успішна реєстрація токена \| ALLOW \| peer=127.0.0.1:58824 \| details=algorithm=SHA256; level=UNCLASSIFIED; role=user |
| 5. alice: успішне рукостискання з сервером (допуск TOP_SECRET) | #5 \| 2026-10-30T14:30:30+00:00 \| alice \| AUTH-SUCCESS — успішна автентифікація \| ALLOW \| peer=127.0.0.1:58825 \| session=bacff0ca \| details=level=TOP_SECRET; role=admin |
| 6. bob: успішне рукостискання з сервером (допуск SECRET) | #6 \| 2026-10-30T14:30:30+00:00 \| bob \| AUTH-SUCCESS — успішна автентифікація \| ALLOW \| peer=127.0.0.1:58826 \| session=e9fca27c \| details=level=SECRET; role=user |
| 7. carol: успішне рукостискання з сервером (допуск CONFIDENTIAL) | #7 \| 2026-10-30T14:30:30+00:00 \| carol \| AUTH-SUCCESS — успішна автентифікація \| ALLOW \| peer=127.0.0.1:58827 \| session=ebd655bb \| details=level=CONFIDENTIAL; role=user |
| 8. dave: успішне рукостискання з сервером (допуск UNCLASSIFIED) | #8 \| 2026-10-30T14:30:30+00:00 \| dave \| AUTH-SUCCESS — успішна автентифікація \| ALLOW \| peer=127.0.0.1:58828 \| session=0ef49c55 \| details=level=UNCLASSIFIED; role=user |
| 9. intruder: вхід із підробленим секретом токена (очікувана відмова) | #9 \| 2026-10-30T14:30:30+00:00 \| alice \| AUTH-FAILURE — невдала автентифікація \| DENY \| peer=127.0.0.1:58829 \| session=9e89f97a \| reason=bad-response |
| 10. mallory: вхід із невідомим ідентифікатором (очікувана відмова) | #10 \| 2026-10-30T14:30:30+00:00 \| mallory \| AUTH-FAILURE — невдала автентифікація \| DENY \| peer=127.0.0.1:58830 \| session=d8d85f7e \| reason=unknown-user,bad-response |
| 11. dave: вхід після вимкнення облікового запису (очікувана відмова) | #11 \| 2026-10-30T14:30:30+00:00 \| dave \| AUTH-FAILURE — невдала автентифікація \| DENY \| peer=127.0.0.1:58831 \| session=1826638a \| reason=disabled |
| 12. alice: створення об'єкта ts-plan рівня TOP_SECRET (тип text) | #12 \| 2026-10-30T14:30:30+00:00 \| alice \| OBJECT-CREATE-ALLOW — створення об'єкта дозволено \| ALLOW \| object=ts-plan \| peer=127.0.0.1:58825 \| session=bacff0ca |
| 13. alice: створення об'єкта ts-keys рівня TOP_SECRET (тип file) | #13 \| 2026-10-30T14:30:30+00:00 \| alice \| OBJECT-CREATE-ALLOW — створення об'єкта дозволено \| ALLOW \| object=ts-keys \| peer=127.0.0.1:58825 \| session=bacff0ca |
| 14. alice: створення об'єкта ts-notes рівня TOP_SECRET (тип text) | #14 \| 2026-10-30T14:30:30+00:00 \| alice \| OBJECT-CREATE-ALLOW — створення об'єкта дозволено \| ALLOW \| object=ts-notes \| peer=127.0.0.1:58825 \| session=bacff0ca |
| 15. bob: створення об'єкта s-report рівня SECRET (тип text) | #15 \| 2026-10-30T14:30:30+00:00 \| bob \| OBJECT-CREATE-ALLOW — створення об'єкта дозволено \| ALLOW \| object=s-report \| peer=127.0.0.1:58826 \| session=e9fca27c |
| 16. bob: створення об'єкта s-design рівня SECRET (тип text) | #16 \| 2026-10-30T14:30:30+00:00 \| bob \| OBJECT-CREATE-ALLOW — створення об'єкта дозволено \| ALLOW \| object=s-design \| peer=127.0.0.1:58826 \| session=e9fca27c |
| 17. bob: створення об'єкта s-tasks рівня SECRET (тип text) | #17 \| 2026-10-30T14:30:30+00:00 \| bob \| OBJECT-CREATE-ALLOW — створення об'єкта дозволено \| ALLOW \| object=s-tasks \| peer=127.0.0.1:58826 \| session=e9fca27c |
| 18. carol: створення об'єкта c-budget рівня CONFIDENTIAL (тип text) | #18 \| 2026-10-30T14:30:30+00:00 \| carol \| OBJECT-CREATE-ALLOW — створення об'єкта дозволено \| ALLOW \| object=c-budget \| peer=127.0.0.1:58827 \| session=ebd655bb |
| 19. carol: створення об'єкта c-contacts рівня CONFIDENTIAL (тип text) | #19 \| 2026-10-30T14:30:30+00:00 \| carol \| OBJECT-CREATE-ALLOW — створення об'єкта дозволено \| ALLOW \| object=c-contacts \| peer=127.0.0.1:58827 \| session=ebd655bb |
| 20. dave: створення об'єкта u-readme рівня UNCLASSIFIED (тип file) | #20 \| 2026-10-30T14:30:30+00:00 \| dave \| OBJECT-CREATE-ALLOW — створення об'єкта дозволено \| ALLOW \| object=u-readme \| peer=127.0.0.1:58828 \| session=0ef49c55 |
| 21. dave: створення об'єкта u-faq рівня UNCLASSIFIED (тип text) | #21 \| 2026-10-30T14:30:30+00:00 \| dave \| OBJECT-CREATE-ALLOW — створення об'єкта дозволено \| ALLOW \| object=u-faq \| peer=127.0.0.1:58828 \| session=0ef49c55 |
| 22. bob: читання власного об'єкта s-report | #22 \| 2026-10-30T14:30:30+00:00 \| bob \| OBJECT-READ-ALLOW — читання об'єкта дозволено \| ALLOW \| object=s-report \| peer=127.0.0.1:58826 \| session=e9fca27c |
| 23. alice: спроба прочитати s-report без права в ACL (очікувана відмова) | #23 \| 2026-10-30T14:30:30+00:00 \| alice \| OBJECT-READ-DENY — читання об'єкта заборонено \| DENY \| object=s-report \| peer=127.0.0.1:58825 \| session=bacff0ca \| reason=дискреційна відмова: немає права 'read' в ACL об'єкта |
| 24. bob: надання alice права read на s-report | #24 \| 2026-10-30T14:30:30+00:00 \| bob \| OBJECT-GRANT-ALLOW — призначення прав дозволено \| ALLOW \| object=s-report \| peer=127.0.0.1:58826 \| session=e9fca27c \| details=target=alice; rights=read |
| 25. alice: читання s-report після надання права read | #25 \| 2026-10-30T14:30:30+00:00 \| alice \| OBJECT-READ-ALLOW — читання об'єкта дозволено \| ALLOW \| object=s-report \| peer=127.0.0.1:58825 \| session=bacff0ca |
| 26. alice: спроба дописати в s-report без права append (очікувана відмова) | #26 \| 2026-10-30T14:30:30+00:00 \| alice \| OBJECT-APPEND-DENY — дописування заборонено \| DENY \| object=s-report \| peer=127.0.0.1:58825 \| session=bacff0ca \| reason=дискреційна відмова: немає права 'append' в ACL об'єкта |
| 27. bob: надання alice права append на s-report | #27 \| 2026-10-30T14:30:30+00:00 \| bob \| OBJECT-GRANT-ALLOW — призначення прав дозволено \| ALLOW \| object=s-report \| peer=127.0.0.1:58826 \| session=e9fca27c \| details=target=alice; rights=read, append |
| 28. alice: дописування вниз у s-report, TOP_SECRET -> SECRET (очікувана відмова no-write-down) | #28 \| 2026-10-30T14:30:30+00:00 \| alice \| OBJECT-APPEND-DENY — дописування заборонено \| DENY \| object=s-report \| peer=127.0.0.1:58825 \| session=bacff0ca \| reason=no-write-down: clearance TOP_SECRET > classification SECRET |
| 29. alice: надання dave права read на ts-plan | #29 \| 2026-10-30T14:30:30+00:00 \| alice \| OBJECT-GRANT-ALLOW — призначення прав дозволено \| ALLOW \| object=ts-plan \| peer=127.0.0.1:58825 \| session=bacff0ca \| details=target=dave; rights=read |
| 30. dave: спроба прочитати ts-plan вищого рівня (очікувана відмова no-read-up) | #30 \| 2026-10-30T14:30:30+00:00 \| dave \| OBJECT-READ-DENY — читання об'єкта заборонено \| DENY \| object=ts-plan \| peer=127.0.0.1:58828 \| session=0ef49c55 \| reason=no-read-up: clearance UNCLASSIFIED < classification TOP_SECRET |
| 31. bob: надання carol права read на s-report | #31 \| 2026-10-30T14:30:30+00:00 \| bob \| OBJECT-GRANT-ALLOW — призначення прав дозволено \| ALLOW \| object=s-report \| peer=127.0.0.1:58826 \| session=e9fca27c \| details=target=carol; rights=read |
| 32. carol: спроба прочитати s-report вищого рівня (очікувана відмова no-read-up) | #32 \| 2026-10-30T14:30:30+00:00 \| carol \| OBJECT-READ-DENY — читання об'єкта заборонено \| DENY \| object=s-report \| peer=127.0.0.1:58827 \| session=ebd655bb \| reason=no-read-up: clearance CONFIDENTIAL < classification SECRET |
| 33. bob: надання carol права append на s-report | #33 \| 2026-10-30T14:30:30+00:00 \| bob \| OBJECT-GRANT-ALLOW — призначення прав дозволено \| ALLOW \| object=s-report \| peer=127.0.0.1:58826 \| session=e9fca27c \| details=target=carol; rights=read, append |
| 34. carol: дописування вгору в s-report, CONFIDENTIAL -> SECRET | #34 \| 2026-10-30T14:30:30+00:00 \| carol \| OBJECT-APPEND-ALLOW — дописування дозволено \| ALLOW \| object=s-report \| peer=127.0.0.1:58827 \| session=ebd655bb |
| 35. carol: спроба видалити s-report без права delete (очікувана відмова) | #35 \| 2026-10-30T14:30:30+00:00 \| carol \| OBJECT-DELETE-DENY — видалення об'єкта заборонено \| DENY \| object=s-report \| peer=127.0.0.1:58827 \| session=ebd655bb \| reason=дискреційна відмова: немає права 'delete' в ACL об'єкта |
| 36. bob: видалення власного об'єкта s-tasks | #36 \| 2026-10-30T14:30:30+00:00 \| bob \| OBJECT-DELETE-ALLOW — видалення об'єкта дозволено \| ALLOW \| object=s-tasks \| peer=127.0.0.1:58826 \| session=e9fca27c |
| 37. carol: читання вже видаленого s-tasks (очікувана відмова object-not-found) | #37 \| 2026-10-30T14:30:30+00:00 \| carol \| OBJECT-READ-DENY — читання об'єкта заборонено \| DENY \| object=s-tasks \| peer=127.0.0.1:58827 \| session=ebd655bb \| reason=object-not-found |
| 38. carol: створення об'єкта нижче допуску, CONFIDENTIAL -> UNCLASSIFIED (очікувана відмова no-write-down) | #38 \| 2026-10-30T14:30:30+00:00 \| carol \| OBJECT-CREATE-DENY — створення об'єкта заборонено \| DENY \| object=c-low \| peer=127.0.0.1:58827 \| session=ebd655bb \| reason=no-write-down: clearance CONFIDENTIAL > classification UNCLASSIFIED |
| 39. bob: заміна вмісту власного s-report (рівні збігаються) | #39 \| 2026-10-30T14:30:30+00:00 \| bob \| OBJECT-WRITE-ALLOW — заміну вмісту дозволено \| ALLOW \| object=s-report \| peer=127.0.0.1:58826 \| session=e9fca27c |
| 40. dave: дописування у власний u-readme | #40 \| 2026-10-30T14:30:30+00:00 \| dave \| OBJECT-APPEND-ALLOW — дописування дозволено \| ALLOW \| object=u-readme \| peer=127.0.0.1:58828 \| session=0ef49c55 |
| 41. bob: відбирання права read у carol на s-report | #41 \| 2026-10-30T14:30:30+00:00 \| bob \| OBJECT-REVOKE-ALLOW — відбирання прав дозволено \| ALLOW \| object=s-report \| peer=127.0.0.1:58826 \| session=e9fca27c \| details=target=carol; rights=append |
| 42. carol: повторне читання s-report після відбирання права (очікувана відмова) | #42 \| 2026-10-30T14:30:30+00:00 \| carol \| OBJECT-READ-DENY — читання об'єкта заборонено \| DENY \| object=s-report \| peer=127.0.0.1:58827 \| session=ebd655bb \| reason=дискреційна відмова: немає права 'read' в ACL об'єкта |
| 43. alice: перевірка власного допуску та ролі (whoami) | #43 \| 2026-10-30T14:30:30+00:00 \| alice \| SESSION-WHOAMI-ALLOW — перевірка власного допуску \| ALLOW \| peer=127.0.0.1:58825 \| session=bacff0ca \| details=level=TOP_SECRET; role=admin |
| 44. alice: перегляд списку доступних об'єктів (list) | #44 \| 2026-10-30T14:30:30+00:00 \| alice \| OBJECT-LIST-ALLOW — перегляд списку об'єктів дозволено \| ALLOW \| peer=127.0.0.1:58825 \| session=bacff0ca \| details=count=4 |
| 45. bob: перегляд метаданих s-report (info) | #45 \| 2026-10-30T14:30:30+00:00 \| bob \| OBJECT-INFO-ALLOW — перегляд метаданих дозволено \| ALLOW \| object=s-report \| peer=127.0.0.1:58826 \| session=e9fca27c \| details=level=SECRET; owner=bob |
| 46. bob: запит метаданих неіснуючого об'єкта (очікувана відмова) | #46 \| 2026-10-30T14:30:30+00:00 \| bob \| OBJECT-INFO-DENY — перегляд метаданих заборонено \| DENY \| object=no-such-object \| peer=127.0.0.1:58826 \| session=e9fca27c \| reason=object-not-found |
| 47. alice: інвентаризація всіх об'єктів як адміністратор | #47 \| 2026-10-30T14:30:30+00:00 \| alice \| ADMIN-INVENTORY-ALLOW — інвентаризацію дозволено \| ALLOW \| peer=127.0.0.1:58825 \| session=bacff0ca \| details=count=9 |
| 48. bob: спроба інвентаризації без ролі адміністратора (очікувана відмова) | #48 \| 2026-10-30T14:30:30+00:00 \| bob \| ADMIN-INVENTORY-DENY — інвентаризацію заборонено \| DENY \| peer=127.0.0.1:58826 \| session=e9fca27c \| reason=інвентаризація доступна лише адміністратору |
| 49. alice: перегляд журналу аудиту як адміністратор | #49 \| 2026-10-30T14:30:30+00:00 \| alice \| ADMIN-AUDIT-ALLOW — перегляд журналу аудиту дозволено \| ALLOW \| peer=127.0.0.1:58825 \| session=bacff0ca \| details=limit=200 |
| 50. bob: спроба переглянути журнал аудиту без ролі адміністратора (очікувана відмова) | #50 \| 2026-10-30T14:30:30+00:00 \| bob \| ADMIN-AUDIT-DENY — перегляд журналу аудиту заборонено \| DENY \| peer=127.0.0.1:58826 \| session=e9fca27c \| reason=журнал дій доступний лише адміністратору |

## Повний журнал аудиту

```text
   ID TIME                USER         EVENT                    OBJECT         RESULT PEER
--------------------------------------------------------------------------------------------------------------------
    1 2026-10-30T14:30:30+00:00 alice        ENROLL-SUCCESS           -              allow  127.0.0.1:58821
    2 2026-10-30T14:30:30+00:00 bob          ENROLL-SUCCESS           -              allow  127.0.0.1:58822
    3 2026-10-30T14:30:30+00:00 carol        ENROLL-SUCCESS           -              allow  127.0.0.1:58823
    4 2026-10-30T14:30:30+00:00 dave         ENROLL-SUCCESS           -              allow  127.0.0.1:58824
    5 2026-10-30T14:30:30+00:00 alice        AUTH-SUCCESS             -              allow  127.0.0.1:58825
    6 2026-10-30T14:30:30+00:00 bob          AUTH-SUCCESS             -              allow  127.0.0.1:58826
    7 2026-10-30T14:30:30+00:00 carol        AUTH-SUCCESS             -              allow  127.0.0.1:58827
    8 2026-10-30T14:30:30+00:00 dave         AUTH-SUCCESS             -              allow  127.0.0.1:58828
    9 2026-10-30T14:30:30+00:00 alice        AUTH-FAILURE             -              deny   127.0.0.1:58829
                                                                                      └─ bad-response
   10 2026-10-30T14:30:30+00:00 mallory      AUTH-FAILURE             -              deny   127.0.0.1:58830
                                                                                      └─ unknown-user,bad-response
   11 2026-10-30T14:30:30+00:00 dave         AUTH-FAILURE             -              deny   127.0.0.1:58831
                                                                                      └─ disabled
   12 2026-10-30T14:30:30+00:00 alice        OBJECT-CREATE-ALLOW      ts-plan        allow  127.0.0.1:58825
   13 2026-10-30T14:30:30+00:00 alice        OBJECT-CREATE-ALLOW      ts-keys        allow  127.0.0.1:58825
   14 2026-10-30T14:30:30+00:00 alice        OBJECT-CREATE-ALLOW      ts-notes       allow  127.0.0.1:58825
   15 2026-10-30T14:30:30+00:00 bob          OBJECT-CREATE-ALLOW      s-report       allow  127.0.0.1:58826
   16 2026-10-30T14:30:30+00:00 bob          OBJECT-CREATE-ALLOW      s-design       allow  127.0.0.1:58826
   17 2026-10-30T14:30:30+00:00 bob          OBJECT-CREATE-ALLOW      s-tasks        allow  127.0.0.1:58826
   18 2026-10-30T14:30:30+00:00 carol        OBJECT-CREATE-ALLOW      c-budget       allow  127.0.0.1:58827
   19 2026-10-30T14:30:30+00:00 carol        OBJECT-CREATE-ALLOW      c-contacts     allow  127.0.0.1:58827
   20 2026-10-30T14:30:30+00:00 dave         OBJECT-CREATE-ALLOW      u-readme       allow  127.0.0.1:58828
   21 2026-10-30T14:30:30+00:00 dave         OBJECT-CREATE-ALLOW      u-faq          allow  127.0.0.1:58828
   22 2026-10-30T14:30:30+00:00 bob          OBJECT-READ-ALLOW        s-report       allow  127.0.0.1:58826
   23 2026-10-30T14:30:30+00:00 alice        OBJECT-READ-DENY         s-report       deny   127.0.0.1:58825
                                                                                      └─ дискреційна відмова: немає права 'read' в ACL об'єкта
   24 2026-10-30T14:30:30+00:00 bob          OBJECT-GRANT-ALLOW       s-report       allow  127.0.0.1:58826
   25 2026-10-30T14:30:30+00:00 alice        OBJECT-READ-ALLOW        s-report       allow  127.0.0.1:58825
   26 2026-10-30T14:30:30+00:00 alice        OBJECT-APPEND-DENY       s-report       deny   127.0.0.1:58825
                                                                                      └─ дискреційна відмова: немає права 'append' в ACL об'єкта
   27 2026-10-30T14:30:30+00:00 bob          OBJECT-GRANT-ALLOW       s-report       allow  127.0.0.1:58826
   28 2026-10-30T14:30:30+00:00 alice        OBJECT-APPEND-DENY       s-report       deny   127.0.0.1:58825
                                                                                      └─ no-write-down: clearance TOP_SECRET > classification SECRET
   29 2026-10-30T14:30:30+00:00 alice        OBJECT-GRANT-ALLOW       ts-plan        allow  127.0.0.1:58825
   30 2026-10-30T14:30:30+00:00 dave         OBJECT-READ-DENY         ts-plan        deny   127.0.0.1:58828
                                                                                      └─ no-read-up: clearance UNCLASSIFIED < classification TOP_SECRET
   31 2026-10-30T14:30:30+00:00 bob          OBJECT-GRANT-ALLOW       s-report       allow  127.0.0.1:58826
   32 2026-10-30T14:30:30+00:00 carol        OBJECT-READ-DENY         s-report       deny   127.0.0.1:58827
                                                                                      └─ no-read-up: clearance CONFIDENTIAL < classification SECRET
   33 2026-10-30T14:30:30+00:00 bob          OBJECT-GRANT-ALLOW       s-report       allow  127.0.0.1:58826
   34 2026-10-30T14:30:30+00:00 carol        OBJECT-APPEND-ALLOW      s-report       allow  127.0.0.1:58827
   35 2026-10-30T14:30:30+00:00 carol        OBJECT-DELETE-DENY       s-report       deny   127.0.0.1:58827
                                                                                      └─ дискреційна відмова: немає права 'delete' в ACL об'єкта
   36 2026-10-30T14:30:30+00:00 bob          OBJECT-DELETE-ALLOW      s-tasks        allow  127.0.0.1:58826
   37 2026-10-30T14:30:30+00:00 carol        OBJECT-READ-DENY         s-tasks        deny   127.0.0.1:58827
                                                                                      └─ object-not-found
   38 2026-10-30T14:30:30+00:00 carol        OBJECT-CREATE-DENY       c-low          deny   127.0.0.1:58827
                                                                                      └─ no-write-down: clearance CONFIDENTIAL > classification UNCLASSIFIED
   39 2026-10-30T14:30:30+00:00 bob          OBJECT-WRITE-ALLOW       s-report       allow  127.0.0.1:58826
   40 2026-10-30T14:30:30+00:00 dave         OBJECT-APPEND-ALLOW      u-readme       allow  127.0.0.1:58828
   41 2026-10-30T14:30:30+00:00 bob          OBJECT-REVOKE-ALLOW      s-report       allow  127.0.0.1:58826
   42 2026-10-30T14:30:30+00:00 carol        OBJECT-READ-DENY         s-report       deny   127.0.0.1:58827
                                                                                      └─ дискреційна відмова: немає права 'read' в ACL об'єкта
   43 2026-10-30T14:30:30+00:00 alice        SESSION-WHOAMI-ALLOW     -              allow  127.0.0.1:58825
   44 2026-10-30T14:30:30+00:00 alice        OBJECT-LIST-ALLOW        -              allow  127.0.0.1:58825
   45 2026-10-30T14:30:30+00:00 bob          OBJECT-INFO-ALLOW        s-report       allow  127.0.0.1:58826
   46 2026-10-30T14:30:30+00:00 bob          OBJECT-INFO-DENY         no-such-object deny   127.0.0.1:58826
                                                                                      └─ object-not-found
   47 2026-10-30T14:30:30+00:00 alice        ADMIN-INVENTORY-ALLOW    -              allow  127.0.0.1:58825
   48 2026-10-30T14:30:30+00:00 bob          ADMIN-INVENTORY-DENY     -              deny   127.0.0.1:58826
                                                                                      └─ інвентаризація доступна лише адміністратору
   49 2026-10-30T14:30:30+00:00 alice        ADMIN-AUDIT-ALLOW        -              allow  127.0.0.1:58825
   50 2026-10-30T14:30:30+00:00 bob          ADMIN-AUDIT-DENY         -              deny   127.0.0.1:58826
                                                                                      └─ журнал дій доступний лише адміністратору
```

## Підсумок

* Кроків сценарію: **50**
* Записів аудиту: **50** (дозволено — 35, відмовлено — 15)
* Протокол: `D:\cybersecurity\lab10\logs\lab10_audit_protocol.md`
