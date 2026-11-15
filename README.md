# SecureOps Lab

SecureOps Lab to celowo podatna aplikacja laboratoryjna w stylu DVWA. Projekt ma sluzyc jako kontrolowany cel do recznego pentestu, rozwijany o kolejne moduly podatnosci aplikacyjnych i chmurowych.

## Cel Projektu

Projekt nie jest systemem produkcyjnym ani pelnym narzedziem SOC. Jego celem jest udostepnienie aplikacji z wlaczanymi podatnosciami, ktore mozna recznie testowac, dokumentowac i opisywac w raporcie pentestowym do pracy magisterskiej.

## Stos Technologiczny

- .NET API jako aplikacja podatna.
- PostgreSQL jako baza danych uzytkownikow, dokumentow laboratoryjnych i audytu.
- LocalStack jako lokalna emulacja wybranych uslug AWS, obecnie S3 i CloudWatch Logs.
- Docker Compose jako sposob uruchomienia API, bazy i LocalStack.

## Struktura Projektu

Backend zachowuje podzial na projekty, ale pozostaje prosty:

- `SecureOpsLab.Api` - kontrolery HTTP, Swagger, konfiguracja i start aplikacji.
- `SecureOpsLab.Application` - logika modulow podatnosci, opcje labu, stale testowych identyfikatorow i abstrakcja dostepu do danych.
- `SecureOpsLab.Contracts` - odpowiedzi zwracane przez API.
- `SecureOpsLab.Domain` - encje domenowe uzywane przez moduly podatnosci.
- `SecureOpsLab.Infrastructure` - Entity Framework Core, PostgreSQL i seeding bazy.

Zaleznosci sa jednokierunkowe: `Api` wywoluje `Application`, `Application` nie zna `Infrastructure`, a `Infrastructure` tylko implementuje dostep do danych wymagany przez `Application`.

## Uruchomienie

```bash
docker compose up --build
```

Adresy uslug:

- UI: `http://localhost:8080`
- API: `http://localhost:8080`
- Swagger: `http://localhost:8080/swagger`
- Katalog podatnosci: `http://localhost:8080/api/vulnerabilities`
- PostgreSQL: `localhost:5432`
- LocalStack edge: `http://localhost:4566`
- Detekcje z logow chmurowych: `http://localhost:8080/api/detections/cloud`

## Moduly Podatnosci

Podatnosci sa konfigurowane w sekcji `SecurityLab:Vulnerabilities`. W Docker Compose uzywany jest zapis z podwojnym podkresleniem, np.:

```yaml
SecurityLab__Vulnerabilities__A01BrokenAccessControl: "true"
SecurityLab__Vulnerabilities__A02CryptographicFailures: "true"
SecurityLab__Vulnerabilities__A03Injection: "true"
SecurityLab__Vulnerabilities__A04InsecureDesign: "true"
SecurityLab__Vulnerabilities__A05SecurityMisconfiguration: "true"
SecurityLab__Vulnerabilities__A06VulnerableComponents: "true"
SecurityLab__Vulnerabilities__A07IdentificationAuthenticationFailures: "true"
SecurityLab__Vulnerabilities__A08SoftwareDataIntegrityFailures: "true"
SecurityLab__Vulnerabilities__A09SecurityLoggingMonitoringFailures: "true"
SecurityLab__Vulnerabilities__A10ServerSideRequestForgery: "true"
```

Znaczenie wartosci:

- `true` oznacza, ze podatnosc jest aktywna i aplikacja zachowuje sie celowo niebezpiecznie.
- `false` oznacza, ze dana podatnosc jest wylaczona i aplikacja stosuje oczekiwana kontrole bezpieczenstwa.

Konfiguracja ustawia stan startowy po uruchomieniu kontenera. Po starcie aplikacji moduly mozna przelaczac bez restartu z UI albo przez API:

```http
PUT /api/vulnerabilities/A01-IDOR/enabled
Content-Type: application/json

{ "enabled": false }
```

Ten stan jest runtime-only: po restarcie aplikacja ponownie startuje z wartosci z `SecurityLab:Vulnerabilities`.

Aktualne moduly:

- `A01-IDOR`: Broken Access Control / IDOR na endpointzie `GET /api/vulnerabilities/a01-broken-access-control/documents/{id}`.
- `A02-CRYPTO`: Cryptographic Failures / Secret Exposure na endpointzie `GET /api/vulnerabilities/a02-cryptographic-failures/secrets/export`.
- `A03-SQLI`: Injection / SQL Injection na endpointzie `GET /api/vulnerabilities/a03-injection/documents/search?term={term}`.
- `A04-DESIGN`: Insecure Design / Approval Bypass na endpointzie `GET /api/vulnerabilities/a04-insecure-design/emergency-access`.
- `A05-S3`: Security Misconfiguration / Object Storage na endpointzie `GET /api/vulnerabilities/a05-security-misconfiguration/objects/{documentId}`.
- `A06-COMPONENTS`: Vulnerable and Outdated Components na endpointzie `GET /api/vulnerabilities/a06-vulnerable-components/render?payload={payload}`.
- `A07-AUTH`: Identification and Authentication Failures na endpointzie `GET /api/vulnerabilities/a07-identification-authentication/default-login?password={password}`.
- `A08-INTEGRITY`: Software and Data Integrity Failures na endpointzie `GET /api/vulnerabilities/a08-software-data-integrity/update?packageUrl={url}`.
- `A09-LOGGING`: Security Logging and Monitoring Failures na endpointzie `GET /api/vulnerabilities/a09-logging-monitoring/admin-export`.
- `A10-SSRF`: Server-Side Request Forgery na endpointzie `GET /api/vulnerabilities/a10-ssrf/fetch?url={url}`.

## Scenariusz A01 IDOR

Scenariusz sprawdza, czy uzytkownik Alice moze odczytac dokument nalezacy do Boba przez zmiane identyfikatora obiektu w URL.

Dane testowe:

- Alice: `11111111-1111-1111-1111-111111111111`
- Bob: `22222222-2222-2222-2222-222222222222`
- Dokument Alice: `aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa`
- Dokument Boba: `bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb`

Przykladowe zadanie do wykonania recznie w Swaggerze, Burp Suite, OWASP ZAP albo dowolnym kliencie HTTP:

Ten sam scenariusz mozna tez wykonac z prostego UI pod adresem `http://localhost:8080`.

```http
GET /api/vulnerabilities/a01-broken-access-control/documents/bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb
X-Lab-User-Id: 11111111-1111-1111-1111-111111111111
```

Oczekiwany wynik przy aktywnej podatnosci:

```yaml
SecurityLab__Vulnerabilities__A01BrokenAccessControl: "true"
```

- API zwraca `HTTP 200`.
- W odpowiedzi widac dokument Boba.
- To jest podatnosc IDOR, poniewaz aplikacja sprawdza tylko `LabDocument.Id`, ale nie sprawdza `LabDocument.OwnerId`.
- W UI kod `200` przy dokumencie obcego wlasciciela jest oznaczany jako dowod podatnosci, nie jako bezpieczny wynik.

Oczekiwany wynik po wylaczeniu podatnosci:

```yaml
SecurityLab__Vulnerabilities__A01BrokenAccessControl: "false"
```

- API zwraca `HTTP 404`.
- Dane Boba nie sa ujawnione Alice.
- Aplikacja filtruje rekordy po `LabDocument.Id` oraz `LabDocument.OwnerId`.
- Tryb mozna zmienic bez restartu przyciskiem w UI albo endpointem `PUT /api/vulnerabilities/A01-IDOR/enabled`.

## Scenariusz A03 SQL Injection

Scenariusz sprawdza, czy uzytkownik Alice moze obejsc filtr wlasciciela dokumentu przez wstrzykniecie warunku SQL do parametru wyszukiwania.

Normalne wyszukiwanie:

```http
GET /api/vulnerabilities/a03-injection/documents/search?term=Alice
X-Lab-User-Id: 11111111-1111-1111-1111-111111111111
```

Przykladowy payload SQL injection:

```http
GET /api/vulnerabilities/a03-injection/documents/search?term=%27%20OR%201%3D1%20--
X-Lab-User-Id: 11111111-1111-1111-1111-111111111111
```

Oczekiwany wynik przy aktywnej podatnosci:

```yaml
SecurityLab__Vulnerabilities__A03Injection: "true"
```

- API zwraca `HTTP 200`.
- W odpowiedzi widac dokumenty innych uzytkownikow, np. dokument Boba.
- To jest podatnosc SQL injection, poniewaz aplikacja sklada zapytanie SQL przez konkatenacje parametru `term`.

Oczekiwany wynik po wylaczeniu podatnosci:

```yaml
SecurityLab__Vulnerabilities__A03Injection: "false"
```

- Payload jest traktowany jak zwykly tekst wyszukiwania.
- API nie zwraca dokumentow innych uzytkownikow.
- Aplikacja filtruje po `OwnerId` i uzywa bezpiecznego filtrowania przez EF.
- Tryb mozna zmienic bez restartu przyciskiem w UI albo endpointem `PUT /api/vulnerabilities/A03-SQLI/enabled`.

## Scenariusz A05 Object Storage / LocalStack S3

Scenariusz sprawdza, czy uzytkownik Alice moze pobrac obiekt S3 powiazany z dokumentem Boba. Aplikacja komunikuje sie z LocalStack przez AWS SDK i tworzy bucket `secureops-lab-documents` podczas startu.

Przykladowe zadanie:

```http
GET /api/vulnerabilities/a05-security-misconfiguration/objects/bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb
X-Lab-User-Id: 11111111-1111-1111-1111-111111111111
```

Oczekiwany wynik przy aktywnej podatnosci:

```yaml
SecurityLab__Vulnerabilities__A05SecurityMisconfiguration: "true"
```

- API zwraca `HTTP 200`.
- W odpowiedzi widac obiekt z providera `LocalStack S3` i klucz `documents/bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb/evidence.txt`.
- To jest blad A05 w laboratorium, poniewaz aplikacja ma zbyt szeroka mozliwosc odczytu obiektow i nie sprawdza wlasciciela dokumentu przed pobraniem obiektu.

Oczekiwany wynik po wylaczeniu podatnosci:

```yaml
SecurityLab__Vulnerabilities__A05SecurityMisconfiguration: "false"
```

- API zwraca `HTTP 404` dla proby Alice do obiektu dokumentu Boba.
- Aplikacja przed pobraniem obiektu z S3 filtruje dokument po `OwnerId`.
- Tryb mozna zmienic bez restartu przyciskiem w UI albo endpointem `PUT /api/vulnerabilities/A05-S3/enabled`.

## Scenariusz A10 SSRF do LocalStack

Scenariusz sprawdza, czy uzytkownik moze zmusic serwer do odpytania wewnetrznego endpointu chmurowego. Z perspektywy uzytkownika host `localstack` nie jest publicznym adresem HTTP aplikacji, ale aplikacja dzialajaca w sieci Docker Compose moze go rozwiazac i odpytac.

Przykladowe zadanie:

```http
GET /api/vulnerabilities/a10-ssrf/fetch?url=http%3A%2F%2Flocalstack%3A4566%2F_localstack%2Fhealth
X-Lab-User-Id: 11111111-1111-1111-1111-111111111111
```

Oczekiwany wynik przy aktywnej podatnosci:

```yaml
SecurityLab__Vulnerabilities__A10ServerSideRequestForgery: "true"
```

- API zwraca `HTTP 200`.
- W odpowiedzi widac fragment odpowiedzi z LocalStack health, czyli serwer wykonal zadanie do wewnetrznego endpointu.
- Do CloudWatch Logs trafia alert `LAB-GENERIC-SSRF` z generycznego detektora oraz `LAB-A10-SSRF` z logiki scenariusza.

Oczekiwany wynik po wylaczeniu podatnosci:

```yaml
SecurityLab__Vulnerabilities__A10ServerSideRequestForgery: "false"
```

- API zwraca `HTTP 403`.
- Wewnętrzny host `localstack` zostaje zablokowany przed wykonaniem requestu.
- Do CloudWatch Logs nadal trafia `LAB-GENERIC-SSRF`, bo sama proba uzycia wewnetrznego celu jest podejrzana.
- Tryb mozna zmienic bez restartu przyciskiem w UI albo endpointem `PUT /api/vulnerabilities/A10-SSRF/enabled`.

## Analiza Logow Chmurowych

SecureOps Lab zapisuje zdarzenia bezpieczenstwa do LocalStack CloudWatch Logs w grupie `/secureops-lab/security-events` i streamie `lab-runtime`. Zdarzenia sa generowane przez scenariusze A01-A08 oraz A10. W scenariuszu A09 tryb podatny celowo nie zapisuje zdarzenia, poniewaz dowodem podatnosci jest brak telemetrii dla wrazliwej akcji. Logi sa analizowane przez endpoint:

```http
GET /api/detections/cloud
```

Przyklady zdarzen wykrywanych jako alerty:

- `SuspiciousHttpInput` -> `LAB-GENERIC-SQLI`, `LAB-GENERIC-XSS` albo `LAB-GENERIC-TRAVERSAL`, gdy generyczny detektor HTTP zobaczy podejrzany payload w URL lub query stringu.
- `SuspiciousHttpInput` -> `LAB-GENERIC-SSRF`, gdy generyczny detektor HTTP zobaczy probe odpytania wewnetrznego hosta albo zakresu IP.
- `CrossOwnerDocumentRead` -> `LAB-A01-IDOR`, gdy uzytkownik otrzyma dokument innego wlasciciela.
- `SensitiveSecretDisclosure` -> `LAB-A02-CRYPTO`, gdy endpoint zwroci plaintext secret.
- `SqlInjectionSearchBypass` -> `LAB-A03-SQLI`, gdy payload SQLi zwroci dokument innego wlasciciela.
- `BusinessRuleBypass` -> `LAB-A04-DESIGN`, gdy workflow wyda dostep bez wymaganego zatwierdzenia.
- `CrossOwnerObjectRead` -> `LAB-A05-S3`, gdy uzytkownik otrzyma obiekt S3 powiazany z dokumentem innego wlasciciela.
- `VulnerableComponentExploit` -> `LAB-A06-COMPONENTS`, gdy symulowany legacy component zaakceptuje exploit marker.
- `DefaultCredentialLogin` -> `LAB-A07-AUTH`, gdy domyslne haslo zostanie zaakceptowane.
- `UnsignedUpdateAccepted` -> `LAB-A08-INTEGRITY`, gdy workflow zaakceptuje niepodpisana paczke.
- `ServerSideRequestForgery` -> `LAB-A10-SSRF`, gdy serwer faktycznie pobierze wewnetrzny endpoint kontrolowany przez parametr uzytkownika.

To jest czesc badawcza pracy magisterskiej zwiazana z detekcja: najpierw wykonywany jest scenariusz ataku, potem aplikacja zapisuje zdarzenie do emulowanej uslugi chmurowej, a endpoint detekcji odczytuje logi i klasyfikuje zdarzenia jako alerty. Detektor generyczny dziala niezaleznie od tego, czy podatnosc faktycznie zostanie wykorzystana. Przyklad: payload SQL injection w trybie bezpiecznym A03 nie zwroci dokumentow innych uzytkownikow, ale nadal zostanie zapisany jako `LAB-GENERIC-SQLI`.

## Jak Robic Raport Pentestowy

Dla kazdego modulu zapisuj:

- nazwe podatnosci i kategorie OWASP,
- cel testu,
- warunki poczatkowe,
- wykonane zadania HTTP,
- odpowiedz aplikacji,
- zdarzenie w LocalStack CloudWatch Logs,
- alert z `GET /api/detections/cloud`,
- dowod podatnosci, np. body odpowiedzi albo wpis w bazie,
- wplyw biznesowy/techniczny,
- rekomendacje naprawy,
- wynik testu po wylaczeniu podatnosci.
