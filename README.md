!!! WARNING WARNING WARNING !!!
Read carefully before using.

# MCP Debugger - Windows Installer
*Current release: MCP Diagnoser v4.3*


> EN: This repository only contains the Windows setup base. Anything generated during installation (virtual environments, certificates, caches, etc.) must stay out of Git and is covered by `.gitignore`.
>
> DE: Dieses Repository enthaelt nur die Windows-Setup-Basis. Alle beim Einrichten entstehenden Artefakte (virtuelle Umgebungen, Zertifikate, Caches usw.) gehoeren nicht in Git und werden ueber `.gitignore` ausgeschlossen.

---

## English

### What Is MCP Debugger?
MCP Debugger (aka MCP Diagnoser PRO) is a desktop toolkit for exercising HTTP/SSE-based MCP servers end-to-end. It spins up a local Python runtime, launches the GUI, and lets you run targeted or bulk diagnostics against your server implementations, including streaming event sources.

### Key Features
### What's new in v4.3
- Live connection monitor with heartbeat + JSON validation.
- Kontext-Navigator mit Scrollbar, Tool-Runner und Fehlerhinweisen.
- Fortschrittsdialog beim "Run all"-Gesamttest, damit die GUI nicht einfriert.
- Neues Ereignis-Tab und Logfilter mit Suchfeld, Warnungsmodus und Laufnummern.
- Erweiterte Testlabor-Szenarien (Timeout, große Payload, fehlender Accept-Header).
- Neue Eingabemethoden-Ansicht zeigt verfügbare Auth/Input-Kanäle aus den Capabilities.
- Ressourcen-Browser inkl. Inhaltsanzeige und Formatvalidierung (JSON/YAML/Markdown).

- One-click Windows installer script (`setup_and_run.bat`) that creates the virtual environment, installs dependencies, and starts the GUI.
- Guided workflows for individual tool calls, "Run all" audits with progress dialog, and detailed export options (JSON, .http, ZIP report).
- Live-Verbindung-Monitor (SSE) mit Herzschlag-Überwachung, JSON-Validierung und Event-Log.
- Kontext-Navigator mit Ebenenübersicht (Handshake, Tools, Prompts, Ressourcen) inkl. direktem Tool-Start und JSON-Details.
- Ereignistab + Log-Filter (Suchfeld, Warnungsmodus, Laufnummern) für eine schnelle Fehlersuche.
- Testlabor für typische Fehlerszenarien (ungültige Argumente, unbekannte Methoden, SSE-Abbruch, Mini-Timeout, große Payload, fehlender Accept-Header).

#### Input & Resource Utilities
- **Input Methods** viewer surfaces authentication/input capabilities (including experimental entries) so you can inspect available channels before triggering tools.
- **Resource Browser** lists `resources/list` entries, fetches contents via `resources/read`, and lets you validate JSON/YAML/Markdown payloads with one click.
- Certificate helper (`certgen_ca_server.py`) to create localhost-ready CA and server certificates for TLS testing.

### Diagnostics Coverage Schema
| Area | What Gets Exercised | Notes |
| --- | --- | --- |
| Streaming (SSE) | Negotiates event streams, enforces `sse_max_seconds`, captures raw payloads for review. | Validates graceful handling when a server keeps streaming or falls back to JSON. |
| HTTP Transport | Exercises initialize/tool/resource endpoints over HTTPS with detailed logging and cURL export. | Highlights latency, headers, TLS trust mode, and retry behaviour. |
| Authentication (OAuth2 / Bearer) | Sends requests with configured access tokens or client credentials. | Ensure tokens are scoped to lab systems; tool does not obtain tokens for you. |
| Destructive Commands (Delete / Reset) | Invokes high-impact tool methods, including delete or purge operations. | Always isolate target systems; responses are logged for later auditing. |
| Error & Validation Paths | Calls `rpc/does_not_exist`, malformed `tools/call`, and schema edge cases. | Confirms servers return JSON-RPC errors instead of hanging. |
| Performance & Timeouts | Measures per-call latency, payload sizes, token estimates, and concurrency behaviour. | Tune `--timeout`, `--per-timeout`, and parallelism to match lab capacity. |

### Windows Installation
1. Ensure Python 3.10 or newer is available via `py -3` or `python` in your PATH.
2. Run `setup_and_run.bat` either via double-click or from PowerShell (`.\setup_and_run.bat`).
3. The script creates `.venv`, upgrades `pip`, installs `requirements.txt`, and launches `mcp_diag_pro.py`.
4. Configure profiles in the GUI, execute checks, and review results once the app is up.

### Generating Certificates
Use the helper to mint a root CA plus localhost server certificate:

```powershell
.\.venv\Scripts\python.exe certgen_ca_server.py --out-dir certs\localhost --cn localhost --days 365
```

- Outputs include `ca.cert.pem`, `ca.key.pem`, `localhost.cert.pem`, `localhost.key.pem`, and `ca_thumbprint.txt`.
- Import `ca.cert.pem` into your trusted root store when you need browsers or clients to trust the test server.

### Connecting to a Server
1. Launch the GUI via `setup_and_run.bat` if it is not already running.
2. Add a profile with the target MCP endpoint URL.
3. Attach client certificates from the generated bundle if your server requires them.
4. Start with a focused request (for example `tools/list`) before triggering larger audits.

### TLS Modes Explained
- `System Trust`: Uses the Windows trust store. Ideal when your MCP endpoint has a certificate trusted by the OS.
- `Embedded CA (./certs/ca.cert.pem)`: Relies on the CA generated via `certgen_ca_server.py`. Use this for localhost testing with self-signed roots.
- `Pick file...`: Lets you point to any other PEM bundle (for example a corporate CA). The wizard stores the path for reuse.
- `Insecure (not recommended)`: Disables TLS validation. Only acceptable inside an isolated lab with throwaway data. Never send secrets in this mode.

### !!! WARNING WARNING WARNING !!!
The **Run all audit** action executes every available tool and scenario against the selected MCP server. This can trigger security-sensitive or destructive operations.

**Only run inside an isolated lab or disposable environment.** Validate with single-tool tests first and confirm no production systems are in scope.

### CLI Quick Start
```powershell
.\.venv\Scripts\python.exe mcp_diag_pro.py overall --url https://localhost:8443/mcp --timeout 30
.\.venv\Scripts\python.exe mcp_diag_pro.py audit   --url https://localhost:8443/mcp --parallel 4 --per-timeout 8
```

Refer to `mcp_diag_pro.py --help` for the complete parameter list.

### Audit Metrics Reference
| Column | Description | Why it matters |
| --- | --- | --- |
| `ms` | Wall-clock latency of the tool call. | Highlights slow handlers, retries, or network delays. |
| `Tokens` | Estimated combined tokens (result metadata or character-based fallback). | Reveals output size growth and possible quota pressure. |
| `KB` | Size of the JSON payload captured from the response. | Helps spot unusually large responses or streaming issues. |
| `Detail` | Status notes (`OUTPUT_VALID`, HTTP codes, schema errors, etc.). | Pinpoints failing steps in the call pipeline. |

---

## Deutsch

### Was ist der MCP Debugger?
Der MCP Debugger (MCP Diagnoser PRO) ist ein Desktop-Werkzeug, um HTTP/SSE-basierte MCP-Server End-to-End zu testen. Er richtet lokal eine Python-Laufzeit ein, startet die GUI und erlaubt zielgerichtete oder umfangreiche Diagnoselaeufe gegen deine Server – inklusive Streaming-Events.

### Wichtige Funktionen
### Neu in v4.3
- Live-Verbindungsmonitor mit Herzschlagwarnung und JSON-Pruefung.
- Kontext-Navigator mit Scrollbar, Tool-Runner und Hinweisbereich.
- Fortschrittsdialog fuer den Gesamttest, damit die GUI weiterhin reagiert.
- Neues Ereignis-Tab und Log-Filter (Stichwort, Warnmodus, Laufnummern).
- Erweitertes Testlabor (Mini-Timeout, grosse Payload, fehlender Accept-Header).

- Windows-Installer-Skript (`setup_and_run.bat`), das eine virtuelle Umgebung aufbaut, Abhaengigkeiten installiert und die GUI startet.
- Gefuehrte Oberflaeche fuer Einzeltests, "Run all"-Audits mit Fortschrittsdialog und umfangreiche Exportoptionen (JSON, .http, ZIP).
- Live-Verbindungsmonitor (SSE) mit Herzschlagwarnung, JSON-Check und Ereignisprotokoll.
- Kontext-Navigator mit Ebenenuebersicht (Handshake, Tools, Prompts, Ressourcen) und direktem Tool-Start.
- Ereignistab + Logfilter (Suchfeld, Warnmodus, Laufnummern) fuer eine schnelle Fehlersuche.
- Testlabor fuer typische Fehlerszenarien (ungueltige Argumente, unbekannte Methoden, SSE-Abbruch, Mini-Timeout, grosse Payload, fehlender Accept-Header).
- Zertifikats-Helfer (`certgen_ca_server.py`) fuer eine lokale Root-CA und Server-Zertifikate fuer TLS-Tests auf localhost.

### Test-Schema
| Bereich | Was geprueft wird | Hinweise |
| --- | --- | --- |
| Streaming (SSE) | Verhandelt Event-Streams, erzwingt `sse_max_seconds`, protokolliert Rohdaten. | Prueft Verhalten bei endlosen oder JSON-Fallback-Antworten. |
| HTTP-Transport | Testet initialize/tool/resource-Endpunkte inkl. TLS-Handshake und Header-Logging. | Hebt Latenzen, TLS-Modus und Wiederholstrategien hervor. |
| Authentifizierung (OAuth2 / Bearer) | Sendet Requests mit hinterlegten Tokens oder Client-Credentials. | Tokens muessen fuer die Laborumgebung vorgesehen sein; Beschaffung erfolgt extern. |
| Destruktive Kommandos (Delete / Reset) | Fuehrt Werkzeuge mit Loesch- oder Bereinigungswirkung aus. | Nur auf isolierten Zielsystemen einsetzen; Antworten werden fuer Audits gespeichert. |
| Fehler- und Validierungspfade | Ruft `rpc/does_not_exist`, fehlerhafte `tools/call` und Schema-Grenzfaelle auf. | Sicherstellt, dass Server JSON-RPC-Fehler liefern statt zu haengen. |
| Performance & Timeouts | Misst Latenz, Payload-Groessen, Token-Schaetzungen und Parallelisierung. | Passe `--timeout`, `--per-timeout` und Parallel-Parameter an die Labor-Kapazitaet an. |

### Installation unter Windows
1. Stelle sicher, dass Python 3.10 oder neuer ueber `py -3` oder `python` im PATH erreichbar ist.
2. Fuehre `setup_and_run.bat` per Doppelklick oder in PowerShell (`.\setup_and_run.bat`) aus.
3. Das Skript legt `.venv` an, aktualisiert `pip`, installiert `requirements.txt` und startet `mcp_diag_pro.py`.
4. Lege im Anschluss Profile in der GUI an, fuehre Checks aus und kontrolliere die Ergebnisse.

### Zertifikate erzeugen
Erstelle eine Root-CA plus Server-Zertifikat fuer localhost:

```powershell
.\.venv\Scripts\python.exe certgen_ca_server.py --out-dir certs\localhost --cn localhost --days 365
```

- Erstellt `ca.cert.pem`, `ca.key.pem`, `localhost.cert.pem`, `localhost.key.pem` sowie `ca_thumbprint.txt`.
- Importiere `ca.cert.pem` in den vertrauenswuerdigen Stammzertifikatsspeicher, wenn Browser oder Clients dem Test-Server vertrauen sollen.

### Verbindung herstellen
1. Starte die GUI ueber `setup_and_run.bat`, falls sie nicht laeuft.
2. Lege ein Profil mit der Ziel-URL deines MCP-Servers an.
3. Hinterlege bei Bedarf Client-Zertifikate aus dem erzeugten Paket.
4. Beginne mit einem gezielten Test (z. B. `tools/list`), bevor du grosse Audit-Laeufe startest.

### TLS-Modi erklaert
- `System Trust`: Verwendet den Windows-Zertifikatsspeicher. Ideal, wenn das MCP-Zertifikat bereits vertrauenswuerdig ist.
- `Embedded CA (./certs/ca.cert.pem)`: Nutzt die per `certgen_ca_server.py` erzeugte Root-CA. Perfekt fuer lokale Self-Signed-Szenarien.
- `Pick file...`: Erlaubt das Auswaehlen eines beliebigen PEM-Bundles (z. B. Firmen-CA). Der Pfad wird fuer spaetere Sitzungen gemerkt.
- `Insecure (not recommended)`: Schaltet TLS-Pruefungen ab. Nur in abgeschotteten Laborumgebungen verwenden und niemals sensible Daten senden.

### !!! WARNUNG WARNUNG WARNUNG !!!
Der Button **Run all audit** fuehrt saemtliche verfuegbaren Tools und Szenarien gegen den ausgewaehlten MCP-Server aus. Dabei koennen sicherheitskritische oder destruktive Aktionen angestossen werden.

**Nur in einer isolierten Test- oder Laborumgebung ausfuehren!** Fuehre vorher einzelne Tests aus und stelle sicher, dass keine produktiven Systeme betroffen sind.

### CLI Schnellstart
```powershell
.\.venv\Scripts\python.exe mcp_diag_pro.py overall --url https://localhost:8443/mcp --timeout 30
.\.venv\Scripts\python.exe mcp_diag_pro.py audit   --url https://localhost:8443/mcp --parallel 4 --per-timeout 8
```

Weitere Optionen listet `mcp_diag_pro.py --help` auf.

### Audit-Metriken im Ueberblick
| Spalte | Bedeutung | Nutzen |
| --- | --- | --- |
| `ms` | Gemessene Laufzeit je Tool-Aufruf. | Zeigt langsame Handler, Timeouts oder Netzlatenzen. |
| `Tokens` | Geschaetzte Token-Anzahl (aus Usage-Daten oder Zeichenanzahl). | Macht wachsende Outputs und moegliche Kontingentprobleme sichtbar. |
| `KB` | Groesse der Antwort-Payload (JSON) in Kilobyte. | Entdeckt unueblich grosse Antworten oder Streaming-Anomalien. |
| `Detail` | Statushinweise (`OUTPUT_VALID`, HTTP-Codes, Schemafehler, ...). | Lokalisiert Fehlerpunkte innerhalb der Call-Pipeline. |
