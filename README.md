!!! WARNING WARNING WARNING !!!
Read carefully before using.

# MCP Debugger - Windows Installer

> EN: This repository only contains the Windows setup base. Anything generated during installation (virtual environments, certificates, caches, etc.) must stay out of Git and is covered by `.gitignore`.
>
> DE: Dieses Repository enthaelt nur die Windows-Setup-Basis. Alle beim Einrichten entstehenden Artefakte (virtuelle Umgebungen, Zertifikate, Caches usw.) gehoeren nicht in Git und werden ueber `.gitignore` ausgeschlossen.

---

## English

### What Is MCP Debugger?
MCP Debugger (aka MCP Diagnoser PRO) is a desktop toolkit for exercising MCP servers end-to-end. It spins up a local Python runtime, launches the GUI, and lets you run targeted or bulk diagnostics against your server implementations.

### Key Features
- One-click Windows installer script (`setup_and_run.bat`) that provisions a virtual environment, installs dependencies, and starts the GUI.
- Visual workflows for running individual MCP tool calls, audits, and exporting logs.
- Certificate helper (`certgen_ca_server.py`) to create localhost-ready CA and server certificates for TLS testing.

### Diagnostics Coverage Schema
| Area | What Gets Exercised | Notes |
| --- | --- | --- |
| Streaming (SSE) | Negotiates event streams, enforces `sse_max_seconds`, captures raw payloads for review. | Validates graceful handling when a server keeps streaming or falls back to JSON. |
| Authentication (OAuth2 / Bearer) | Sends requests with configured access tokens or client credentials. | Ensure tokens are scoped to lab systems; tool does not obtain tokens for you. |
| Destructive Commands (Delete / Reset) | Invokes high-impact tool methods, including delete or purge operations. | Always isolate target systems; responses are logged for later auditing. |
| Error & Validation Paths | Calls `rpc/does_not_exist`, malformed `tools/call`, and schema edge cases. | Confirms servers return JSON-RPC errors instead of hanging. |
| Performance & Timeouts | Measures per-call latency, payload sizes, and concurrency behaviour. | Tune `--timeout`, `--per-timeout`, and parallelism to match lab capacity. |

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

### !!! WARNING WARNING WARNING !!!
The **Run all audit** action executes every available tool and scenario against the selected MCP server. This can trigger security-sensitive or destructive operations.

**Only run inside an isolated lab or disposable environment.** Validate with single-tool tests first and confirm no production systems are in scope.

### CLI Quick Start
```powershell
.\.venv\Scripts\python.exe mcp_diag_pro.py overall --url https://localhost:8443/mcp --timeout 30
.\.venv\Scripts\python.exe mcp_diag_pro.py audit   --url https://localhost:8443/mcp --parallel 4 --per-timeout 8
```

Refer to `mcp_diag_pro.py --help` for the complete parameter list.

---

## Deutsch

### Was ist der MCP Debugger?
Der MCP Debugger (MCP Diagnoser PRO) ist ein Desktop-Werkzeug, um MCP-Server End-to-End zu testen. Er richtet lokal eine Python-Laufzeit ein, startet die GUI und erlaubt zielgerichtete oder umfangreiche Diagnoselaeufe gegen deine Server.

### Wichtige Funktionen
- Windows-Installer-Skript (`setup_and_run.bat`), das eine virtuelle Umgebung aufbaut, Abhaengigkeiten installiert und die GUI startet.
- Visuelle Oberflaeche zum Ausfuehren einzelner Tool-Calls, Audit-Laeufe und zum Exportieren von Logs.
- Zertifikats-Helfer (`certgen_ca_server.py`) fuer eine lokale Root-CA und Server-Zertifikate fuer TLS-Tests auf localhost.

### Test-Schema
| Bereich | Was geprueft wird | Hinweise |
| --- | --- | --- |
| Streaming (SSE) | Verhandelt Event-Streams, erzwingt `sse_max_seconds`, protokolliert Rohdaten. | Prueft Verhalten bei endlosen oder JSON-Fallback-Antworten. |
| Authentifizierung (OAuth2 / Bearer) | Sendet Requests mit hinterlegten Tokens oder Client-Credentials. | Tokens muessen fuer die Laborumgebung vorgesehen sein; Beschaffung erfolgt extern. |
| Destruktive Kommandos (Delete / Reset) | Fuehrt Werkzeuge mit Loesch- oder Bereinigungswirkung aus. | Nur auf isolierten Zielsystemen einsetzen; Antworten werden fuer Audits gespeichert. |
| Fehler- und Validierungspfade | Ruft `rpc/does_not_exist`, fehlerhafte `tools/call` und Schema-Grenzfaelle auf. | Sicherstellt, dass Server JSON-RPC-Fehler liefern statt zu haengen. |
| Performance & Timeouts | Misst Latenz, Payload-Groessen und Parallelisierung. | Passe `--timeout`, `--per-timeout` und Parallel-Parameter an die Labor-Kapazitaet an. |

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

### !!! WARNUNG WARNUNG WARNUNG !!!
Der Button **Run all audit** fuehrt saemtliche verfuegbaren Tools und Szenarien gegen den ausgewaehlten MCP-Server aus. Dabei koennen sicherheitskritische oder destruktive Aktionen angestossen werden.

**Nur in einer isolierten Test- oder Laborumgebung ausfuehren!** Fuehre vorher einzelne Tests aus und stelle sicher, dass keine produktiven Systeme betroffen sind.

### CLI Schnellstart
```powershell
.\.venv\Scripts\python.exe mcp_diag_pro.py overall --url https://localhost:8443/mcp --timeout 30
.\.venv\Scripts\python.exe mcp_diag_pro.py audit   --url https://localhost:8443/mcp --parallel 4 --per-timeout 8
```

Weitere Optionen listet `mcp_diag_pro.py --help` auf.
