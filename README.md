# MCP Diagnoser v4.2 – Robust gegen strikt validierende Server

> Hinweis: Dieses Repository enthaelt nur die Setup- und Installationsbasis. Alle beim Einrichten entstehenden Artefakte (z. B. virtuelle Umgebungen oder Zertifikate) gehoeren nicht in Git und werden ueber .gitignore ausgeschlossen.

**Fixes**
- **Overall Summary hing bei 'rpc/does_not_exist'** auf streng typisierten Servern (Pydantic‑Validierung).
  - Der Fehler‑Probeaufruf nutzt nun **JSON‑only** (`Accept: application/json`) und **kein Streaming**.
  - Falls der Server trotzdem SSE liefert, wird die Antwort **nicht** gestreamt, sondern als Raw‑Body erfasst (kein Blockieren).
  - Fallback‑Probe: `tools/call` mit absichtlich **invalid params** (liefert i. d. R. `error`‑Objekt −32602).
- **Neue Call‑Parameter**: `accept_json_only`, `sse_max_seconds` (harte Abbruchgrenze beim SSE‑Lesen).
- **Per‑Step Fehlerrobustheit**: `Run all/Run overall` fängt Exceptions und zeigt zumindest eine Summary‑Zeile an.
- **Konsole/Log**: doppelte `_sink` entfernt; Log bleibt vollständig im Speicher.

**Weiterhin enthalten**
- MUST/SHOULD/OPTIONAL‑Summary, Overall‑Timeout, Audit mit Farben + ms/KB, cURL‑Export, `.http`‑Save, Profiles, Tree‑Viewer.

## Warum passierte das?
Einige MCP‑Server modellieren eingehende JSON‑RPC‑Requests über **Pydantic‑Unionen** bekannter Methoden. Unbekannte Methoden (z. B. `rpc/does_not_exist`) schlagen bereits **vor** der Handler‑Logik fehl (Validierungsfehler) und manche Implementierungen antworten dabei nicht mit einer regulären JSON‑RPC‑Fehlerstruktur. Der Diagnoser hing, wenn der Server zudem **SSE** auf POST lieferte. v4.2 vermeidet das zuverlässig.

## CLI‑Beispiel
```bat
.venv\Scripts\python.exe mcp_diag_pro.py overall --url https://localhost:8443/mcp --timeout 30
.venv\Scripts\python.exe mcp_diag_pro.py audit   --url https://localhost:8443/mcp --parallel 8 --per-timeout 8
```
