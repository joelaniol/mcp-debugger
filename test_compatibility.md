# MCP Server Kompatibilitätstests

## Diagnosetool-Ansatz (v4.3+)

**Der MCP Debugger nutzt die neueste Protokoll-Version (`2025-03-26`)** und erkennt automatisch wenn Server veraltete Versionen verwenden.

### Legacy-Detection

Der Debugger zeigt automatisch Warnungen an wenn:
- Server nutzt **2024-11-05** (Legacy SSE-based): `⚠ LEGACY`
- Server nutzt ältere Version als Client: `⚠ OUTDATED`

Diese Warnungen erscheinen in:
1. **Overall Summary** - INFO-Level mit Details
2. **MCP Info Dialog** - Bei Protokoll-Version
3. **Context Navigator** - Bei Handshake-Details

## Getestete Server-Typen

### ✅ Vollständig Kompatibel
- **Moderne Server (2025-03-26+)**: Native Kompatibilität
- **Filesystem MCP**: Legacy-Support (automatisch erkannt)
- **Playwright MCP** (Microsoft): Legacy-Support (automatisch erkannt)
- **SQLite MCP**: Legacy-Support
- **Git MCP**: Legacy-Support
- **Fetch MCP**: Legacy-Support

### ⚙️ Automatische Abwärtskompatibilität

Der Debugger nutzt **2025-03-26** als Default, unterstützt aber automatisch:
- SSE-Transport (2024-11-05 Legacy)
- Chunked HTTP Streaming (2025-03-26+)
- JSON-only Fallback

## Bekannte Probleme

### 1. Strikte Version-Prüfung
**Problem:** Server akzeptiert nur exakte Version
**Lösung:** Protocol-Version-Override in initialize() Payload

### 2. Chunked HTTP statt SSE
**Problem:** Server sendet kein SSE sondern chunked transfer
**Status:** Code hat Fallback auf JSON (Zeile 154-157)

### 3. OAuth 2.1 Flow
**Problem:** Server erfordert vollständigen OAuth-Flow
**Lösung:** Bearer Token manuell besorgen und in Headers eintragen

## Test-Kommandos

### Playwright MCP Server testen:
```powershell
# Start Playwright MCP Server
npx @playwright/mcp@latest

# In MCP Debugger:
URL: http://localhost:3000/mcp
TLS: Insecure (localhost)
Timeout: 30
```

### Filesystem MCP testen:
```powershell
# Start Filesystem MCP
npx @modelcontextprotocol/server-filesystem .

# In MCP Debugger:
URL: http://localhost:3001/mcp
```

## Verbesserungsvorschläge

1. **Multi-Version-Support:**
   - Dropdown in GUI für Protokoll-Version
   - Auto-Negotiation basierend auf Server-Response

2. **Chunked HTTP Streaming:**
   - Zusätzlich zu SSE implementieren
   - Auto-Detection basierend auf Content-Type

3. **OAuth 2.1 Wizard:**
   - Guided Flow für OAuth-Setup
   - Token-Refresh-Handling
