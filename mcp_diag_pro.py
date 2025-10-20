# -*- coding: latin-1 -*-
import argparse, json, time, threading, queue, sys, os, logging, zipfile, concurrent.futures, shlex, warnings, math, copy, urllib.parse
from contextlib import contextmanager
import requests
from sseclient import SSEClient
from jsonschema import Draft7Validator
from auth_utils import AuthState

try:
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox
    from tkinter.scrolledtext import ScrolledText
except Exception:
    tk = None
    ttk = None
    filedialog = None
    ScrolledText = None
    messagebox = None

DEFAULT_PROTOCOL_VERSION = "2025-03-26"  # Latest stable MCP spec (supports legacy servers)

# Known valid MCP protocol versions (in chronological order)
KNOWN_MCP_VERSIONS = [
    "2024-11-05",  # Initial release (SSE-based)
    "2025-03-26",  # OAuth 2.1 + chunked streaming
    # Future versions will be added here
]

LEGACY_MCP_VERSIONS = ["2024-11-05"]  # Versions that work but are outdated

# UI responsiveness tuning knobs (batch size, scheduling, log clipping)
LOG_PUMP_MAX_PER_TICK = 200           # Maximum log entries processed per UI tick
LOG_PUMP_FAST_DELAY_MS = 10           # Delay when backlog is pending (ms)
LOG_PUMP_NORMAL_DELAY_MS = 60         # Default idle delay between pumps (ms)
LOG_DISPLAY_CLIP = 6000               # Maximum characters rendered per log line
LOG_STORE_CLIP = 10000              # Maximum characters kept per log line in memory/console


TRANSLATIONS = {
    "Deutsch": {
        "Settings": "Einstellungen",
        "Language": "Sprache",
        "English": "Englisch",
        "Deutsch": "Deutsch",
    }
}

def ts():
    return time.strftime("%H:%M:%S")

class Sink:
    def __init__(self, gui_cb=None, mem_log=None):
        self.gui_cb=gui_cb
        self.mem_log = mem_log if mem_log is not None else []
        self.session_resets = 0
    def write(self, line):
        msg = f"[{ts()}] {line}"
        limit = getattr(self, '_log_store_limit', LOG_STORE_CLIP)
        if limit and len(msg) > limit:
            omitted = len(msg) - limit
            display = f"{msg[:limit]}... (gekuerzt, {omitted} weitere Zeichen unterdrueckt)"
        else:
            display = msg
        print(display, flush=True)
        self.mem_log.append(display)
        # Prevent memory leak: trim log if it grows too large
        if len(self.mem_log) > 10000:
            self.mem_log = self.mem_log[-5000:]
        if "Session-Objekt zurückgesetzt" in line or "Session-Objekt zur\u00fcckgesetzt" in line:
            self.session_resets += 1
        if self.gui_cb: self.gui_cb(display)


class MCP:
    def __init__(self, url, verify=True, timeout=30.0, extra=None, sink=None, verbose=False, auto_session_renew=True, session_retry_limit=3):
        self.url=url; self.verify=verify; self.timeout=timeout
        self.extra=dict(extra or {}); self.sid=""; self.proto=""; self._id=1
        self.sink=sink or Sink()
        self.verbose = verbose
        self._session = None  # Lazy-initialized requests.Session for connection pooling
        self.last_request = None
        self.last_http = None
        self.last_body = None
        self._id_lock = threading.Lock()
        self._thread_local = threading.local()
        self.auto_session_renew = bool(auto_session_renew)
        try:
            limit=int(session_retry_limit)
        except (TypeError, ValueError):
            limit=3
        self.auto_session_retry_limit=max(0, limit)
        self._renewing_session = False


    def _get_session(self):
        """Get or create requests.Session for connection pooling"""
        if self._session is None:
            self._session = requests.Session()
        return self._session

    def _setup_logging(self):
        lvl = logging.DEBUG if self.verbose else logging.WARNING
        logging.basicConfig(level=lvl)
        for name in ["urllib3","requests","requests.packages.urllib3"]:
            try: logging.getLogger(name).setLevel(lvl)
            except Exception: pass

    def _next(self):
        with self._id_lock:
            i=self._id; self._id+=1; return i

    def _h_post(self, include_sid=True, include_proto=True, is_init=False, accept_json_only=False):
        if accept_json_only:
            # prefer JSON responses but still allow servers that insist on text/event-stream
            accept = "application/json, text/event-stream;q=0.5"
        else:
            accept = "application/json, text/event-stream"
        h={"Accept": accept, "Content-Type":"application/json"}
        if include_sid and self.sid: h["Mcp-Session-Id"]=self.sid
        if include_proto and self.proto and not is_init: h["MCP-Protocol-Version"]=self.proto
        h.update(self.extra); return h

    def _h_get(self):
        h={"Accept":"text/event-stream"}
        if self.sid: h["Mcp-Session-Id"]=self.sid
        if self.proto: h["MCP-Protocol-Version"]=self.proto
        h.update(self.extra); return h

    def _log_h(self, h):
        lines=[]
        for k,v in h.items():
            redacted = "***" if k.lower()=="authorization" else v
            lines.append(f"{k}: {redacted}")
        self.sink.write(">> Headers: " + " | ".join(lines))

    @contextmanager
    def temp_timeout(self, seconds=None):
        old=self.timeout
        if seconds is not None: self.timeout = float(seconds)
        try: yield
        finally: self.timeout = old

    def _curl_from_http(self, http_obj, redact=True, windows=False):
        if not http_obj: return ""
        m=http_obj.get("method","POST")
        url=http_obj.get("url", self.url)
        headers=http_obj.get("headers",{})
        body=http_obj.get("body",None)
        lines=[]
        if windows:
            lines.append(f'curl -X {m} "{url}" ^')
            for k,v in headers.items():
                val = v if k.lower()!="authorization" or not redact else "***"
                lines.append(f'  -H "{k}: {val}" ^')
            if body is not None:
                payload=json.dumps(body, separators=(",",":"))
                lines.append(f'  --data-raw "{payload}"')
        else:
            lines.append(f"curl -X {shlex.quote(m)} {shlex.quote(url)} \\")
            for k,v in headers.items():
                val = v if k.lower()!="authorization" or not redact else "***"
                lines.append(f"  -H {shlex.quote(f'{k}: {val}')} \\")
            if body is not None:
                payload=json.dumps(body, separators=(",",":"))
                lines.append(f"  --data-raw {shlex.quote(payload)}")
            else:
                if lines[-1].endswith("\\"):
                    lines[-1]=lines[-1][:-2]
        return "\n".join(lines)

    def last_curl(self, redact=True, windows=False):
        return self._curl_from_http(self.last_http, redact=redact, windows=windows)

    def initialize(self, protocol_version=DEFAULT_PROTOCOL_VERSION):
        self._setup_logging()
        payload={"jsonrpc":"2.0","id":self._next(),"method":"initialize","params":{"protocolVersion":protocol_version,"capabilities":{},"clientInfo":{"name":"mcp-diagnoser-pro","version":"0.4.2"}}}
        h=self._h_post(include_sid=False, include_proto=False, is_init=True)
        self.last_request={"method":"initialize","headers":h,"payload":payload}
        self.last_http={"method":"POST","url":self.url,"headers":h.copy(),"body":payload}
        self.sink.write(f">> POST {self.url} [initialize]"); self._log_h(h)
        self.sink.write(">> Body: " + json.dumps(payload, ensure_ascii=False))
        r=self._get_session().post(self.url, data=json.dumps(payload), headers=h, stream=True, verify=self.verify, timeout=self.timeout)
        self.sink.write(f"<< HTTP {r.status_code}  Content-Type: {r.headers.get('Content-Type','')}")
        sid=r.headers.get("Mcp-Session-Id",""); 
        if sid: self.sid=sid; self.sink.write(f"<< Mcp-Session-Id: {sid}")
        ct=(r.headers.get("Content-Type") or "").lower()
        obj={}
        if "text/event-stream" in ct:
            client=SSEClient(r)
            for ev in client.events():
                try:
                    d=json.loads(ev.data); self.sink.write(f"<< [SSE {ev.event or 'message'}] " + json.dumps(d, ensure_ascii=False))
                    if isinstance(d,dict) and d.get("id")==payload["id"] and ("result" in d or "error" in d): obj=d; break
                except Exception:
                    self.sink.write("<< [SSE raw] " + ev.data)
        else:
            try: obj=r.json()
            except Exception: obj={"_raw": r.text}
            self.sink.write("<< Body: " + json.dumps(obj, ensure_ascii=False))
        self.last_body = obj
        if isinstance(obj,dict) and obj.get("result"):
            pv=obj["result"].get("protocolVersion") or ""
            if pv: self.proto=pv; self.sink.write(f"<< Negotiated MCP-Protocol-Version: {pv}")
        return obj, r

    def initialized(self):
        payload={"jsonrpc":"2.0","method":"notifications/initialized"}
        h=self._h_post()
        self.last_request={"method":"notifications/initialized","headers":h,"payload":payload}
        self.last_http={"method":"POST","url":self.url,"headers":h.copy(),"body":payload}
        self.sink.write(f">> POST {self.url} [notifications/initialized]"); self._log_h(h)
        self.sink.write(">> Body: " + json.dumps(payload, ensure_ascii=False))
        r=self._get_session().post(self.url, data=json.dumps(payload), headers=h, stream=False, verify=self.verify, timeout=self.timeout)
        self.sink.write(f"<< HTTP {r.status_code} (initialized)")
        return r

    def call(self, method, params=None, stream=True, accept_json_only=False, sse_max_seconds=None):
        max_attempts = 1 + (self.auto_session_retry_limit if self.auto_session_renew else 0)
        attempt = 0
        last_obj = None
        last_response = None
        while attempt < max_attempts:
            attempt += 1
            payload={"jsonrpc":"2.0","id":self._next(),"method":method}
            if params is not None:
                payload["params"]=params
            h=self._h_post(accept_json_only=accept_json_only)
            self.last_request={"method":method,"headers":h,"payload":payload}
            self.last_http={"method":"POST","url":self.url,"headers":h.copy(),"body":payload}
            snapshot = self.last_request.copy() if isinstance(self.last_request, dict) else self.last_request
            try:
                self._thread_local.last_request = snapshot
            except Exception:
                self._thread_local.last_request = snapshot
            self.sink.write(f">> POST {self.url} [{method}]"); self._log_h(h)
            self.sink.write(">> Body: " + json.dumps(payload, ensure_ascii=False))
            if self.sid:
                self.sink.write(f">> Using session: {self.sid}")
            r=self._get_session().post(self.url, data=json.dumps(payload), headers=h, stream=stream, verify=self.verify, timeout=self.timeout)
            try:
                request_info = copy.deepcopy(getattr(self._thread_local, 'last_request', self.last_request))
            except Exception:
                request_info = getattr(self._thread_local, 'last_request', self.last_request)
            try:
                r._mcp_request_info = copy.deepcopy(request_info)
            except Exception:
                r._mcp_request_info = request_info
            self.sink.write(f"<< HTTP {r.status_code}  Content-Type: {r.headers.get('Content-Type','')}")
            ct=(r.headers.get("Content-Type") or "").lower()

            obj = None
            if "text/event-stream" in ct and (accept_json_only or not stream):
                self.sink.write("<< WARN: Unexpected text/event-stream for non-stream call; parsing first event.")
                try:
                    client = SSEClient(r)
                    event_obj = None
                    for ev in client.events():
                        try:
                            data = json.loads(ev.data)
                            event_obj = data
                            break
                        except Exception:
                            self.sink.write(f"<< [SSE raw] {ev.data}")
                    if event_obj is None:
                        try:
                            raw = r.text
                        except Exception:
                            raw = "<streaming>"
                        obj={"_raw": raw, "_note":"unexpected event-stream for non-stream/json-only call"}
                    else:
                        obj=event_obj
                except Exception as exc:
                    self.sink.write(f"<< WARN: Failed to parse SSE fallback: {exc}")
                    try:
                        raw = r.text
                    except Exception:
                        raw = "<streaming>"
                    obj={"_raw": raw, "_note":"unexpected event-stream for non-stream/json-only call"}
                self.last_body=obj
                self.sink.write("<< Body: " + json.dumps(obj, ensure_ascii=False))
            elif "text/event-stream" in ct:
                client=SSEClient(r)
                deadline = time.monotonic() + (sse_max_seconds or 30)
                matched=None
                for ev in client.events():
                    try:
                        d=json.loads(ev.data)
                        self.last_body=d
                        self.sink.write(f"<< [SSE {ev.event or 'message'}] " + json.dumps(d, ensure_ascii=False))
                        if isinstance(d,dict) and d.get("id")==payload["id"] and ("result" in d or "error" in d):
                            matched=d
                            break
                    except Exception:
                        self.sink.write(f"<< [SSE raw] {ev.data}")
                    if time.monotonic() >= deadline:
                        self.sink.write("<< WARN: SSE read timed out; continuing.")
                        break
                if matched is None:
                    obj={}
                    self.last_body=obj
                else:
                    obj=matched
            else:
                try:
                    obj=r.json()
                except Exception:
                    obj={"_raw": r.text}
                self.last_body = obj
                self.sink.write("<< Body: " + json.dumps(obj, ensure_ascii=False))

            last_obj, last_response = obj, r
            retry_reason = self._detect_session_expired(obj, r, is_stream="text/event-stream" in ct)
            if self.auto_session_renew and retry_reason:
                if attempt < max_attempts and self._auto_renew_session(attempt, max_attempts, retry_reason):
                    continue
                if attempt >= max_attempts:
                    self.sink.write(f"<< WARN: Session auto-renew skipped; retry limit ({self.auto_session_retry_limit}) reached.")
                return obj, r
            return obj, r
        return last_obj, last_response

    def _detect_session_expired(self, obj, response, is_stream=False):
        status = None
        try:
            status = getattr(response, "status_code", None)
        except Exception:
            status = None
        headers = {}
        if response is not None:
            try:
                headers = dict(response.headers)
            except Exception:
                headers = {}
        text_fragments = []
        if isinstance(obj, dict):
            try:
                text_fragments.append(json.dumps(obj, ensure_ascii=False).lower())
            except Exception:
                text_fragments.append(str(obj).lower())
        elif isinstance(obj, str):
            text_fragments.append(obj.lower())
        elif obj is not None:
            text_fragments.append(str(obj).lower())
        if response is not None and not is_stream:
            try:
                text_fragments.append(response.text.lower())
            except Exception:
                pass
        combined = " ".join(fragment for fragment in text_fragments if fragment)
        header_candidates=("Mcp-Session-Status","X-Session-Status","X-Mcp-Session")
        for key in header_candidates:
            value = headers.get(key)
            if value and "expire" in value.lower():
                return f"{key}: {value}"
        if status in (440, 419):
            return f"HTTP {status} indicates session timeout"
        if status in (401, 403) and "session" in combined:
            return f"HTTP {status} with session error message"
        if status is not None and 400 <= status < 500 and "session" in combined:
            return f"HTTP {status} indicates session problem"
        keywords=(
            "session expired",
            "session has expired",
            "invalid session",
            "session invalid",
            "session reset",
            "session terminated",
            "session not found",
            "session missing",
            "session abgelaufen",
            "session ist abgelaufen",
            "session timed out",
            "session timeout",
            "session abgel.",
            "mcp session expired",
        )
        for kw in keywords:
            if kw in combined:
                return f"Server reported '{kw}'"
        return None

    def _auto_renew_session(self, attempt, max_attempts, reason):
        if self._renewing_session:
            self.sink.write("<< WARN: Session auto-renew already in progress; skipping additional request.")
            return False
        retry_max = max(1, max_attempts - 1)
        retry_no = min(attempt, retry_max)
        self._renewing_session = True
        try:
            self.sink.write(f"<< WARN: {reason}. Auto session renew attempt {retry_no}/{retry_max}.")
            try:
                if self._session is not None:
                    self._session.close()
            except Exception:
                pass
            self._session = None
            self.sid=""
            self.initialize()
            try:
                self.initialized()
            except Exception as exc:
                self.sink.write(f"<< WARN: notifications/initialized during auto-renew failed: {exc}")
            else:
                self.sink.write("<< INFO: Session auto-renew completed.")
            return True
        except Exception as exc:
            self.sink.write(f"<< WARN: Session auto-renew failed: {exc}")
            return False
        finally:
            self._renewing_session = False

    def list_tools(self): return self.call("tools/list", {"cursor": None}, sse_max_seconds=5)
    def list_resources(self): return self.call("resources/list", {"cursor": None}, sse_max_seconds=5)
    def list_prompts(self): return self.call("prompts/list", {"cursor": None}, sse_max_seconds=5)

    def get_sse(self, seconds=3):
        h=self._h_get()
        self.last_http={"method":"GET","url":self.url,"headers":h.copy(),"body":None}
        self.sink.write(f">> GET {self.url} [SSE] {seconds}s"); self._log_h(h)
        raw_connect_timeout = self.timeout if not isinstance(self.timeout, (list, tuple)) else self.timeout[0]
        try:
            connect_timeout = float(raw_connect_timeout)
        except (TypeError, ValueError):
            connect_timeout = 30.0
        try:
            target_seconds = float(seconds) if seconds is not None else None
        except (TypeError, ValueError):
            target_seconds = None
        if target_seconds is not None:
            read_timeout = max(0.5, target_seconds)
            timeout_arg = (connect_timeout, read_timeout)
            deadline = time.monotonic() + max(0.0, target_seconds)
        else:
            read_timeout = None
            timeout_arg = self.timeout
            deadline = None
        r=self._get_session().get(self.url, headers=h, stream=True, verify=self.verify, timeout=timeout_arg)
        self.sink.write(f"<< HTTP {r.status_code}  Content-Type: {r.headers.get('Content-Type','')}")
        ct=(r.headers.get("Content-Type") or "").lower()
        if "text/event-stream" not in ct:
            self.sink.write("<< Kein text/event-stream (405 oder JSON)."); return r
        client=SSEClient(r)
        events_iter=client.events()
        try:
            while True:
                if deadline is not None and time.monotonic() >= deadline:
                    self.sink.write("<< INFO: SSE time window elapsed; closing stream.")
                    break
                try:
                    ev=next(events_iter)
                except StopIteration:
                    break
                try:
                    d=json.loads(ev.data); self.last_body=d; self.sink.write(f"<< [SSE {ev.event or 'message'}] " + json.dumps(d, ensure_ascii=False))
                except Exception:
                    self.sink.write("<< [SSE raw] " + ev.data)
        except requests.exceptions.ReadTimeout:
            self.sink.write("<< WARN: SSE read timeout; closing stream.")
        except requests.exceptions.ChunkedEncodingError as exc:
            self.sink.write(f"<< WARN: SSE stream ended unexpectedly: {exc}")
        except requests.exceptions.RequestException as exc:
            self.sink.write(f"<< WARN: SSE stream error: {exc}")
        finally:
            if target_seconds is not None:
                try: client.close()
                except Exception: pass
        return r

    def delete_session(self):
        h=self._h_post()
        self.last_http={"method":"DELETE","url":self.url,"headers":h.copy(),"body":None}
        self.sink.write(f">> DELETE {self.url} [session]"); self._log_h(h)
        r=self._get_session().delete(self.url, headers=h, verify=self.verify, timeout=self.timeout)
        self.sink.write(f"<< HTTP {r.status_code} (DELETE)")
        return r

    def _gen_from_schema(self, schema):
        def gen(sch):
            if not isinstance(sch, dict): return None
            if "default" in sch: return sch["default"]
            if "enum" in sch and sch["enum"]: return sch["enum"][0]
            t = sch.get("type")
            if isinstance(t, list): t=t[0]
            if t=="string": return "x"
            if t=="integer": return 0
            if t=="number": return 0.0
            if t=="boolean": return False
            if t=="array":
                it = sch.get("items")
                v = gen(it) if isinstance(it, dict) else None
                mi = int(sch.get("minItems", 0))
                arr = [v] if mi>0 else ([] if v is None else [v])
                while len(arr)<mi: arr.append(v)
                return arr
            if t=="object" or "properties" in sch or "required" in sch:
                out={}
                props = sch.get("properties", {})
                for req in sch.get("required", []):
                    out[req] = gen(props.get(req, {}))
                return out
            if "oneOf" in sch: return gen(sch["oneOf"][0])
            if "anyOf" in sch: return gen(sch["anyOf"][0])
            if "allOf" in sch: 
                res={}
                for p in sch["allOf"]:
                    x=gen(p)
                    if isinstance(x, dict): res.update(x)
                return res
            return {}
        return gen(schema or {})

    def _validate(self, schema, instance):
        try:
            Draft7Validator(schema or {}).validate(instance)
            return True, None
        except Exception as e:
            return False, str(e)

    def _extract_structured_from_result(self, tool_result):
        if not isinstance(tool_result, dict): return None
        if "structuredContent" in tool_result and isinstance(tool_result["structuredContent"], (dict, list)):
            return tool_result["structuredContent"]
        content = tool_result.get("content") or []
        for item in content:
            if isinstance(item, dict) and item.get("type")=="text":
                txt=item.get("text","")
                if not isinstance(txt, str): continue
                txt=txt.strip()
                if not (txt.startswith("{") or txt.startswith("[")): continue
                try:
                    data=json.loads(txt)
                    if isinstance(data, (dict, list)):
                        return data
                except Exception:
                    continue
        return None

    def _estimate_tokens(self, rpc_obj):
        candidates=("total_tokens","totalTokens","token_count","tokenCount","output_tokens","outputTokens","tokens")

        def _metric_from_dict(data):
            if not isinstance(data, dict):
                return None
            usage=data.get("usage")
            if isinstance(usage, dict):
                for key in candidates:
                    val=usage.get(key)
                    if isinstance(val, (int, float)):
                        return int(val)
            for key in candidates:
                val=data.get(key)
                if isinstance(val, (int, float)):
                    return int(val)
            return None

        if isinstance(rpc_obj, dict):
            metric=_metric_from_dict(rpc_obj)
            if metric is not None:
                return metric
            result=rpc_obj.get("result")
            metric=_metric_from_dict(result)
            if metric is not None:
                return metric

        texts=[]
        seen=set()

        def collect(val):
            key=id(val)
            if key in seen:
                return
            seen.add(key)
            if isinstance(val, str):
                if val.strip():
                    texts.append(val)
                return
            if isinstance(val, dict):
                # Focus on likely textual fields
                for k in ("text","data","message","value","body","content","structuredContent","output","result"):
                    if k in val:
                        collect(val[k])
                for v in val.values():
                    if isinstance(v, (dict, list, tuple, set)):
                        collect(v)
            elif isinstance(val, (list, tuple, set)):
                for item in val:
                    collect(item)

        if isinstance(rpc_obj, dict):
            collect(rpc_obj.get("result"))
        collect(rpc_obj)

        total_chars=sum(len(t) for t in texts if isinstance(t, str))
        if total_chars>0:
            return max(1, int(math.ceil(total_chars/4.0)))
        try:
            dumped=json.dumps(rpc_obj, ensure_ascii=False)
            total_chars=len(dumped)
            if total_chars>0:
                return max(1, int(math.ceil(total_chars/4.0)))
        except Exception:
            pass
        return 0

    def _gather_text_blocks(self, tool_result):
        texts=[]
        def _add(val):
            if isinstance(val, str):
                s=val.strip()
                if s:
                    texts.append(s)
        if isinstance(tool_result, dict):
            for key in ("summary","message","text","detail"):
                _add(tool_result.get(key))
            content=tool_result.get("content")
            if isinstance(content, list):
                for item in content:
                    if isinstance(item, dict):
                        _add(item.get("text"))
        return texts

    def _walk_json_nodes(self, obj, collected=None):
        if collected is None:
            collected=[]
        if isinstance(obj, dict):
            collected.append(obj)
            for value in obj.values():
                self._walk_json_nodes(value, collected)
        elif isinstance(obj, list):
            for value in obj:
                self._walk_json_nodes(value, collected)
        return collected

    def _parse_text_blocks(self, texts):
        parsed=[]
        for txt in texts:
            stripped=txt.strip()
            if not stripped or stripped[0] not in "{[":
                continue
            try:
                parsed.append(json.loads(stripped))
            except Exception:
                continue
        return parsed

    def _analyze_result_messages(self, tool_name, tool_result):
        if not isinstance(tool_result, dict):
            return None, ""
        texts=self._gather_text_blocks(tool_result)
        parsed=self._parse_text_blocks(texts)
        structured=tool_result.get("structuredContent")
        if structured is not None:
            parsed.append(structured)
        nodes=[]
        for block in parsed:
            nodes.extend(self._walk_json_nodes(block, []))
        issues=[]

        def add_issue(code, message):
            if not isinstance(message, str):
                return
            cleaned=message.strip()
            if cleaned:
                issues.append((code, cleaned))

        for txt in texts:
            low=txt.lower()
            if "not implemented" in low:
                add_issue("NOT_IMPLEMENTED", txt)
            if "blocked" in low or "unable to rotate" in low:
                add_issue("LOGICAL_BLOCKED", txt)
            if "action_needed" in low or "action needed" in low or "wake it up" in low:
                add_issue("ACTION_REQUIRED", txt)
            if "power_error" in low or "device still authorizing" in low or "adb.exe" in low or "not found" in low:
                add_issue("DEVICE_ERROR", txt)
            if "screen state unclear" in low:
                add_issue("SCREEN_STATE_UNCLEAR", txt)

        for node in nodes:
            if not isinstance(node, dict):
                continue
            p_err=node.get("power_error")
            if isinstance(p_err, str) and p_err.strip():
                add_issue("DEVICE_ERROR", f"power_error: {p_err.strip()}")
            w_err=node.get("window_error")
            if isinstance(w_err, str) and w_err.strip():
                add_issue("DEVICE_ERROR", f"window_error: {w_err.strip()}")
            action=node.get("action_needed")
            if isinstance(action, str) and action.strip():
                add_issue("ACTION_REQUIRED", f"action_needed: {action.strip()}")
            summary=node.get("summary")
            if isinstance(summary, str) and "screen state unclear" in summary.lower():
                add_issue("SCREEN_STATE_UNCLEAR", summary)

        if not issues:
            return None, ""

        priority={"DEVICE_ERROR":5,"LOGICAL_BLOCKED":3,"ACTION_REQUIRED":3,"SCREEN_STATE_UNCLEAR":2,"NOT_IMPLEMENTED":1}
        status_map={
            "DEVICE_ERROR":"DEVICE_ERROR",
            "LOGICAL_BLOCKED":"WARN_BLOCKED",
            "ACTION_REQUIRED":"WARN_ACTION_REQUIRED",
            "SCREEN_STATE_UNCLEAR":"WARN_STATE_UNCLEAR",
            "NOT_IMPLEMENTED":"WARN_NOT_IMPLEMENTED"
        }
        issues.sort(key=lambda item: priority.get(item[0],0), reverse=True)
        top_code=issues[0][0]
        status=status_map.get(top_code)
        detail="; ".join(dict.fromkeys([msg for _, msg in issues]))
        return status, detail

    def audit_tools(self, limit=None, per_call_timeout=None, parallelism=1, stop_flag=None, on_progress=None, validate_outputs=True, throttle_seconds=0.0):
        tools_obj, _ = self.list_tools()
        tools = (tools_obj.get("result") or {}).get("tools") or []
        if limit: tools = tools[:max(0, int(limit))]

        results = []

        throttle_delay = 0.0
        if throttle_seconds:
            try:
                throttle_delay = max(0.0, float(throttle_seconds))
            except (TypeError, ValueError):
                throttle_delay = 0.0

        if on_progress:
            try:
                on_progress({"meta":"start","total":len(tools)})
            except Exception:
                pass

        def worker(t):
            if stop_flag and stop_flag(): 
                return None
            notified=False
            try:
                if on_progress:
                    on_progress({"meta":"inflight","delta":1})
                    notified=True
                name = t.get("name","")
                schema = t.get("inputSchema") or {}
                out_schema = t.get("outputSchema") or None
                args = self._gen_from_schema(schema)
                ok, err = self._validate(schema, args)
                status = "ARGS_VALID" if ok else "ARGS_INVALID"
                detail = "" if ok else err or "Validation failed"
                ms = 0
                kb = 0.0
                tokens = 0
                call_id = f"{name}-{int(time.time()*1000)}-{threading.get_ident()}"
                start_wall = time.time()
                if on_progress:
                    try:
                        on_progress({"meta":"timeline","phase":"start","tool":name,"call_id":call_id,"ts":start_wall})
                    except Exception:
                        pass
                if not ok:
                    res={"tool":name,"status":status,"detail":detail,"ms":ms,"kb":kb,"tokens":tokens,"args":args,"http":None,"call_id":call_id}
                    if on_progress: 
                        on_progress(res)
                        try:
                            on_progress({"meta":"timeline","phase":"end","tool":name,"call_id":call_id,"ts":time.time(),"status":status,"ms":ms})
                        except Exception:
                            pass
                    return res
                try:
                    start=time.monotonic()
                    obj, resp = self.call("tools/call", {"name": name, "arguments": args}, sse_max_seconds=20)
                    ms = int(round((time.monotonic()-start)*1000))
                    tokens = self._estimate_tokens(obj)
                    try:
                        request_info = getattr(resp, '_mcp_request_info', getattr(self._thread_local, 'last_request', self.last_request))
                        req_snapshot = copy.deepcopy(request_info)
                    except Exception:
                        req_snapshot = getattr(resp, '_mcp_request_info', getattr(self._thread_local, 'last_request', self.last_request))
                    try:
                        ct=(resp.headers.get("Content-Type") or "").lower()
                    except Exception:
                        ct=""
                    try:
                        if "application/json" in ct:
                            kb = (len(resp.content or b"")/1024.0)
                        else:
                            kb = (len(json.dumps(obj).encode("utf-8"))/1024.0)
                    except Exception:
                        kb = 0.0

                    if resp.ok:
                        out_status=None; out_detail=None
                        if isinstance(obj, dict) and "error" in obj:
                            status="PROTOCOL_ERROR"; detail=f"{obj['error'].get('code')} {obj['error'].get('message')}"
                        else:
                            rres = (obj.get("result") or {}) if isinstance(obj, dict) else {}
                            if isinstance(rres, dict) and rres.get("isError"):
                                status="TOOL_ERROR"; detail="isError=true"
                            else:
                                status="OK"; detail="call succeeded"
                                if validate_outputs and out_schema:
                                    structured = self._extract_structured_from_result(rres)
                                    if structured is None:
                                        out_status="NO_STRUCTURED"; out_detail="no structuredContent / parsable JSON text"
                                    else:
                                        v_ok, v_err = self._validate(out_schema, structured)
                                        if v_ok: out_status="OUTPUT_VALID"; out_detail=""
                                        else: out_status="OUTPUT_SCHEMA_INVALID"; out_detail=v_err or "schema validation failed"
                                # semantic analysis even when validation succeeded
                                if isinstance(rres, dict):
                                    sem_status, sem_detail = self._analyze_result_messages(name, rres)
                                    if sem_status:
                                        if status == "OK":
                                            status = sem_status
                                            if sem_detail:
                                                detail = sem_detail
                                            elif not detail:
                                                detail = sem_status
                                        else:
                                            if sem_detail:
                                                detail = (detail + ("; " if detail else "") + sem_detail).strip("; ")
                        if out_status:
                            detail = (detail + ("; " if detail else "") + f"{out_status}: {out_detail}").strip("; ")
                    else:
                        status="HTTP_ERROR"; detail=f"HTTP {resp.status_code}"
                    res={"tool":name,"status":status,"detail":detail,"ms":ms,"kb":kb,"tokens":tokens,"args":args,"http":resp.status_code,"request":req_snapshot,"response":obj,"http_headers":dict(getattr(resp, "headers", {})),"call_id":call_id}
                except requests.exceptions.Timeout as e:
                    ms = int(round((time.monotonic()-start)*1000))
                    try:
                        req_snapshot_timeout = copy.deepcopy(getattr(self._thread_local, 'last_request', self.last_request))
                    except Exception:
                        req_snapshot_timeout = getattr(self._thread_local, 'last_request', self.last_request)
                    res={"tool":name,"status":"TIMEOUT","detail":str(e),"ms":ms,"kb":0.0,"tokens":0,"args":args,"http":None,"request":req_snapshot_timeout,"response":None,"http_headers":{},"call_id":call_id}
                except Exception as e:
                    ms = int(round((time.monotonic()-start)*1000))
                    try:
                        req_snapshot_exc = copy.deepcopy(getattr(self._thread_local, 'last_request', self.last_request))
                    except Exception:
                        req_snapshot_exc = getattr(self._thread_local, 'last_request', self.last_request)
                    res={"tool":name,"status":"EXCEPTION","detail":str(e),"ms":ms,"kb":0.0,"tokens":0,"args":args,"http":None,"request":req_snapshot_exc,"response":None,"http_headers":{},"call_id":call_id}
                if on_progress: 
                    on_progress(res)
                    try:
                        on_progress({"meta":"timeline","phase":"end","tool":name,"call_id":call_id,"ts":time.time(),"status":res.get("status"),"ms":ms})
                    except Exception:
                        pass
                if throttle_delay>0.0:
                    time.sleep(throttle_delay)
                return res
            finally:
                if notified:
                    try:
                        on_progress({"meta":"inflight","delta":-1})
                    except Exception:
                        pass

        if parallelism<=1:
            for t in tools:
                if stop_flag and stop_flag(): break
                r = worker(t)
                if r: results.append(r)
        else:
            with concurrent.futures.ThreadPoolExecutor(max_workers=parallelism) as ex:
                futs = [ex.submit(worker, t) for t in tools]
                for f in concurrent.futures.as_completed(futs):
                    r = f.result()
                    if r: results.append(r)
        return results

    def overall(self, timeout_override=None, step_delay=None, stage_callback=None, stop_flag=None):
        summary=[]; details={}
        delay_seconds=0.0
        if step_delay:
            try:
                delay_seconds=max(0.0, float(step_delay))
            except (TypeError, ValueError):
                delay_seconds=0.0
        def add(level, name, status, detail, detail_key=None):
            entry={"level":level,"check":name,"status":status,"detail":detail}
            if detail_key:
                entry["detail_key"]=detail_key
            summary.append(entry)

        def notify_stage(label):
            if stage_callback:
                try:
                    stage_callback(label)
                except Exception:
                    pass

        def should_stop():
            if stop_flag and callable(stop_flag):
                try:
                    return stop_flag()
                except Exception:
                    return False
            return False

        def stage(label, first=False):
            if should_stop():
                add("INFO", "Test abgebrochen", "WARN", f"Abbruch bei Schritt: {label}")
                return True
            if not first and delay_seconds>0.0:
                time.sleep(delay_seconds)
            notify_stage(label)
            return False

        with (self.temp_timeout(timeout_override) if timeout_override is not None else self.temp_timeout(None)):
            if stage("POST initialize", first=True):
                return summary, details
            init_key="initialize"
            try:
                obj, r = self.initialize()
                details["initialize"]={
                    "http":r.status_code,
                    "headers":dict(r.headers),
                    "body":obj,
                    "request": copy.deepcopy(self.last_http) if self.last_http else None,
                }
                init_key="initialize"
                j_ok = isinstance(obj, dict) and obj.get("jsonrpc")=="2.0" and ("result" in obj or "error" in obj)
                add("MUST","JSON-RPC 2.0 response", "OK" if j_ok else "FAIL", "jsonrpc='2.0' & result|error required", detail_key=init_key)
                h=self.last_http.get("headers",{}) if self.last_http else {}
                acc=h.get("Accept",""); ct=h.get("Content-Type","")
                add("MUST","Accept header", "OK" if ("application/json" in acc and "text/event-stream" in acc) else "FAIL", acc or "missing", detail_key=init_key)
                add("MUST","Content-Type header", "OK" if ct.lower()=="application/json" else "FAIL", ct or "missing", detail_key=init_key)
                pv=(obj.get("result") or {}).get("protocolVersion") if isinstance(obj,dict) else None

                # MUST: protocolVersion must be present
                if not isinstance(pv,str) or not pv:
                    add("MUST","Protocol-Version negotiated", "FAIL", "missing or not a string", detail_key=init_key)
                else:
                    # Validate version format (YYYY-MM-DD)
                    import re
                    version_pattern = re.compile(r'^\d{4}-\d{2}-\d{2}$')
                    if not version_pattern.match(pv):
                        add("MUST","Protocol-Version format valid", "FAIL", f"Invalid format: {pv} (expected YYYY-MM-DD)", detail_key=init_key)
                    elif pv not in KNOWN_MCP_VERSIONS:
                        add("MUST","Protocol-Version recognized", "FAIL", f"Unknown version: {pv} (known: {', '.join(KNOWN_MCP_VERSIONS)})", detail_key=init_key)
                    else:
                        add("MUST","Protocol-Version negotiated", "OK", pv, detail_key=init_key)
                        # Additional checks for legacy/outdated but valid versions
                        requested_ver = DEFAULT_PROTOCOL_VERSION
                        if pv in LEGACY_MCP_VERSIONS:
                            add("INFO", "Legacy protocol version detected", "WARN", f"Server uses {pv} (legacy SSE-based). Latest: {requested_ver}", detail_key=init_key)
                        elif pv < requested_ver:
                            add("INFO", "Outdated protocol version", "WARN", f"Server: {pv}, Latest: {requested_ver}", detail_key=init_key)
                caps=(obj.get("result") or {}).get("capabilities") if isinstance(obj,dict) else None
                add("MUST","Capabilities object in InitializeResult", "OK" if isinstance(caps, dict) else "FAIL", "present" if isinstance(caps,dict) else "missing", detail_key=init_key)
                s_info=(obj.get("result") or {}).get("serverInfo") if isinstance(obj,dict) else None
                add("SHOULD","serverInfo provided", "OK" if isinstance(s_info, dict) else "WARN", "present" if isinstance(s_info,dict) else "absent", detail_key=init_key)
            except Exception as e:
                add("MUST","initialize", "FAIL", str(e), detail_key=init_key)
                return summary, details

            if stage("notifications/initialized"):
                return summary, details
            initd_key="notifications/initialized"
            try:
                rr=self.initialized()
                details[initd_key]={
                    "http":rr.status_code,
                    "headers":dict(rr.headers),
                    "body":None,
                    "request": copy.deepcopy(self.last_http) if self.last_http else None,
                }
                add("MUST","notifications/initialized -> 202", "OK" if rr.status_code==202 else "FAIL", f"HTTP {rr.status_code}", detail_key=initd_key)
            except Exception as e:
                add("MUST","notifications/initialized", "FAIL", str(e), detail_key=initd_key)

            tools=[]
            if stage("tools/list"):
                return summary, details
            tools_key="tools/list"
            try:
                o,r=self.list_tools()
                details[tools_key]={
                    "http":r.status_code,
                    "headers":dict(r.headers),
                    "body":o,
                    "request": copy.deepcopy(self.last_http) if self.last_http else None,
                }
                tools=((o.get("result") or {}).get("tools") or []) if isinstance(o,dict) else []
                has_tools_cap = isinstance(caps,dict) and isinstance(caps.get("tools"), dict)
                if has_tools_cap or (isinstance(tools, list) and len(tools)>0):
                    add("MUST","tools/list returns list", "OK" if isinstance(tools,list) else "FAIL", f"count={len(tools) if isinstance(tools,list) else 'n/a'}", detail_key=tools_key)
                else:
                    add("OPTIONAL","tools/list (no tools advertised)", "OK" if r.ok else "WARN", f"HTTP {r.status_code}", detail_key=tools_key)
            except Exception as e:
                add("MUST","tools/list", "FAIL", str(e), detail_key=tools_key)

            if isinstance(tools, list) and tools:
                t=tools[0]; name=t.get("name")
                if stage("tools/call (sample)"):
                    return summary, details
                tool_call_key="tools/call"
                try:
                    obj, resp = self.call("tools/call", {"name": name, "arguments": {}}, stream=True, sse_max_seconds=15)
                    details[tool_call_key]={
                        "http": getattr(resp, "status_code", None),
                        "headers": dict(getattr(resp, "headers", {})),
                        "body": obj,
                        "request": copy.deepcopy(self.last_http) if self.last_http else None,
                    }
                    ok = resp.ok and isinstance(obj, dict) and ("result" in obj or "error" in obj)
                    add("MUST","tools/call JSON-RPC", "OK" if ok else "FAIL", f"HTTP {getattr(resp,'status_code', 'n/a')}", detail_key=tool_call_key)
                except Exception as e:
                    add("MUST","tools/call", "FAIL", str(e), detail_key=tool_call_key)
            else:
                add("OPTIONAL","tools/call (no tools)", "OK", "skipped")

            # Robust error-object probe: try unknown method JSON-only; fallback to invalid params
            if stage("JSON-RPC error probe"):
                return summary, details
            error_key="jsonrpc-error-probe"
            try:
                bad, br = self.call("rpc/does_not_exist", {}, stream=False, accept_json_only=True)
                details[error_key]={
                    "http": getattr(br, "status_code", None),
                    "headers": dict(getattr(br, "headers", {})),
                    "body": bad,
                    "request": copy.deepcopy(self.last_http) if self.last_http else None,
                }
                primary_status = getattr(br, "status_code", "n/a")
                err_payload_ok = isinstance(bad, dict) and isinstance(bad.get("error"), dict) and ("code" in bad["error"] and "message" in bad["error"])
                err_ok = bool(getattr(br, "ok", False)) and err_payload_ok
                detail_parts = [f"primary HTTP {primary_status}"]
                if isinstance(bad, (dict, list)):
                    try:
                        detail_parts.append(json.dumps(bad, ensure_ascii=False)[:200])
                    except Exception:
                        detail_parts.append(str(bad)[:200])
                elif bad is not None:
                    detail_parts.append(str(bad)[:200])
                fallback_note = ""
                if not err_ok:
                    # fallback: provoke invalid params on tools/call
                    bad2, br2 = self.call("tools/call", {"arguments": {"_":1}}, stream=False, accept_json_only=True)
                    fb_status = getattr(br2, "status_code", "n/a")
                    fb_payload_ok = isinstance(bad2, dict) and isinstance(bad2.get("error"), dict) and ("code" in bad2["error"] and "message" in bad2["error"])
                    details[error_key]["fallback"]={
                        "http": getattr(br2, "status_code", None),
                        "headers": dict(getattr(br2, "headers", {})),
                        "body": bad2,
                        "request": copy.deepcopy(self.last_http) if self.last_http else None,
                    }
                    if isinstance(bad2, (dict, list)):
                        try:
                            fb_preview = json.dumps(bad2, ensure_ascii=False)[:200]
                        except Exception:
                            fb_preview = str(bad2)[:200]
                    else:
                        fb_preview = str(bad2)[:200]
                    fallback_note = f"fallback HTTP {fb_status} ({'valid error' if fb_payload_ok else 'invalid error'}) {fb_preview}"
                    detail_parts.append(fallback_note)
                detail = "; ".join([p for p in detail_parts if p])
                add("MUST","JSON-RPC error format", "OK" if err_ok else "FAIL", detail, detail_key=error_key)
            except Exception as e:
                add("MUST","JSON-RPC error format", "WARN", f"probe failed: {e}", detail_key=error_key)

            if stage("GET SSE (1s)"):
                return summary, details
            sse_key="GET-SSE"
            try:
                r=self.get_sse(1)
                details[sse_key]={
                    "http":r.status_code,
                    "headers":dict(r.headers),
                    "body": self.last_body,
                    "request": copy.deepcopy(self.last_http) if self.last_http else None,
                }
                ct=(r.headers.get("Content-Type") or "").lower()
                if "text/event-stream" in ct or r.status_code==405:
                    add("MUST","HTTP SSE endpoint behavior", "OK", "event-stream or 405", detail_key=sse_key)
                else:
                    add("MUST","HTTP SSE endpoint behavior", "FAIL", f"{r.status_code} {ct}", detail_key=sse_key)
            except Exception as e:
                add("MUST","HTTP SSE endpoint", "FAIL", str(e), detail_key=sse_key)

            try:
                sid_present = bool(details.get(init_key,{}).get("headers",{}).get("Mcp-Session-Id") or self.sid)
                add("SHOULD","Mcp-Session-Id issued", "OK" if sid_present else "WARN", "present" if sid_present else "not issued", detail_key=init_key)
            except Exception as e:
                add("SHOULD","Mcp-Session-Id", "WARN", str(e), detail_key=init_key)

            if stage("prompts/list"):
                return summary, details
            prompts_key="prompts/list"
            try:
                op, rp = self.list_prompts()
                details[prompts_key]={
                    "http": getattr(rp, "status_code", None),
                    "headers": dict(getattr(rp, "headers", {})),
                    "body": op,
                    "request": copy.deepcopy(self.last_http) if self.last_http else None,
                }
                ok = rp.ok and isinstance(op, dict) and "result" in op
                add("OPTIONAL","prompts/list", "OK" if ok else "WARN", f"HTTP {getattr(rp,'status_code','n/a')}", detail_key=prompts_key)
            except Exception as e:
                add("OPTIONAL","prompts/list", "WARN", str(e), detail_key=prompts_key)
            if stage("resources/list"):
                return summary, details
            resources_key="resources/list"
            try:
                orc, rr2 = self.list_resources()
                details[resources_key]={
                    "http": getattr(rr2, "status_code", None),
                    "headers": dict(getattr(rr2, "headers", {})),
                    "body": orc,
                    "request": copy.deepcopy(self.last_http) if self.last_http else None,
                }
                ok = rr2.ok and isinstance(orc, dict) and "result" in orc
                add("OPTIONAL","resources/list", "OK" if ok else "WARN", f"HTTP {getattr(rr2,'status_code','n/a')}", detail_key=resources_key)
            except Exception as e:
                add("OPTIONAL","resources/list", "WARN", str(e), detail_key=resources_key)

            if stage("DELETE session"):
                return summary, details
            try:
                r=self.delete_session()
                details["DELETE"]={
                    "http":r.status_code,
                    "headers":dict(r.headers),
                    "body":None,
                    "request": copy.deepcopy(self.last_http) if self.last_http else None,
                }
                add("OPTIONAL","DELETE session", "OK" if 200 <= r.status_code < 400 else "WARN", f"HTTP {r.status_code}", detail_key="DELETE")
            except Exception as e:
                add("OPTIONAL","DELETE session", "WARN", str(e), detail_key="DELETE")

            try:
                resets=getattr(self.sink, "session_resets", 0)
                if resets and resets > 1:
                    add("INFO","Session resets", "WARN", f"{resets} resets observed during run")
            except Exception:
                pass

            # ========== SERVER MODERNIZATION ASSESSMENT ==========
            # Analyze multiple indicators to determine if server is outdated
            modernization_issues = []
            modernization_score = 100  # Start at 100%, deduct points for issues

            # 1. Protocol Version Check (-40 for unknown, -30 for legacy, -20 for outdated)
            pv = (details.get("initialize", {}).get("body", {}).get("result", {}).get("protocolVersion") or "")
            if pv and pv not in KNOWN_MCP_VERSIONS:
                modernization_issues.append(f"Unknown protocol version {pv} (not in known versions)")
                modernization_score -= 40
            elif pv in LEGACY_MCP_VERSIONS:
                modernization_issues.append(f"Legacy protocol {pv} (SSE-based)")
                modernization_score -= 30
            elif pv and pv < DEFAULT_PROTOCOL_VERSION:
                modernization_issues.append(f"Outdated protocol {pv}")
                modernization_score -= 20

            # 2. Transport Type Detection (-20 points for SSE-only)
            init_headers = details.get("initialize", {}).get("headers", {})
            response_ct = init_headers.get("Content-Type", "").lower()
            if "text/event-stream" in response_ct and pv in LEGACY_MCP_VERSIONS:
                modernization_issues.append("SSE-only transport (no chunked streaming support)")
                modernization_score -= 20

            # 3. Missing serverInfo (-15 points)
            s_info = (details.get("initialize", {}).get("body", {}).get("result", {}).get("serverInfo") or {})
            if not s_info or not isinstance(s_info, dict):
                modernization_issues.append("Missing serverInfo (SHOULD provide server details)")
                modernization_score -= 15

            # 4. Check for modern capabilities (-10 points each)
            caps = (details.get("initialize", {}).get("body", {}).get("result", {}).get("capabilities") or {})
            def _caps_contains(fragment, obj):
                fragment = fragment.lower()
                if isinstance(obj, dict):
                    for key, value in obj.items():
                        if fragment in str(key).lower():
                            return True
                        if _caps_contains(fragment, value):
                            return True
                elif isinstance(obj, (list, tuple, set)):
                    for item in obj:
                        if _caps_contains(fragment, item):
                            return True
                elif isinstance(obj, str):
                    if fragment in obj.lower():
                        return True
                return False
            if isinstance(caps, dict):
                auth_present = bool(caps.get("auth") or caps.get("authorization"))
                if not auth_present and caps.get("experimental"):
                    auth_present = _caps_contains("auth", caps.get("experimental"))
                if not auth_present:
                    modernization_issues.append("No auth/authorization capability advertised")
                    modernization_score -= 10
                structured_present = bool(caps.get("structuredOutputs"))
                if not structured_present:
                    structured_present = _caps_contains("structured", caps)
                if not structured_present:
                    modernization_issues.append("No structured outputs support")
                    modernization_score -= 10

            # 5. Session Management (-5 points)
            if not self.sid:
                modernization_issues.append("No session ID issued")
                modernization_score -= 5

            # Generate assessment summary
            if modernization_score < 70:
                status = "OUTDATED"
                level_color = "FAIL"
            elif modernization_score < 90:
                status = "LEGACY"
                level_color = "WARN"
            else:
                status = "MODERN"
                level_color = "OK"

            if modernization_issues:
                issues_text = "; ".join(modernization_issues)
                add("ASSESSMENT", f"Server Modernization Score: {modernization_score}/100", level_color,
                    f"{status} - Issues: {issues_text}")
            else:
                add("ASSESSMENT", f"Server Modernization Score: {modernization_score}/100", "OK",
                    "MODERN - Server uses latest MCP specifications")

        return summary, details

# ---------------- GUI ----------------
class ProGUI:
    def __init__(self, root):
        self.root=root; self.root.title("MCP Diagnoser v4.3")
        try:
            self.root.protocol("WM_DELETE_WINDOW", self._on_window_close)
        except Exception:
            pass
        self.mem_log=[]
        self.q=queue.Queue(); self.client=None; self.last_report=None
        self._audit_stop=False
        self._audit_total=0
        self._audit_done=0
        self._audit_running=0



        try:
            self._state = self._load_state()
        except Exception:
            self._state = {}  # Fallback to empty state on load error
        state_defaults={
            "url":"https://localhost:5000/mcp",
            "tls_mode":"Insecure (not recommended)",
            "timeout":"30",
            "overall_timeout":"30",
            "overall_delay":"200",
            "audit_delay":"200",
            "ca":"",
            "auth_mode":"None",
            "auth_token":"",
            "auth_header":"Authorization",
            "auth_enabled":False,
            "auto_session_renew":True,
            "language":"English",
        }
        merged={k:self._state.get(k, v) for k,v in state_defaults.items()}
        self.url=tk.StringVar(value=merged["url"])
        self.tls_mode=tk.StringVar(value=merged["tls_mode"])
        self.timeout=tk.StringVar(value=merged["timeout"])
        self.overall_timeout=tk.StringVar(value=merged["overall_timeout"])
        self.overall_delay=tk.StringVar(value=merged["overall_delay"])
        self.audit_delay=tk.StringVar(value=merged["audit_delay"])
        self.summary_status=tk.StringVar(value="Ready")
        self.ca=tk.StringVar(value=merged["ca"])
        self.auth_mode=tk.StringVar(value=merged["auth_mode"])
        self.auth_token=tk.StringVar(value=merged["auth_token"])
        self.auth_header=tk.StringVar(value=merged["auth_header"])
        self.auto_session=tk.BooleanVar(value=bool(merged.get("auto_session_renew", True)))
        self.language=tk.StringVar(value=merged.get("language", "English"))
        if "language" not in self._state:
            self._state["language"] = self.language.get()
        default_enabled = bool(merged["auth_mode"] != "None" and merged["auth_token"])
        enabled_val = self._state.get("auth_enabled", default_enabled)
        self.auth_enabled=tk.BooleanVar(value=bool(enabled_val if enabled_val is not None else default_enabled))
        if self.auth_mode.get()=="None" or not self.auth_token.get().strip():
            self.auth_enabled.set(False)
        self.auth_status=tk.StringVar(value="")
        self.auth_toggle_text=tk.StringVar(value="")
        self._wizard_active=False
        self._token_manager=None
        self._sse_monitor=None
        self._test_lab=None
        self._context_layers=None
        self._input_methods_dialog=None
        self._resources_dialog=None
        self._resource_cache={}
        self._audit_timelines={}
        self._audit_call_items={}
        self._overall_progress_dialog=None
        self._overall_current_stage=""
        self._overall_wait_job=None
        self._overall_wait_tick=0
        self.summary_detail_map={}
        self.summary_data_map={}
        self.log_filter=tk.StringVar(value="")
        self.log_warn_only=tk.BooleanVar(value=False)
        self.log_show_ids=tk.BooleanVar(value=False)
        self._build_menubar()
        self._build()
        if self.language.get() != "English":
            self._refresh_language()
        self._apply_auth(silent=True)
        self._center_window(self.root, min_w=900, min_h=640)
        self._pump()
        if self.root is not None and not self._state.get("wizard_done"):
            self.root.after(200, self._show_wizard)

    def _sink(self, m):
        self.mem_log.append(m)
        # Prevent memory leak: trim log if it grows too large
        if len(self.mem_log) > 10000:
            self.mem_log = self.mem_log[-5000:]
        if len(self.mem_log) > 10000:
            self.mem_log = self.mem_log[-5000:]
        self.q.put(m)

    def _pump(self):
        try:
            dirty=False
            processed=0
            max_batch=LOG_PUMP_MAX_PER_TICK
            while processed < max_batch:
                m=self.q.get_nowait()
                dirty=True
                processed+=1
                idx=len(self.mem_log)
                self._maybe_append_event(m)
                if not self._log_filter_active():
                    self._insert_console_line(idx, m)
        except queue.Empty:
            pass
        if self._log_filter_active() and dirty:
            self._refresh_console()
        has_more = not self.q.empty()
        delay = LOG_PUMP_FAST_DELAY_MS if has_more else LOG_PUMP_NORMAL_DELAY_MS
        self.root.after(delay, self._pump)

    def _log_filter_active(self):
        return bool(self.log_filter.get().strip()) or bool(self.log_warn_only.get()) or bool(self.log_show_ids.get())

    def _filtered_log_lines(self):
        keyword=self.log_filter.get().strip().lower()
        warn_only=self.log_warn_only.get()
        filtered=[]
        for idx,line in enumerate(self.mem_log, start=1):
            check=line.lower()
            if warn_only and not any(tag in line for tag in ("WARN","FAIL","ERROR","ERR","\u26a0")):
                continue
            if keyword and keyword not in check:
                continue
            filtered.append((idx, line))
        return filtered

    def _refresh_console(self):
        lines=self._filtered_log_lines()
        self.console.configure(state="normal")
        self.console.delete("1.0","end")
        for idx,line in lines:
            self.console.insert("end", self._format_log_line(idx, line)+"\n")
        if lines:
            self.console.see("end")
        self.console.configure(state="disabled")

    def _apply_log_filter(self):
        self._refresh_console()

    def _reset_log_filter(self):
        self.log_filter.set("")
        self.log_warn_only.set(False)
        self.log_show_ids.set(False)
        self._refresh_console()

    def _clip_log_line(self, line):
        limit=getattr(self, '_log_line_display_limit', LOG_DISPLAY_CLIP)
        if limit and len(line)>limit:
            omitted=len(line)-limit
            return f"{line[:limit]}... (gekürzt, {omitted} weitere Zeichen ausgeblendet)"
        return line

    def _format_log_line(self, idx, line):
        display_line=self._clip_log_line(line)
        if self.log_show_ids.get():
            return f"[{idx:04d}] {display_line}"
        return display_line

    def _insert_console_line(self, idx, line):
        self.console.configure(state="normal")
        self.console.insert("end", self._format_log_line(idx, line)+"\n")
        self.console.see("end")
        self.console.configure(state="disabled")

    def _append_event_line(self, line):
        widget = getattr(self, "events_log", None)
        if widget is None:
            return
        widget.configure(state="normal")
        display_line = self._clip_log_line(line)
        widget.insert("end", display_line+"\n")
        widget.see("end")
        try:
            rows = int(float(widget.index("end-1c").split(".")[0]))
            if rows > 500:
                widget.delete("1.0", "2.0")
        except Exception:
            pass
        widget.configure(state="disabled")


    def _maybe_append_event(self, line):
        markers=("[SSE", "notifications/", "progress", "timeline", "\u26a0")
        if any(marker in line for marker in markers):
            self._append_event_line(line)

    def _(self, text):
        lang = None
        try:
            lang = self.language.get() if hasattr(self, "language") else None
        except Exception:
            lang = None
        if not lang and hasattr(self, "_state"):
            lang = self._state.get("language")
        lang = lang or "English"
        return TRANSLATIONS.get(lang, {}).get(text, text)

    def _build_menubar(self):
        if tk is None:
            return
        menubar = tk.Menu(self.root)
        settings_menu = tk.Menu(menubar, tearoff=0)
        language_menu = tk.Menu(settings_menu, tearoff=0)
        for value in ("English", "Deutsch"):
            language_menu.add_radiobutton(label=self._(value), variable=self.language, value=value, command=self._on_language_change)
        settings_menu.add_cascade(label=self._("Language"), menu=language_menu)
        menubar.add_cascade(label=self._("Settings"), menu=settings_menu)
        try:
            self.root.config(menu=menubar)
            self._menubar = menubar
        except Exception:
            pass

    def _on_language_change(self):
        selected = self.language.get() or "English"
        if self._state.get("language") != selected:
            self._state["language"] = selected
            self._save_state()
            self._build_menubar()

    def _refresh_language(self):
        self._build_menubar()

    def _build(self):
        p={"padx":6,"pady":4}
        top=ttk.Frame(self.root); top.pack(fill="x", **p)
        for col in range(9):
            top.grid_columnconfigure(col, weight=0)
        for col in (1,2,3):
            top.grid_columnconfigure(col, weight=1)
        ttk.Label(top, text="MCP URL:").grid(row=0, column=0, sticky="w")
        ttk.Entry(top, textvariable=self.url, width=50).grid(row=0, column=1, columnspan=2, sticky="we")

        ttk.Label(top, text="TLS Mode:").grid(row=0, column=3, sticky="e")
        tls=ttk.Combobox(top, textvariable=self.tls_mode, state="readonly",
                         values=["System Trust","Insecure (not recommended)","Embedded CA (./certs/ca.cert.pem)","Pick file..."], width=28)
        tls.grid(row=0, column=4, sticky="we")

        ttk.Label(top, text="Timeout (s):").grid(row=0, column=5, sticky="e")
        ttk.Entry(top, textvariable=self.timeout, width=6).grid(row=0, column=6, sticky="w")

        ttk.Label(top, text="Overall timeout (s):").grid(row=0, column=7, sticky="e")
        ttk.Entry(top, textvariable=self.overall_timeout, width=6).grid(row=0, column=8, sticky="w")

        ttk.Label(top, text="CA-Bundle:").grid(row=1, column=0, sticky="w")
        ttk.Entry(top, textvariable=self.ca, width=50).grid(row=1, column=1, columnspan=2, sticky="we")
        ttk.Button(top, text="...", width=3, command=self._pick_ca).grid(row=1, column=3, sticky="w")
        ttk.Button(top, text="Generate CA+Server", command=self._gen_ca).grid(row=1, column=4, sticky="w")
        ttk.Button(top, text="Clear console", command=self._clear).grid(row=1, column=5, sticky="w")
        ttk.Button(top, text="Save settings", command=self._save_settings).grid(row=1, column=6, sticky="w")

        ttk.Label(top, text="Auth:").grid(row=2, column=0, sticky="e")
        ttk.Label(top, textvariable=self.auth_status, width=38).grid(row=2, column=1, columnspan=3, sticky="we")
        ttk.Button(top, textvariable=self.auth_toggle_text, command=self._toggle_auth, width=14).grid(row=2, column=4, sticky="w", padx=(0,4))
        ttk.Button(top, text="Authentifizierungsmanager...", command=self._open_token_manager).grid(row=2, column=5, sticky="w")
        ttk.Label(top, text="Konfiguration und Token im Authentifizierungsmanager pflegen.", foreground="#555").grid(row=3, column=1, columnspan=5, sticky="w", pady=(2,0))
        ttk.Checkbutton(top, text="Session automatisch erneuern", variable=self.auto_session, command=self._save_settings).grid(row=4, column=1, columnspan=3, sticky="w", pady=(4,0))

        prof=ttk.Frame(self.root); prof.pack(fill="x", **p)
        ttk.Label(prof, text="Profiles:").pack(side="left")
        ttk.Button(prof, text="Save (per URL)", command=self._save_profile).pack(side="left")
        ttk.Button(prof, text="Load", command=self._load_profile).pack(side="left")
        ttk.Button(prof, text="Delete", command=self._delete_profile).pack(side="left")
        ttk.Button(prof, text="MCP Info", command=self._show_mcp_info).pack(side="left", padx=(6,0))
        ttk.Button(prof, text="Live-Verbindung", command=self._open_sse_monitor).pack(side="left", padx=(6,0))
        ttk.Button(prof, text="Kontext-Navigator...", command=self._open_context_layers).pack(side="left", padx=(6,0))
        ttk.Button(prof, text="Input-Methoden...", command=self._show_input_methods).pack(side="left", padx=(6,0))
        ttk.Button(prof, text="Ressourcen-Browser...", command=self._open_resource_browser).pack(side="left", padx=(6,0))
        ttk.Button(prof, text="Testlabor...", command=self._open_test_lab).pack(side="left", padx=(6,0))
        ttk.Label(prof, text="\u26a0 Token wird lokal im Klartext gespeichert. Nur auf vertrauensw\u00fcrdigen Ger\u00e4ten.").pack(side="left")

        body=ttk.PanedWindow(self.root, orient="horizontal"); body.pack(fill="both", expand=True, **p)
        left=ttk.Frame(body); right=ttk.Frame(body)
        body.add(left, weight=1); body.add(right, weight=2)

        ttk.Label(left, text="Checks & Samples").pack(anchor="w")
        self.tree=ttk.Treeview(left, show="tree")
        self.tree.pack(fill="both", expand=True)
        self.tree.bind("<<TreeviewSelect>>", self._update_tree_action_state)
        h = self.tree.insert("", "end", text="Handshake", open=True)
        self.tree.insert(h, "end", iid="init", text="POST initialize")
        self.tree.insert(h, "end", iid="initialized", text="notifications/initialized")
        l = self.tree.insert("", "end", text="Lists", open=True)
        self.tree.insert(l, "end", iid="tools_list", text="tools/list")
        self.tree.insert(l, "end", iid="resources_list", text="resources/list")
        self.tree.insert(l, "end", iid="prompts_list", text="prompts/list")
        s = self.tree.insert("", "end", text="Samples", open=True)
        self.tree.insert(s, "end", iid="prompts_get_first", text="prompts/get (1st)")
        self.tree.insert(s, "end", iid="resources_read_first", text="resources/read (1st)")
        self.tree.insert(s, "end", iid="tools_call_first", text="tools/call (1st, empty args)")
        a = self.tree.insert("", "end", text="Audit", open=True)
        self.tree.insert(a, "end", iid="audit_tools", text="Audit all tools (schema->args->validate->call)")
        m = self.tree.insert("", "end", text="Misc", open=True)
        self.tree.insert(m, "end", iid="get_sse", text="GET SSE (3s)")
        self.tree.insert(m, "end", iid="delete_session", text="DELETE session")

        btns=ttk.Frame(left); btns.pack(fill="x")
        self.run_selected_btn = ttk.Button(btns, text="Run selected", command=self._run_selected)
        self.run_selected_btn.pack(side="left")
        ttk.Button(btns, text="Run all", command=self._run_all).pack(side="left", padx=(6,0))
        ttk.Button(btns, text="Reset session", command=self._reset_session).pack(side="right")
        self._update_tree_action_state()

        ttk.Label(left, text="Overall Test Summary").pack(anchor="w")
        self.summary=ttk.Treeview(left, columns=("check","level","status","detail"), show="headings", height=10)
        self.summary.heading("check", text="Check")
        self.summary.heading("level", text="Level")
        self.summary.heading("status", text="Status")
        self.summary.heading("detail", text="Detail")
        self.summary.column("check", width=260, anchor="w")
        self.summary.column("level", width=80, anchor="center")
        self.summary.column("status", width=120, anchor="center")
        self.summary.column("detail", width=380, anchor="w")
        self.summary.tag_configure("ok", foreground="#0A7D00")
        self.summary.tag_configure("warn", foreground="#C27C00")
        self.summary.tag_configure("err", foreground="#B00020")
        self.summary.pack(fill="both", expand=False)
        self.summary.bind("<Double-1>", self._on_summary_double_click)
        self.summary.bind("<Button-3>", self._on_summary_right_click)
        self._summary_menu = tk.Menu(self.summary, tearoff=0)
        self._summary_menu.add_command(label="Request/Response anzeigen", command=self._open_selected_summary_detail)
        sumcfg=ttk.Frame(left); sumcfg.pack(fill="x")
        ttk.Label(sumcfg, text="Overall delay (ms):").pack(side="left")
        overall_spin_cls = getattr(ttk, "Spinbox", None)
        if overall_spin_cls is None and tk is not None:
            overall_spin_cls = tk.Spinbox
        if overall_spin_cls is not None:
            self._overall_delay_spin = overall_spin_cls(sumcfg, from_=0, to=5000, increment=50, width=7, textvariable=self.overall_delay)
            self._overall_delay_spin.pack(side="left", padx=(2,8))
        ttk.Label(sumcfg, textvariable=self.summary_status, foreground="#444").pack(side="left", padx=(6,0), expand=True, fill="x")
        sumbtns=ttk.Frame(left); sumbtns.pack(fill="x")
        ttk.Button(sumbtns, text="Run overall test", command=self._run_overall).pack(side="left")
        ttk.Button(sumbtns, text="Run auth tests", command=self._run_auth_tests).pack(side="left")
        ttk.Button(sumbtns, text="Save report (ZIP)", command=self._save_report).pack(side="left")
        ttk.Button(sumbtns, text="Clear summary", command=self._clear_summary).pack(side="left")

        ttk.Label(left, text="Audit results (per tool)").pack(anchor="w")
        self.audit=ttk.Treeview(left, columns=("tool","status","ms","tokens","kb","detail"), show="headings", height=12)
        self.audit.heading("tool", text="Tool")
        self.audit.heading("status", text="Status")
        self.audit.heading("ms", text="ms")
        self.audit.heading("tokens", text="Tokens")
        self.audit.heading("kb", text="KB")
        self.audit.heading("detail", text="Detail")
        self.audit.column("tool", width=220, anchor="w")
        self.audit.column("status", width=130, anchor="center")
        self.audit.column("ms", width=70, anchor="center")
        self.audit.column("tokens", width=90, anchor="center")
        self.audit.column("kb", width=90, anchor="center")
        self.audit.column("detail", width=90, anchor="center")
        self.audit.tag_configure("ok", foreground="#0A7D00")
        self.audit.tag_configure("warn", foreground="#C27C00")
        self.audit.tag_configure("err", foreground="#B00020")
        self.audit.pack(fill="both", expand=True)
        self._audit_row_data = {}
        self.audit.bind("<ButtonRelease-1>", self._on_audit_tree_click)
        self.audit.bind("<Double-1>", self._on_audit_tree_click)
        self.audit.bind("<Motion>", self._on_audit_motion)

        audcfg=ttk.Frame(left); audcfg.pack(fill="x")
        ttk.Label(audcfg, text="Per-Tool Timeout (s):").pack(side="left")
        self.audit_timeout=tk.StringVar(value="10")
        ttk.Entry(audcfg, textvariable=self.audit_timeout, width=5).pack(side="left")
        ttk.Label(audcfg, text="Parallelism:").pack(side="left")
        self.audit_parallel=tk.StringVar(value="1")
        ttk.Entry(audcfg, textvariable=self.audit_parallel, width=3).pack(side="left")
        ttk.Label(audcfg, text="Delay (ms):").pack(side="left", padx=(8,0))
        audit_spin_cls = getattr(ttk, "Spinbox", None)
        if audit_spin_cls is None and tk is not None:
            audit_spin_cls = tk.Spinbox
        if audit_spin_cls is not None:
            self._audit_delay_spin = audit_spin_cls(audcfg, from_=0, to=5000, increment=50, width=6, textvariable=self.audit_delay)
            self._audit_delay_spin.pack(side="left", padx=(2,0))
        self.audit_progress=tk.StringVar(value="")
        ttk.Label(audcfg, textvariable=self.audit_progress).pack(side="right")
        audbtns=ttk.Frame(left); audbtns.pack(fill="x")
        ttk.Button(audbtns, text="Run audit", command=self._run_audit).pack(side="left")
        ttk.Button(audbtns, text="Stop audit", command=self._stop_audit).pack(side="left")
        ttk.Button(audbtns, text="Clear audit", command=self._clear_audit).pack(side="left")

        ttk.Label(right, text="JSON-RPC Payload (f\u00fcr POST-Sample):").pack(anchor="w")
        self.payload=ScrolledText(right, height=10); self.payload.pack(fill="x")
        self._prefill_payload()

        rightbtns=ttk.Frame(right); rightbtns.pack(fill="x")
        ttk.Button(rightbtns, text="Open Tree Viewer (last JSON)", command=self._open_tree).pack(side="left")
        ttk.Button(rightbtns, text="Show cURL (last request)", command=self._show_curl).pack(side="left")
        ttk.Button(rightbtns, text="Save last request (.http)", command=self._save_httpfile).pack(side="left")
        ttk.Button(rightbtns, text="Request-Details", command=self._show_request_details).pack(side="left")

        ttk.Label(right, text="Console & Ereignisse:").pack(anchor="w")
        self.log_tabs = ttk.Notebook(right)
        self.log_tabs.pack(fill="both", expand=True)

        console_tab = ttk.Frame(self.log_tabs)
        events_tab = ttk.Frame(self.log_tabs)
        self.log_tabs.add(console_tab, text="Konsole")
        self.log_tabs.add(events_tab, text="Live-Ereignisse")

        logtools = ttk.Frame(console_tab); logtools.pack(fill="x")
        ttk.Label(logtools, text="Filter:").pack(side="left")
        entry = ttk.Entry(logtools, textvariable=self.log_filter, width=24)
        entry.pack(side="left", padx=(2,6))
        ttk.Button(logtools, text="Anwenden", command=self._apply_log_filter).pack(side="left")
        ttk.Button(logtools, text="Zur\u00fccksetzen", command=self._reset_log_filter).pack(side="left", padx=(4,0))
        entry.bind("<Return>", lambda e: self._apply_log_filter())
        ttk.Checkbutton(logtools, text="Nur Warnungen/Fehler", variable=self.log_warn_only, command=self._apply_log_filter).pack(side="left", padx=(8,0))
        ttk.Checkbutton(logtools, text="Zeige Laufnummer", variable=self.log_show_ids, command=self._apply_log_filter).pack(side="left", padx=(8,0))
        self.console=ScrolledText(console_tab, height=16); self.console.pack(fill="both", expand=True)
        self.console.configure(state="disabled")

        self.events_log=ScrolledText(events_tab, height=20)
        self.events_log.pack(fill="both", expand=True)
        self.events_log.configure(state="disabled", font=("Consolas", 10))

        tip = ttk.Label(self.root, text="Hinweis: Overall timeout gilt nur f\u00fcr den Gesamtcheck. Bearer nur via TLS.", foreground="#444")
        tip.pack(fill="x", **p)

    def _center_window(self, window, min_w=600, min_h=480):
        try:
            window.update_idletasks()
            w = window.winfo_width()
            h = window.winfo_height()
            if w < min_w: w = min_w
            if h < min_h: h = min_h
            sw = window.winfo_screenwidth()
            sh = window.winfo_screenheight()
            x = max((sw - w) // 2, 0)
            y = max((sh - h) // 2, 0)
            window.geometry(f"{w}x{h}+{x}+{y}")
        except Exception:
            pass

    def _show_wizard(self):
        if self._wizard_active or tk is None or self._state.get("wizard_done"):
            return
        self._wizard_active=True
        try:
            self.root.attributes("-disabled", True)
        except Exception:
            pass
        SetupWizard(self)

    def _wizard_closed(self, completed=False):
        try:
            self.root.attributes("-disabled", False)
        except Exception:
            pass
        self._wizard_active=False
        if completed:
            try:
                self._state["wizard_done"]=True
                self._save_settings()
            except Exception:
                pass
        try:
            self.root.focus_force()
        except Exception:
            pass

    def _prefill_payload(self):
        pl={"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":DEFAULT_PROTOCOL_VERSION,"capabilities":{},"clientInfo":{"name":"mcp-diagnoser-pro","version":"0.4.2"}}}
        self.payload.delete("1.0","end"); self.payload.insert("1.0", json.dumps(pl, indent=2))

    def _clear(self):
        self.mem_log.clear()
        self.events_log.configure(state="normal")
        self.events_log.delete("1.0","end")
        self.events_log.configure(state="disabled")
        self._refresh_console()
    def _reset_session(self): self.client=None; self._sink("Session-Objekt zur\u00fcckgesetzt.")

    def _pick_ca(self):
        p=filedialog.askopenfilename(title="CA-Bundle w\u00e4hlen", filetypes=[("Zertifikate","*.pem *.crt *.cer *.ca-bundle"),("Alle Dateien","*.*")])
        if p: self.ca.set(p)

    def _gen_ca(self):
        try:
            from certgen_ca_server import make_ca, make_server_cert, sha1_thumbprint
            from cryptography.hazmat.primitives import serialization
            out=os.path.join(os.path.dirname(__file__),"certs")
            os.makedirs(out, exist_ok=True)
            ca_key, ca_cert = make_ca("localhost", 3650)
            server_key, server_cert = make_server_cert(ca_key, ca_cert, "localhost", 3650)
            with open(os.path.join(out,"ca.key.pem"),"wb") as f:
                f.write(ca_key.private_bytes(encoding=serialization.Encoding.PEM,format=serialization.PrivateFormat.TraditionalOpenSSL,encryption_algorithm=serialization.NoEncryption()))
            with open(os.path.join(out,"ca.cert.pem"),"wb") as f:
                f.write(ca_cert.public_bytes(serialization.Encoding.PEM))
            with open(os.path.join(out,"localhost.key.pem"),"wb") as f:
                f.write(server_key.private_bytes(encoding=serialization.Encoding.PEM,format=serialization.PrivateFormat.TraditionalOpenSSL,encryption_algorithm=serialization.NoEncryption()))
            with open(os.path.join(out,"localhost.cert.pem"),"wb") as f:
                f.write(server_cert.public_bytes(serialization.Encoding.PEM))
            with open(os.path.join(out,"ca_thumbprint.txt"),"w",encoding="utf-8") as f:
                f.write(sha1_thumbprint(ca_cert))
            ca_path = os.path.join(out, "ca.cert.pem")
            self.ca.set(ca_path)
            self.tls_mode.set("Embedded CA (./certs/ca.cert.pem)")
            self._sink("CA + Server-Zertifikat unter ./certs erzeugt.")
        except Exception as e:
            self._sink(f"Zertifikatsfehler: {e}")

    def _state_path(self):
        return os.path.join(os.path.dirname(__file__), "mcp_debugger_state.json")

    def _load_state(self):
        path=self._state_path()
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    data=json.load(f)
                    if isinstance(data, dict):
                        return data
            except Exception:
                pass
        return {}

    def _save_state(self):
        try:
            with open(self._state_path(), "w", encoding="utf-8") as f:
                json.dump(self._state, f, ensure_ascii=False, indent=2)
        except Exception:
            pass

    def _save_settings(self):
        critical_keys=("url","tls_mode","ca","timeout","auth_mode","auth_token","auth_header","auth_enabled")
        previous={k:self._state.get(k) for k in critical_keys}
        updates={
            "url": self.url.get().strip(),
            "tls_mode": self.tls_mode.get(),
            "timeout": self.timeout.get(),
            "overall_timeout": self.overall_timeout.get(),
            "overall_delay": self.overall_delay.get(),
            "audit_delay": self.audit_delay.get(),
            "ca": self.ca.get().strip(),
            "auth_mode": self.auth_mode.get(),
            "auth_token": self.auth_token.get(),
            "auth_header": self.auth_header.get(),
            "auth_enabled": bool(self.auth_enabled.get()),
            "auto_session_renew": bool(self.auto_session.get()),
            "language": self.language.get(),
        }
        self._state.update(updates)
        if self.client is not None:
            try:
                self.client.auto_session_renew = bool(self.auto_session.get())
            except Exception:
                pass
        self._save_state()
        connection_changed=any(previous.get(k)!=updates.get(k) for k in critical_keys)
        if connection_changed:
            self.client=None
            self._sink("Settings saved. Connection parameters changed; session will be recreated.")
        else:
            self._sink("Settings saved.")

    def _on_window_close(self):
        try:
            self._save_settings()
        except Exception:
            pass
        try:
            self.root.destroy()
        except Exception:
            pass

    def _profiles_path(self): return os.path.join(os.path.dirname(__file__), "auth_profiles.json")
    def _load_profiles_file(self):
        p=self._profiles_path()
        if os.path.exists(p):
            try:
                with open(p, "r", encoding="utf-8") as f: return json.load(f)
            except Exception: return {}
        return {}
    def _write_profiles_file(self, data):
        with open(self._profiles_path(), "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    def _save_profile(self):
        url=self.url.get().strip()
        if not url:
            if messagebox: messagebox.showinfo("Profile", "URL fehlt."); 
            return
        data=self._load_profiles_file()
        data[url]={
            "auth_mode": self.auth_mode.get(),
            "token": self.auth_token.get(),
            "header": self.auth_header.get(),
            "enabled": bool(self.auth_enabled.get()),
        }
        self._write_profiles_file(data); self._sink(f"Profile gespeichert f\u00fcr URL: {url}")
    def _load_profile(self):
        url=self.url.get().strip(); data=self._load_profiles_file()
        if url not in data:
            if messagebox: messagebox.showinfo("Profile", "Kein Profil f\u00fcr diese URL.")
            return
        prof=data[url]
        self.auth_mode.set(prof.get("auth_mode","None"))
        self.auth_token.set(prof.get("token",""))
        self.auth_header.set(prof.get("header","Authorization"))
        enabled_flag = prof.get("enabled")
        if enabled_flag is None:
            enabled_flag = bool(self.auth_mode.get() != "None" and self.auth_token.get())
        self.auth_enabled.set(bool(enabled_flag))
        self._apply_auth()
        self._sink(f"Profile geladen f\u00fcr URL: {url}")
    def _delete_profile(self):
        url=self.url.get().strip(); data=self._load_profiles_file()
        if url in data:
            del data[url]; self._write_profiles_file(data); self._sink(f"Profile gel\u00f6scht f\u00fcr URL: {url}")
        else:
            if messagebox: messagebox.showinfo("Profile", "Kein Profil vorhanden.")

    def _apply_auth(self, silent=False):
        state = self._current_auth_state()
        result = state.compute()
        self.auth_enabled.set(result.effective)
        self._auth_extra = result.headers
        self._set_auth_labels(result)
        if not silent and result.log:
            self._sink(result.log)
        self.client = None

    def _current_auth_state(self):
        return AuthState(
            mode=self.auth_mode.get(),
            token=self.auth_token.get(),
            header=self.auth_header.get(),
            enabled=bool(self.auth_enabled.get()),
        )

    def _set_auth_labels(self, result):
        self.auth_status.set(result.status)
        self.auth_toggle_text.set(result.toggle)

    def _update_auth_status(self):
        self._set_auth_labels(self._current_auth_state().compute())

    def _toggle_auth(self):
        state = self._current_auth_state()
        if state.effective():
            self.auth_enabled.set(False)
            self._apply_auth()
            self._save_settings()
            return
        if not state.ready():
            self._sink("Auth: Bitte zuerst im Authentifizierungsmanager konfigurieren.")
            self._open_token_manager()
            return
        self.auth_enabled.set(True)
        self._apply_auth()
        self._save_settings()

    def _collect_mcp_info(self):
        info={
            "url": self.url.get().strip(),
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "errors":[],
        }
        client=self._create_client(silent=True)
        init_obj=None
        try:
            start=time.monotonic()
            init_obj, init_resp = client.initialize()
            info["initializeMs"] = int((time.monotonic()-start)*1000)
            info["httpInitialize"] = getattr(init_resp, "status_code", "n/a")
            info["sessionId"] = getattr(client, "sid", "")
            result = init_obj.get("result") if isinstance(init_obj, dict) else {}
            info["protocolVersion"] = result.get("protocolVersion")
            caps = result.get("capabilities") or {}
            info["capabilities"] = sorted(caps.keys())
            info["serverInfo"] = result.get("serverInfo") or {}
        except Exception as e:
            info["errors"].append(f"initialize: {e}")
        try:
            client.initialized()
        except Exception as e:
            info["errors"].append(f"notifications/initialized: {e}")
        def collect_list(name, func, key, label_key="name"):
            bucket={"count":0,"examples":[]}
            try:
                start=time.monotonic()
                obj, resp = func()
                bucket["http"] = getattr(resp, "status_code", "n/a")
                bucket["ms"] = int((time.monotonic()-start)*1000)
                items=((obj.get("result") or {}).get(key) or []) if isinstance(obj, dict) else []
                bucket["count"]=len(items)
                previews=[]
                for item in items[:5]:
                    if isinstance(item, dict):
                        previews.append(item.get(label_key) or item.get("uri") or "")
                    else:
                        previews.append(str(item))
                bucket["examples"]=previews
            except Exception as exc:
                info["errors"].append(f"{name}: {exc}")
            info[name]=bucket
        collect_list("tools", client.list_tools, "tools")
        collect_list("prompts", client.list_prompts, "prompts")
        collect_list("resources", client.list_resources, "resources", label_key="name")
        try:
            if getattr(client, "sid", ""):
                client.delete_session()
        except Exception:
            pass
        return info

    def _present_mcp_info(self, info):
        if tk is None:
            return
        top = tk.Toplevel(self.root)
        top.title("MCP-Info")
        try:
            top.transient(self.root)
        except Exception:
            pass
        text = ScrolledText(top, width=80, height=24)
        text.pack(fill="both", expand=True)
        def write(label, value=""):
            text.insert("end", f"{label}\n", ("section",))
            if isinstance(value, dict):
                text.insert("end", json.dumps(value, ensure_ascii=False, indent=2))
            else:
                text.insert("end", value if value else " - ")
            text.insert("end", "\n\n")
        text.tag_config("section", font=("Segoe UI", 10, "bold"))
        write("Zeitpunkt", info.get("timestamp",""))
        write("URL", info.get("url",""))
        proto = info.get("protocolVersion") or "unbekannt"
        if proto not in ["unbekannt"] and proto not in KNOWN_MCP_VERSIONS:
            proto = f"{proto} \u274c UNKNOWN (not in known versions)"
        elif proto in LEGACY_MCP_VERSIONS:
            proto = f"{proto} \u26a0 LEGACY (SSE-based, outdated)"
        elif proto != "unbekannt" and proto < DEFAULT_PROTOCOL_VERSION:
            proto = f"{proto} \u26a0 OUTDATED (latest: {DEFAULT_PROTOCOL_VERSION})"
        write("Protokoll-Version", proto)
        caps = ", ".join(info.get("capabilities") or []) or "keine"
        write("Bereitgestellte F\u00e4higkeiten", caps)
        server_info = info.get("serverInfo") or {}
        if server_info:
            write("Server-Details", server_info)
        init_ms = info.get("initializeMs")
        if init_ms is not None:
            status = info.get("httpInitialize", "n/a")
            session = info.get("sessionId") or " - "
            write("Handshake", f"HTTP {status} \u00b7 {init_ms} ms \u00b7 Session: {session}")
        def render_bucket(title, bucket):
            count = bucket.get("count",0)
            examples = bucket.get("examples") or []
            if examples:
                sample = ", ".join(ex if ex else " - " for ex in examples)
            else:
                sample = "keine Beispiele"
            extra = ""
            if "ms" in bucket:
                extra = f" \u00b7 {bucket['ms']} ms"
            icon = "\u2705" if count else "\u26a0"
            write(f"{icon} {title}", f"{count} Eintr\u00e4ge{extra}\nBeispiele: {sample}")
        render_bucket("Tools", info.get("tools", {}))
        render_bucket("Prompts", info.get("prompts", {}))
        render_bucket("Resources", info.get("resources", {}))
        errors = info.get("errors") or []
        if errors:
            write("Hinweise", "\n".join(errors))
        text.config(state="disabled")
        ttk.Button(top, text="Schlie\u00dfen", command=top.destroy).pack(pady=6)

    def _show_mcp_info(self):
        self._sink("MCP-Info wird geladen ...")
        def worker():
            info = self._collect_mcp_info()
            self.root.after(0, lambda: self._present_mcp_info(info))
        threading.Thread(target=worker, daemon=True).start()

    def _show_input_methods(self):
        if tk is None:
            self._sink("Input-Methoden-Ansicht nicht verfuegbar (Tkinter fehlt).")
            return
        existing = getattr(self, "_input_methods_dialog", None)
        if existing and str(existing) and existing.winfo_exists():
            try:
                existing.lift()
                existing.focus_force()
            except Exception:
                pass
            return
        self._sink("Input-Methoden werden gesammelt ...")
        def worker():
            data = self._collect_input_methods()
            self.root.after(0, lambda: self._present_input_methods(data))
        threading.Thread(target=worker, daemon=True).start()

    def _collect_input_methods(self):
        result={"methods":[], "errors":[]}
        client=self._create_client(silent=True)
        try:
            obj, _ = client.initialize()
            caps=(obj.get("result") or {}).get("capabilities") if isinstance(obj, dict) else {}
            if isinstance(caps, dict):
                result["methods"]=self._extract_input_methods(caps)
            else:
                result["errors"].append("Capabilities nicht verfuegbar")
        except Exception as exc:
            result["errors"].append(str(exc))
        finally:
            try:
                if getattr(client, "sid", ""):
                    client.delete_session()
            except Exception:
                pass
        return result

    def _extract_input_methods(self, caps):
        methods=[]
        def walk(node, path):
            if isinstance(node, dict):
                name="::".join(path) if path else "root"
                modes=node.get("modes")
                transport=node.get("transport")
                allow=node.get("allowAnonymous")
                tokens=node.get("tokensConfigured")
                if isinstance(modes, (list, tuple)):
                    methods.append({
                        "name": name,
                        "transport": transport,
                        "modes": ", ".join(str(m) for m in modes),
                        "allowAnonymous": allow,
                        "tokensConfigured": tokens,
                    })
                for key, value in node.items():
                    walk(value, path+[str(key)])
            elif isinstance(node, (list, tuple)):
                for idx, item in enumerate(node):
                    walk(item, path+[str(idx)])
        walk(caps, [])
        unique={}
        for method in methods:
            unique_key=(method["name"], method["transport"], method["modes"])
            unique[unique_key]=method
        return list(unique.values())

    def _present_input_methods(self, data):
        methods=data.get("methods") or []
        errors=data.get("errors") or []
        if tk is None:
            self._sink("Input-Methoden: " + ("keine" if not methods else str(methods)))
            return
        if not methods and errors:
            if messagebox:
                try:
                    messagebox.showwarning("Input-Methoden", "Keine Input-Methoden gefunden: " + "; ".join(errors))
                except Exception:
                    pass
            else:
                self._sink("Input-Methoden: " + "; ".join(errors))
            return
        self._resource_cache.clear()
        top=tk.Toplevel(self.root)
        top.title("Input-Methoden")
        self._input_methods_dialog=top
        def on_close():
            try:
                top.destroy()
            finally:
                self._input_methods_dialog=None
        top.protocol("WM_DELETE_WINDOW", on_close)
        try:
            top.transient(self.root)
        except Exception:
            pass
        frame=ttk.Frame(top); frame.pack(fill="both", expand=True, padx=10, pady=10)
        ttk.Label(frame, text="Bekannte Eingabemethoden", font=("Segoe UI", 11, "bold")).pack(anchor="w")
        columns=("name","transport","modes","anonymous","tokens")
        tree=ttk.Treeview(frame, columns=columns, show="headings", height=8)
        tree.heading("name", text="Name")
        tree.heading("transport", text="Transport")
        tree.heading("modes", text="Modi")
        tree.heading("anonymous", text="Allow anonymous")
        tree.heading("tokens", text="Tokens konfiguriert")
        tree.column("name", width=220, anchor="w")
        tree.column("transport", width=120, anchor="center")
        tree.column("modes", width=200, anchor="w")
        tree.column("anonymous", width=130, anchor="center")
        tree.column("tokens", width=140, anchor="center")
        tree.pack(fill="both", expand=True, pady=(6,6))
        for method in methods:
            tree.insert("", "end", values=(
                method.get("name",""),
                method.get("transport",""),
                method.get("modes",""),
                str(method.get("allowAnonymous")),
                str(method.get("tokensConfigured")),
            ))
        if errors:
            err_label=ttk.Label(frame, text="Hinweise: " + "; ".join(errors), foreground="#B00020", wraplength=480, justify="left")
            err_label.pack(fill="x", pady=(4,0))
        ttk.Button(frame, text="Schliessen", command=on_close).pack(pady=(6,0), anchor="e")

    def _open_resource_browser(self):
        if tk is None:
            self._sink("Ressourcen-Browser nicht verfuegbar (Tkinter fehlt).")
            return
        existing = getattr(self, "_resources_dialog", None)
        if existing and str(existing) and existing.winfo_exists():
            try:
                existing.lift()
                existing.focus_force()
            except Exception:
                pass
            return
        self._sink("Ressourcen werden gesammelt ...")
        def worker():
            data = self._collect_resource_list()
            self.root.after(0, lambda: self._present_resource_browser(data))
        threading.Thread(target=worker, daemon=True).start()

    def _collect_resource_list(self):
        result={"items":[], "errors":[]}
        client=self._create_client(silent=True)
        try:
            client.initialize(); client.initialized()
            obj, resp = client.list_resources()
            resources = (obj.get("result") or {}).get("resources") if isinstance(obj, dict) else []
            if isinstance(resources, list):
                for entry in resources:
                    if not isinstance(entry, dict):
                        continue
                    result["items"].append({
                        "name": entry.get("name") or entry.get("uri") or "(ohne Name)",
                        "uri": entry.get("uri"),
                        "mimeType": entry.get("mimeType"),
                        "description": entry.get("description"),
                    })
            result["http_status"] = getattr(resp, "status_code", None)
        except Exception as exc:
            result["errors"].append(str(exc))
        finally:
            try:
                if getattr(client, "sid", ""):
                    client.delete_session()
            except Exception:
                pass
        return result

    def _read_resource_content(self, uri):
        result={"uri":uri, "content":None, "errors":[]}
        if not uri:
            result["errors"].append("Keine URI angegeben")
            return result
        client=self._create_client(silent=True)
        def _invalid_params(obj):
            return isinstance(obj, dict) and isinstance(obj.get("error"), dict) and obj["error"].get("code")==-32602
        try:
            client.initialize(); client.initialized()
            params={"uris":[uri]}
            obj, _ = client.call("resources/read", params, stream=False, accept_json_only=True, sse_max_seconds=10)
            if _invalid_params(obj):
                params={"uris":[{"uri": uri}]}
                obj, _ = client.call("resources/read", params, stream=False, accept_json_only=True, sse_max_seconds=10)
            if isinstance(obj, dict) and isinstance(obj.get("error"), dict):
                err=obj["error"].get("message") or str(obj["error"])
                result["errors"].append(err)
                try:
                    result["content"]=json.dumps(obj, ensure_ascii=False, indent=2)
                except Exception:
                    result["content"]=str(obj)
                return result
            contents = (obj.get("result") or {}).get("contents") if isinstance(obj, dict) else None
            if isinstance(contents, list) and contents:
                first = contents[0]
                if isinstance(first, dict):
                    if first.get("text") is not None:
                        value = first.get("text")
                        result["content"] = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, indent=2)
                    elif first.get("bytes") is not None:
                        result["content"] = "<binary content>"
                    else:
                        result["content"] = json.dumps(first, ensure_ascii=False, indent=2)
                else:
                    result["content"] = str(first)
            else:
                try:
                    result["content"] = json.dumps(obj, ensure_ascii=False, indent=2)
                except Exception:
                    result["content"] = "<keine Daten>"
        except Exception as exc:
            result["errors"].append(str(exc))
        finally:
            try:
                if getattr(client, "sid", ""):
                    client.delete_session()
            except Exception:
                pass
        return result

    def _present_resource_browser(self, data):
        if tk is None:
            items=data.get("items") or []
            self._sink(f"Ressourcen: {len(items)} gefunden")
            return
        dialog=getattr(self, "_resources_dialog", None)
        if dialog and str(dialog) and dialog.winfo_exists():
            try:
                dialog.destroy()
            except Exception:
                pass
            self._resources_dialog=None
        top=tk.Toplevel(self.root)
        top.title("Ressourcen-Browser")
        self._resources_dialog=top
        self._resource_cache.clear()

        def on_close():
            try:
                top.destroy()
            finally:
                self._resources_dialog=None

        top.protocol("WM_DELETE_WINDOW", on_close)
        try:
            top.geometry("900x500")
            top.transient(self.root)
        except Exception:
            pass
        container=ttk.Frame(top)
        container.pack(fill="both", expand=True, padx=10, pady=10)
        splitter=ttk.PanedWindow(container, orient="horizontal")
        splitter.pack(fill="both", expand=True)
        left_frame=ttk.Frame(splitter)
        right_frame=ttk.Frame(splitter)
        splitter.add(left_frame, weight=1)
        splitter.add(right_frame, weight=2)
        columns=("name","uri","mime")
        tree=ttk.Treeview(left_frame, columns=columns, show="headings", height=15)
        tree.heading("name", text="Name")
        tree.heading("uri", text="URI")
        tree.heading("mime", text="MIME-Type")
        tree.column("name", width=220, anchor="w")
        tree.column("uri", width=280, anchor="w")
        tree.column("mime", width=140, anchor="center")
        tree.pack(fill="both", expand=True)
        scrollbar=ttk.Scrollbar(left_frame, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        text_widget=ScrolledText(right_frame, wrap="word")
        text_widget.pack(fill="both", expand=True)
        status_label=ttk.Label(right_frame, text="Bitte Ressource waehlen", foreground="#444")
        status_label.pack(fill="x", pady=(6,0))
        items=data.get("items") or []
        for entry in items:
            tree.insert("", "end", values=(entry.get("name",""), entry.get("uri",""), entry.get("mimeType","")))
        errors=data.get("errors") or []
        if errors:
            status_label.configure(text="Hinweise: " + "; ".join(errors), foreground="#B00020")

        def load_resource(event=None):
            selection=tree.selection()
            if not selection:
                return
            item_id=selection[0]
            values=tree.item(item_id, "values")
            uri=values[1]
            mime_value=values[2]
            status_label.configure(text=f"Lade Ressource: {uri}", foreground="#444")
            text_widget.configure(state="normal")
            text_widget.delete("1.0","end")
            text_widget.insert("end", "Lade ...")
            text_widget.configure(state="disabled")

            def worker():
                info=self._read_resource_content(uri)
                def update():
                    content=info.get("content") or "<keine Daten>"
                    text_widget.configure(state="normal")
                    text_widget.delete("1.0","end")
                    text_widget.insert("end", content)
                    text_widget.configure(state="disabled")
                    errs=info.get("errors") or []
                    self._resource_cache[uri]={"content":content, "mime":mime_value}
                    if errs:
                        status_label.configure(text="; ".join(errs), foreground="#B00020")
                    else:
                        status_label.configure(text=f"Ressource: {uri}", foreground="#444")
                try:
                    self.root.after(0, update)
                except Exception:
                    pass
            threading.Thread(target=worker, daemon=True).start()

        tree.bind("<<TreeviewSelect>>", load_resource)

        def validate_current():
            selection=tree.selection()
            if not selection:
                status_label.configure(text="Bitte Ressource waehlen", foreground="#B00020")
                return
            item_id=selection[0]
            uri=tree.item(item_id, "values")[1]
            cache=self._resource_cache.get(uri)
            if not cache or not cache.get("content"):
                status_label.configure(text="Bitte Ressource zuerst laden, dann validieren.", foreground="#C27C00")
                load_resource()
                return
            status, message = self._validate_resource_content(cache.get("content"), cache.get("mime"))
            color = "#0A7D00" if status=="OK" else ("#C27C00" if status=="WARN" else "#B00020")
            status_label.configure(text=f"Validierung ({status}): {message}", foreground=color)

        btn_row=ttk.Frame(container)
        btn_row.pack(fill="x", pady=(8,0))
        ttk.Button(btn_row, text="Validieren", command=validate_current).pack(side="left")
        ttk.Button(btn_row, text="Schliessen", command=on_close).pack(side="right")

    def _validate_resource_content(self, content, mime_type):
        mime = (mime_type or "").lower()
        try:
            if "json" in mime:
                json.loads(content)
                return "OK", "JSON ist valide."
            if "yaml" in mime or mime.endswith("+yml") or mime.endswith("+yaml"):
                try:
                    import yaml  # type: ignore
                except ImportError:
                    return "WARN", "PyYAML nicht installiert."
                yaml.safe_load(content)
                return "OK", "YAML ist valide."
            if "markdown" in mime or mime.endswith("md"):
                if content.strip():
                    return "OK", "Markdown-Inhalt vorhanden."
                return "FAIL", "Markdown-Inhalt ist leer."
            if content and content.strip():
                return "OK", "Textinhalt nicht leer."
            return "WARN", "Inhalt ist leer."
        except Exception as exc:
            return "FAIL", str(exc)

    def _collect_context_layers(self):
        info={"errors":[], "layers":[]}
        client=self._create_client(silent=True)
        layers=[]
        try:
            start=time.monotonic()
            init_obj, init_resp = client.initialize()
            client.initialized()
            init_ms=int((time.monotonic()-start)*1000)
            init_http=getattr(init_resp,"status_code","n/a")
            result = init_obj.get("result") if isinstance(init_obj, dict) else {}
            session_id=getattr(client,"sid","")
            proto_ver = result.get("protocolVersion") or "unbekannt"
            if proto_ver not in ["unbekannt"] and proto_ver not in KNOWN_MCP_VERSIONS:
                proto_ver = f"{proto_ver} \u274c UNKNOWN"
            elif proto_ver in LEGACY_MCP_VERSIONS:
                proto_ver = f"{proto_ver} \u26a0 LEGACY"
            elif proto_ver != "unbekannt" and proto_ver < DEFAULT_PROTOCOL_VERSION:
                proto_ver = f"{proto_ver} \u26a0 OUTDATED"
            handshake_items=[
                {"label":"Protokoll-Version","details":proto_ver},
                {"label":"HTTP Status","details":f"{init_http} \u00b7 {init_ms} ms"},
                {"label":"Session-ID","details":session_id or "keine"},
            ]
            capabilities=result.get("capabilities") or {}
            if capabilities:
                handshake_items.append({"label":"Capabilities","details":json.dumps(capabilities, ensure_ascii=False, indent=2)})
            server_info=result.get("serverInfo") or {}
            if server_info:
                handshake_items.append({"label":"Server-Info","details":json.dumps(server_info, ensure_ascii=False, indent=2)})
            layers.append({"title":"Ebene 1 - Handshake","items":handshake_items})

            def collect_section(title, getter, key, formatter):
                try:
                    obj, resp = getter()
                    items = ((obj.get("result") or {}).get(key) or []) if isinstance(obj, dict) else []
                    section={"title":title,"items":[]}
                    section["items"].append({"label":"\u00dcbersicht","details":f"{len(items)} Eintr\u00e4ge \u00b7 HTTP {getattr(resp,'status_code','n/a')}"})
                    for entry in items:
                        label, detail = formatter(entry)
                        section["items"].append({"label":label,"details":detail})
                    layers.append(section)
                except Exception as exc:
                    info["errors"].append(f"{title}: {exc}")

            collect_section(
                "Ebene 2 - Tools",
                client.list_tools,
                "tools",
                lambda item: (
                    item.get("name","(ohne Name)"),
                    json.dumps({
                        "description": item.get("description"),
                        "inputSchema": item.get("inputSchema"),
                        "outputSchema": item.get("outputSchema"),
                    }, ensure_ascii=False, indent=2)
                )
            )

            collect_section(
                "Ebene 3 - Prompts",
                client.list_prompts,
                "prompts",
                lambda item: (
                    item.get("name","(ohne Name)"),
                    json.dumps({
                        "description": item.get("description"),
                        "arguments": item.get("argumentSchema"),
                    }, ensure_ascii=False, indent=2)
                )
            )

            collect_section(
                "Ebene 4 - Ressourcen",
                client.list_resources,
                "resources",
                lambda item: (
                    item.get("name") or item.get("uri") or "(ohne Name)",
                    json.dumps({
                        "uri": item.get("uri"),
                        "mimeType": item.get("mimeType"),
                        "description": item.get("description"),
                    }, ensure_ascii=False, indent=2)
                )
            )
        except Exception as exc:
            info["errors"].append(str(exc))
        finally:
            try:
                if getattr(client, "sid", ""):
                    client.delete_session()
            except Exception:
                pass
        if info["errors"]:
            layers.append({
                "title": "Hinweise",
                "items": [{"label": f"# {idx+1}", "details": err} for idx, err in enumerate(info["errors"])]
            })
        info["layers"]=layers
        return info

    def _show_context_layers(self, data):
        if tk is None:
            return
        if not data:
            self._sink("Kontext-Navigator: keine Daten.")
            return
        errs = data.get("errors") or []
        if errs:
            self._sink("Kontext-Navigator Hinweise: " + " | ".join(str(e) for e in errs))
        dlg = ContextNavigatorDialog(self, data, title="Kontext-Navigator")
        self._context_layers = dlg

    def _create_client(self, extra_override=None, silent=False):
        mode = self.tls_mode.get()
        verify=True
        if mode=="Insecure (not recommended)":
            verify=False
        elif mode=="Embedded CA (./certs/ca.cert.pem)":
            p=os.path.join(os.path.dirname(__file__),"certs","ca.cert.pem")
            verify=p if os.path.exists(p) else True
            if not os.path.exists(p):
                self._sink("WARN: ./certs/ca.cert.pem nicht gefunden. 'Generate CA+Server' ausf\u00fchren oder TLS Mode wechseln.")
        elif mode=="Pick file...":
            p=self.ca.get().strip(); verify=p if p else True
        url=self.url.get().strip()
        try: to=float(self.timeout.get() or "30")
        except: to=30.0
        extra = extra_override if extra_override is not None else getattr(self, "_auth_extra", {})
        if extra and mode=="Insecure (not recommended)":
            self._sink("WARN: Bearer/API-Key niemals ohne TLS senden.")
        if not verify:
            try:
                from urllib3.exceptions import InsecureRequestWarning
                warnings.simplefilter("ignore", InsecureRequestWarning)
            except Exception:
                pass
        if silent:
            class QuietSink(Sink):
                def write(self, line):
                    msg = f"[{ts()}] {line}"
                    limit = getattr(self, '_log_store_limit', LOG_STORE_CLIP)
                    if limit and len(msg) > limit:
                        omitted = len(msg) - limit
                        msg = f"{msg[:limit]}... (gekuerzt, {omitted} weitere Zeichen unterdrueckt)"
                    self.mem_log.append(msg)
                    # Prevent memory leak: trim log if it grows too large
                    if len(self.mem_log) > 10000:
                        self.mem_log = self.mem_log[-5000:]
                    if len(self.mem_log) > 10000:
                        self.mem_log = self.mem_log[-5000:]
                    if "Session-Objekt zurückgesetzt" in line or "Session-Objekt zur\u00fcckgesetzt" in line:
                        self.session_resets += 1
            sink = QuietSink(gui_cb=None, mem_log=[])
        else:
            sink = Sink(self._sink, self.mem_log)
        return MCP(url, verify=verify, timeout=to, extra=extra, sink=sink, verbose=False, auto_session_renew=bool(self.auto_session.get()))

    def _build_client(self, reset=False, extra_override=None):
        if reset or self.client is None:
            self.client = self._create_client(extra_override=extra_override)
        return self.client

    def _update_tree_action_state(self, event=None):
        btn = getattr(self, "run_selected_btn", None)
        if not btn:
            return
        try:
            has_selection = bool(self.tree.selection())
        except Exception:
            has_selection = False
        state = "normal" if has_selection else "disabled"
        try:
            btn.config(state=state)
        except Exception:
            pass

    def _run_selected(self):
        sel=self.tree.selection()
        if not sel: return
        action=sel[0]
        threading.Thread(target=lambda: self._run_action(action), daemon=True).start()

    def _start_overall(self, reset_session):
        self._clear_summary()
        c=self._build_client(reset=reset_session)
        try: ov_to=float(self.overall_timeout.get() or "30")
        except: ov_to=30.0
        try: delay_ms=float(self.overall_delay.get() or "0")
        except: delay_ms=0.0
        step_delay=max(0.0, delay_ms/1000.0)
        self.summary_status.set("Overall-Test laeuft ...")

        # Stop flag for cancellation
        self._overall_stop_flag = False

        def on_cancel():
            self._overall_stop_flag = True
            self._sink("Overall-Test wird abgebrochen...")

        dlg = ProgressDialog(self.root, "Gesamttest", "Vorbereitung ...", cancelable=True, on_cancel=on_cancel, modal=False)
        self._overall_progress_dialog = dlg
        self._overall_current_stage = ""
        self._overall_wait_tick = 0
        self._cancel_overall_wait_animation()

        def stage_cb(stage):
            def _set():
                if stage:
                    self.summary_status.set(f"Aktuell: {stage}")
                else:
                    self.summary_status.set("Aktuell: -")
                self._set_overall_stage(stage)
            try:
                self.root.after(0, _set)
            except Exception:
                pass

        def stop_check():
            return getattr(self, '_overall_stop_flag', False)

        def run():
            try:
                summary, details = c.overall(timeout_override=ov_to, step_delay=step_delay, stage_callback=stage_cb, stop_flag=stop_check)
                if getattr(self, '_overall_stop_flag', False):
                    status_msg="\u26a0 Test abgebrochen"
                else:
                    status_msg="\u2714 Gesamtcheck abgeschlossen"
            except Exception as e:
                if getattr(self, '_overall_stop_flag', False):
                    summary=[{"level":"MUST","check":"overall()", "status":"FAIL","detail":"Abgebrochen durch Benutzer"}]; details={}
                    status_msg="\u26a0 Test abgebrochen"
                else:
                    summary=[{"level":"MUST","check":"overall()", "status":"FAIL","detail":str(e)}]; details={}
                    status_msg=f"Fehler: {e}"
            self.last_report={"summary":summary,"details":details,"log":"\n".join(self.mem_log),"meta":{"url":self.url.get().strip(),"tls_mode":self.tls_mode.get(),"time":time.strftime("%Y-%m-%d %H:%M:%S"),"protocol_version":getattr(c,'proto',''),"session_id":getattr(c,'sid','')}}
            def _finalize():
                if summary:
                    self._populate_summary(summary)
                else:
                    self.summary.insert("", "end", values=("Keine Ergebnisse", "", "", ""))
                self.summary_status.set(status_msg)
                self._cancel_overall_wait_animation()
                current = getattr(self, "_overall_progress_dialog", None)
                if current:
                    current.close()
                    self._overall_progress_dialog = None
                self._overall_stop_flag = False
            self.root.after(0, _finalize)
        threading.Thread(target=run, daemon=True).start()

    def _cancel_overall_wait_animation(self):
        job = getattr(self, "_overall_wait_job", None)
        if job:
            try:
                self.root.after_cancel(job)
            except Exception:
                pass
        self._overall_wait_job=None

    def _start_overall_wait_animation(self):
        self._cancel_overall_wait_animation()
        if not self._overall_current_stage:
            return
        def tick():
            current = getattr(self, "_overall_progress_dialog", None)
            if not current or not self._overall_current_stage:
                self._overall_wait_job=None
                return
            self._overall_wait_tick = (self._overall_wait_tick + 1) % 3
            dots = "." * (self._overall_wait_tick + 1)
            try:
                current.update_message(f"Schritt: {self._overall_current_stage} (warte{dots})")
            except Exception:
                pass
            try:
                self._overall_wait_job = self.root.after(450, tick)
            except Exception:
                self._overall_wait_job=None
        tick()

    def _set_overall_stage(self, stage_label):
        current = getattr(self, "_overall_progress_dialog", None)
        if stage_label:
            self._overall_current_stage = stage_label
            self._overall_wait_tick = -1
            if current:
                try:
                    current.update_message(f"Schritt: {stage_label}")
                except Exception:
                    pass
            self._start_overall_wait_animation()
        else:
            self._overall_current_stage = ""
            self._cancel_overall_wait_animation()
            if current:
                try:
                    current.update_message("Gesamttest laeuft ...")
                except Exception:
                    pass

    def _run_all(self):
        self._start_overall(reset_session=True)

    def _run_overall(self):
        self._start_overall(reset_session=False)

    def _clear_summary(self):
        self.summary_detail_map = {}
        self.summary_data_map = {}
        try:
            self.summary.delete(*self.summary.get_children())
        except Exception:
            while True:
                children = self.summary.get_children()
                if not children:
                    break
                self.summary.delete(children[0])

    def _populate_summary(self, summary):
        warn_statuses={"WARN","INFO","WARN_BLOCKED","WARN_ACTION_REQUIRED","WARN_STATE_UNCLEAR","WARN_NOT_IMPLEMENTED"}
        self.summary_detail_map={}
        self.summary_data_map={}
        for it in summary:
            status=it.get("status","")
            if status=="OK":
                tag="ok"
            elif status in warn_statuses:
                tag="warn"
            else:
                tag="err"
            item=self.summary.insert("", "end", values=(it["check"], it["level"], status, it.get("detail","")), tags=(tag,))
            key=it.get("detail_key")
            if key:
                self.summary_detail_map[item]=key
            self.summary_data_map[item]=it

    def _open_selected_summary_detail(self):
        sel = self.summary.selection()
        if not sel:
            return
        self._show_summary_detail_for_item(sel[0])

    def _on_summary_double_click(self, event):
        item = self.summary.identify_row(event.y)
        if not item:
            return
        try:
            self.summary.selection_set(item)
        except Exception:
            pass
        self._show_summary_detail_for_item(item)

    def _on_summary_right_click(self, event):
        item = self.summary.identify_row(event.y)
        if not item:
            return
        try:
            self.summary.selection_set(item)
        except Exception:
            pass
        key = self.summary_detail_map.get(item)
        if key:
            try:
                self._summary_menu.tk_popup(event.x_root, event.y_root)
            finally:
                self._summary_menu.grab_release()

    def _show_summary_detail_for_item(self, item):
        key = self.summary_detail_map.get(item)
        if not key:
            if messagebox:
                messagebox.showinfo("Summary", "Keine Request/Response-Daten für diesen Eintrag.")
            return
        details = (self.last_report or {}).get("details") or {}
        data = details.get(key)
        if not isinstance(data, dict):
            if messagebox:
                messagebox.showwarning("Summary", f"Keine Detaildaten für '{key}' vorhanden.")
            return
        summary_entry = self.summary_data_map.get(item, {})
        check_label = summary_entry.get("check") or key
        SummaryDetailDialog(self, check_label, key, data)


    def _run_auth_tests(self):
        self.summary.insert("", "end", values=("Auth tests", "", "", ""))
        url=self.url.get().strip()
        try: to=float(self.timeout.get() or "30")
        except: to=30.0
        mode = self.tls_mode.get()
        verify=True
        if mode=="Insecure (not recommended)": verify=False
        elif mode=="Embedded CA (./certs/ca.cert.pem)":
            p=os.path.join(os.path.dirname(__file__),"certs","ca.cert.pem"); verify=p if os.path.exists(p) else True
        elif mode=="Pick file...":
            p=self.ca.get().strip(); verify=p if p else True

        def mk(extra):
            return MCP(url, verify=verify, timeout=to, extra=extra, sink=Sink(self._sink, self.mem_log), verbose=False)

        tests=[("No token", {}),("Invalid token", {"Authorization": "Bearer invalid-"+str(int(time.time()))}),("Provided token", getattr(self, "_auth_extra", {}))]
        def run():
            rows=[]
            for name, extra in tests:
                c = mk(extra)
                try:
                    obj, r = c.initialize()
                    code=r.status_code
                    if name=="No token" and code==401:
                        wa=r.headers.get("WWW-Authenticate",""); status="OK" if wa else "WARN"; detail=f"401; WWW-Authenticate: {wa or 'missing'}"
                    elif name=="Invalid token" and code in (401,403):
                        status="OK"; detail=f"HTTP {code}"
                    elif name=="Provided token" and 200 <= code < 300:
                        status="OK"; detail=f"HTTP {code}"
                    else:
                        status="INFO"; detail=f"HTTP {code}"
                except Exception as e:
                    status="FAIL"; detail=str(e)
                rows.append((f"Auth: {name}", "INFO", status, detail))
            warn_statuses={"WARN","INFO","WARN_BLOCKED","WARN_ACTION_REQUIRED","WARN_STATE_UNCLEAR","WARN_NOT_IMPLEMENTED"}
            def _tag_for_status(status):
                if status=="OK":
                    return "ok"
                if status in warn_statuses:
                    return "warn"
                return "err"
            def _populate_rows():
                for row in rows:
                    tag=_tag_for_status(row[2])
                    self.summary.insert("", "end", values=row, tags=(tag,))
            self.root.after(0, _populate_rows)
        threading.Thread(target=run, daemon=True).start()

    def _stop_audit(self):
        self._audit_stop=True
        self._sink("Audit stop requested. L\u00e4uft bis zum Ende des aktuellen Requests weiter.")
        if self._audit_running:
            self.audit_progress.set(f"Stop requested \u00b7 {self._audit_running} running")
        else:
            self.audit_progress.set("Stop requested")

    def _run_audit(self):
        confirmed = True
        if messagebox is not None:
            try:
                confirmed = messagebox.askokcancel("Warnung", "\u26a0 Run audit f\u00fchrt alle verf\u00fcgbaren Tools aus. Sicher fortfahren?", icon="warning", default='cancel', parent=getattr(self, 'root', None))
            except Exception:
                confirmed = True
        if not confirmed:
            self._sink("Run audit abgebrochen durch Benutzer.")
            return
        for i in self.audit.get_children(): self.audit.delete(i)
        self._audit_row_data = {}
        self._audit_timelines = {}
        self._audit_call_items = {}
        self._audit_stop=False
        c=self._build_client(reset=False)
        if c.sid=="":
            self._sink("Keine Session aktiv. Bitte zuerst 'POST initialize' ausf\u00fchren."); return
        try: per_to=float(self.audit_timeout.get() or "10")
        except: per_to=10.0
        try: parallel=int(self.audit_parallel.get() or "1")
        except: parallel=1
        try: delay_ms=float(self.audit_delay.get() or "0")
        except: delay_ms=0.0
        throttle_seconds=max(0.0, delay_ms/1000.0)
        self.audit_progress.set("")
        self._audit_total=0
        self._audit_done=0
        self._audit_running=0

        def _update_audit_status():
            total=self._audit_total
            running=self._audit_running
            done=self._audit_done
            parts=[]
            if total:
                parts.append(f"{done}/{total} done")
            elif done:
                parts.append(f"{done} done")
            if running:
                parts.append(f"{running} running")
            self.audit_progress.set(" \u00b7 ".join(parts) if parts else "")

        def on_progress(event):
            if event is None: 
                return
            def _ins(): 
                meta = event.get("meta") if isinstance(event, dict) else None
                if meta == "timeline":
                    call_id = event.get("call_id")
                    tool_name = event.get("tool") or ""
                    phase = event.get("phase") or ""
                    status = event.get("status") or ""
                    ms_val = event.get("ms")
                    summary = f"Timeline \u00b7 {tool_name} \u00b7 {phase} ({ms_val} ms)" if ms_val is not None else f"Timeline \u00b7 {tool_name} \u00b7 {phase}"
                    self._append_event_line(summary.strip())
                    if call_id:
                        timeline = self._audit_timelines.setdefault(call_id, [])
                        timeline.append({
                            "phase": event.get("phase"),
                            "ts": event.get("ts"),
                            "status": event.get("status"),
                            "ms": event.get("ms"),
                        })
                        item_ref = getattr(self, "_audit_call_items", {}).get(call_id)
                        if item_ref and item_ref in self._audit_row_data:
                            self._audit_row_data[item_ref]["timeline"] = list(timeline)
                    return
                if meta == "start":
                    try:
                        self._audit_total = max(0, int(event.get("total") or 0))
                    except Exception:
                        self._audit_total = 0
                    self._audit_done = 0
                    self._audit_running = 0
                    _update_audit_status()
                    return
                if meta == "inflight":
                    try:
                        delta=int(event.get("delta") or 0)
                    except Exception:
                        delta=0
                    self._audit_running = max(0, self._audit_running + delta)
                    _update_audit_status()
                    return
                res=event
                tag=""
                okset={"OK","ARGS_VALID","OUTPUT_VALID"}
                warnset={"WARN","INFO","WARN_BLOCKED","WARN_ACTION_REQUIRED","WARN_STATE_UNCLEAR","WARN_NOT_IMPLEMENTED"}
                errset={"ARGS_INVALID","HTTP_ERROR","PROTOCOL_ERROR","TOOL_ERROR","TIMEOUT","EXCEPTION","OUTPUT_SCHEMA_INVALID","DEVICE_ERROR"}
                status=res.get("status","")
                if status in okset: tag="ok"
                elif status in warnset: tag="warn"
                elif status in errset: tag="err"
                tokens_val=res.get("tokens",0)
                try: tokens_str=str(int(tokens_val))
                except Exception: tokens_str=str(tokens_val)
                detail_display = "View..."
                call_id = res.get("call_id")
                if call_id:
                    res["timeline"] = list(self._audit_timelines.get(call_id, []))
                item=self.audit.insert("", "end", values=(res.get("tool","?"), status, f"{int(res.get('ms',0))}", tokens_str, f"{res.get('kb',0.0):.2f}", detail_display), tags=((tag,) if tag else ()))
                if call_id:
                    self._audit_call_items[call_id] = item
                self._audit_row_data[item]=res
                self._audit_done += 1
                _update_audit_status()
            self.root.after(0, _ins)
        def stop_flag(): return self._audit_stop
        def run():
            out = c.audit_tools(per_call_timeout=per_to, parallelism=max(1,parallel), stop_flag=stop_flag, on_progress=on_progress, validate_outputs=True, throttle_seconds=throttle_seconds)
            if not hasattr(self, "last_report") or self.last_report is None:
                self.last_report={"summary":[],"details":{},"log":"\n".join(self.mem_log),"meta":{"url":self.url.get().strip(),"tls_mode":self.tls_mode.get(),"time":time.strftime("%Y-%m-%d %H:%M:%S"),"protocol_version":c.proto,"session_id":c.sid}}
            self.last_report["details"]["audit"]=out
            def _finalize():
                total = self._audit_total or len(out)
                self._audit_total = total
                self._audit_done = len(out)
                self._audit_running = 0
                if total:
                    self.audit_progress.set(f"{self._audit_done}/{total} done \u00b7 Finished")
                else:
                    self.audit_progress.set(f"Finished: {len(out)} tools processed")
            self.root.after(0, _finalize)
        threading.Thread(target=run, daemon=True).start()

    def _clear_audit(self):
        self._audit_row_data = {}
        self._audit_timelines = {}
        self._audit_call_items = {}
        self.audit.delete(*self.audit.get_children())
        self._audit_total = 0
        self._audit_done = 0
        self._audit_running = 0
        self.audit_progress.set("")
        try:
            self.audit.configure(cursor="")
        except Exception:
            pass

    def _open_token_manager(self):
        if tk is None:
            self._sink("Authentifizierungsmanager nicht verf\u00fcgbar (Tkinter fehlt).")
            return
        existing = getattr(self, "_token_manager", None)
        if existing and str(existing) and existing.winfo_exists():
            try:
                existing.lift()
                existing.focus_force()
            except Exception:
                pass
            return
        self._token_manager = TokenManagerDialog(self)

    def _open_sse_monitor(self):
        if tk is None:
            self._sink("SSE-Monitor nicht verf\u00fcgbar (Tkinter fehlt).")
            return
        existing = getattr(self, "_sse_monitor", None)
        if existing and str(existing) and existing.winfo_exists():
            try:
                existing.lift()
                existing.focus_force()
            except Exception:
                pass
            return
        self._sse_monitor = SSEMonitorDialog(self)

    def _open_context_layers(self):
        if tk is None:
            self._sink("Kontext-Navigator nicht verf\u00fcgbar (Tkinter fehlt).")
            return
        existing = getattr(self, "_context_layers", None)
        if existing and str(existing) and existing.winfo_exists():
            try:
                existing.lift()
                existing.focus_force()
            except Exception:
                pass
            return
        self._sink("Kontext-Ebenen werden gesammelt ...")
        def worker():
            data = self._collect_context_layers()
            self.root.after(0, lambda: self._show_context_layers(data))
        threading.Thread(target=worker, daemon=True).start()

    def _open_test_lab(self):
        if tk is None:
            self._sink("Testlabor nicht verf\u00fcgbar (Tkinter fehlt).")
            return
        existing = getattr(self, "_test_lab", None)
        if existing and str(existing) and existing.winfo_exists():
            try:
                existing.lift()
                existing.focus_force()
            except Exception:
                pass
            return
        self._test_lab = TestLabDialog(self)

    def _on_audit_tree_click(self, event):
        region = self.audit.identify("region", event.x, event.y)
        if region != "cell":
            return
        column = self.audit.identify_column(event.x)
        if column != "#6":
            return
        item = self.audit.identify_row(event.y)
        if not item:
            return
        self._open_audit_detail(item)

    def _on_audit_motion(self, event):
        region = self.audit.identify("region", event.x, event.y)
        column = self.audit.identify_column(event.x)
        if region == "cell" and column == "#6":
            self.audit.configure(cursor="hand2")
        else:
            self.audit.configure(cursor="")

    def _open_audit_detail(self, item):
        data = self._audit_row_data.get(item)
        if not data:
            return
        top = tk.Toplevel(self.root)
        top.title(f"Audit detail - {data.get('tool','')}")
        try:
            top.transient(self.root)
        except Exception:
            pass
        txt = ScrolledText(top, width=100, height=34)
        txt.pack(fill="both", expand=True)
        txt.configure(font=("Consolas", 10))
        def _write_block(title, payload):
            txt.insert("end", f"{title}\n", ("section",))
            if isinstance(payload, (dict, list)):
                txt.insert("end", json.dumps(payload, ensure_ascii=False, indent=2))
            elif payload is None:
                txt.insert("end", "(none)")
            else:
                txt.insert("end", str(payload))
            txt.insert("end", "\n\n")
        txt.tag_config("section", font=("Segoe UI", 10, "bold"))
        _write_block("Tool", data.get("tool"))
        _write_block("Status", data.get("status"))
        _write_block("Detail", data.get("detail"))
        _write_block("Timing (ms)", data.get("ms"))
        _write_block("Tokens", data.get("tokens"))
        _write_block("Kilobytes", data.get("kb"))
        _write_block("Arguments", data.get("args"))
        _write_block("HTTP status", data.get("http"))
        _write_block("HTTP headers", data.get("http_headers"))
        _write_block("Request payload", data.get("request"))
        _write_block("Response payload", data.get("response"))
        timeline = data.get("timeline") or []
        if timeline:
            lines=[]
            for ev in timeline:
                ts = ev.get("ts")
                when = time.strftime("%H:%M:%S", time.localtime(ts)) if isinstance(ts, (int, float)) else "?"
                phase = ev.get("phase") or ""
                status = ev.get("status") or ""
                ms = ev.get("ms")
                extra = f" \u00b7 {ms} ms" if isinstance(ms, (int, float)) else ""
                parts = [p for p in (when, phase, f"Status: {status}" if status else "") if p]
                lines.append(" | ".join(parts) + extra)
            _write_block("Ablauf", "\n".join(lines))
        txt.config(state="disabled")
        txt.see("1.0")
        ttk.Button(top, text="Close", command=top.destroy).pack(pady=6)

    def _open_tree(self):
        c=self._build_client(reset=False)
        data = c.last_body if c and c.last_body is not None else {}
        top=tk.Toplevel(self.root); top.title("Last JSON result")
        tv=ttk.Treeview(top, columns=("value",), show="tree headings")
        tv.heading("value", text="Value"); tv.pack(fill="both", expand=True)
        def add_node(parent, key, val):
            label=str(key)
            if isinstance(val, dict):
                nid=tv.insert(parent, "end", text=label, values=("",))
                for k,v in val.items(): add_node(nid, k, v)
            elif isinstance(val, list):
                nid=tv.insert(parent, "end", text=f"{label} []", values=("",))
                for i,v in enumerate(val): add_node(nid, i, v)
            else:
                tv.insert(parent, "end", text=label, values=(str(val),))
        add_node("", "root", data)
        for n in tv.get_children(): tv.item(n, open=True)
        btns = ttk.Frame(top)
        btns.pack(fill="x", pady=(8,8), padx=8)
        ttk.Button(btns, text="Export as JSON...", command=lambda: self._export_last_json(data)).pack(side="right")

    def _export_last_json(self, payload):
        if filedialog is None:
            self._sink("JSON export not available (Tkinter fehlt).")
            return
        path = filedialog.asksaveasfilename(
            initialfile="mcp_last_response.json",
            defaultextension=".json",
            filetypes=[("JSON", "*.json"), ("All files", "*.*")]
        )
        if not path:
            return
        def _fallback(obj):
            return repr(obj)
        try:
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, ensure_ascii=False, indent=2, default=_fallback)
        except Exception as exc:
            self._sink(f"Export failed: {exc}")
        else:
            self._sink(f"JSON export saved to {path}")

    def _show_curl(self):
        c=self._build_client(reset=False)
        s_bash=c.last_curl(redact=True, windows=False) if c else ""
        s_win=c.last_curl(redact=True, windows=True) if c else ""
        top=tk.Toplevel(self.root); top.title("cURL (last request)")
        txt=ScrolledText(top, height=20); txt.pack(fill="both", expand=True)
        txt.insert("1.0", "# Bash\n"+s_bash+"\n\n# Windows CMD/PowerShell\n"+s_win); txt.see("1.0")

    def _show_request_details(self):
        c=self._build_client(reset=False)
        http = getattr(c, "last_http", None) if c else None
        if not http:
            if messagebox:
                messagebox.showinfo("Request-Details", "Noch keine HTTP-Anfrage vorhanden.")
            return
        top = tk.Toplevel(self.root)
        top.title("Request-Details")
        try:
            top.transient(self.root)
        except Exception:
            pass
        txt = ScrolledText(top, width=80, height=28)
        txt.pack(fill="both", expand=True)
        txt.configure(font=("Consolas", 10))
        def write(block_title, content):
            txt.insert("end", f"{block_title}\n", ("section",))
            if isinstance(content, dict):
                txt.insert("end", json.dumps(content, ensure_ascii=False, indent=2))
            else:
                txt.insert("end", content if content else " - ")
            txt.insert("end", "\n\n")
        txt.tag_config("section", font=("Segoe UI", 10, "bold"))
        method = http.get("method", "GET")
        url = http.get("url", "")
        parsed = urllib.parse.urlparse(url)
        query = urllib.parse.parse_qs(parsed.query)
        write("Methode & URL", f"{method} {url}")
        write("Host", parsed.netloc or " - ")
        write("Pfad", parsed.path or "/")
        write("Query-Parameter", {k: v for k,v in query.items()} or "keine")
        headers = http.get("headers", {})
        write("Headers", headers or "keine")
        extra = getattr(self, "_auth_extra", {}) or {}
        write("Aktuelle Auth-Header", extra or "keine")
        body = http.get("body")
        if body is not None:
            write("Body", body)
        ttk.Button(top, text="Schlie\u00dfen", command=top.destroy).pack(pady=6)
        txt.config(state="disabled")

    def _save_httpfile(self):
        c=self._build_client(reset=False)
        if not c or not c.last_http:
            if messagebox: messagebox.showinfo("Save .http", "Kein letzter Request gefunden.")
            return
        h=c.last_http
        p=filedialog.asksaveasfilename(defaultextension=".http", filetypes=[("HTTP file","*.http"),("Text","*.txt")], initialfile="last_request.http")
        if not p: return
        lines=[f"{h['method']} {h['url']}"]
        for k,v in h.get("headers",{}).items():
            if k.lower()=="authorization": v="***"
            lines.append(f"{k}: {v}")
        lines.append("")
        if h.get("body") is not None:
            lines.append(json.dumps(h["body"], indent=2, ensure_ascii=False))
        with open(p, "w", encoding="utf-8") as f: f.write("\n".join(lines))
        if messagebox: messagebox.showinfo("Save .http", f"Gespeichert: {p}")

    def _save_report(self):
        if not self.last_report:
            c=self._build_client(reset=False)
            snap={"summary":[],"details":{},"meta":{"url":self.url.get().strip(),"tls_mode":self.tls_mode.get(),"time":time.strftime("%Y-%m-%d %H:%M:%S"),"protocol_version":getattr(c,'proto',''),"session_id":getattr(c,'sid','')},"log":"\n".join(self.mem_log)}
        else:
            snap=self.last_report
        default = f"mcp_report_{int(time.time())}.zip"
        p=filedialog.asksaveasfilename(initialfile=default, defaultextension=".zip", filetypes=[("ZIP","*.zip")])
        if not p: return
        md_lines = [f"# MCP Overall Report", f"- URL: {snap['meta']['url']}", f"- Time: {snap['meta']['time']}", f"- TLS Mode: {snap['meta']['tls_mode']}", f"- Protocol Version: {snap['meta'].get('protocol_version','')}", f"- Session ID: {snap['meta'].get('session_id','')}", "", "## Summary", "| Level | Check | Status | Detail |", "|---|---|---|---|"]
        for it in snap.get("summary", []):
            md_lines.append(f"| {it.get('level','')} | {it.get('check','')} | {it.get('status','')} | {it.get('detail','')} |")
        md = "\n".join(md_lines)
        c=self._build_client(reset=False)
        last_http = getattr(c, "last_http", None); last_http_text = ""
        if last_http:
            lines=[f"{last_http['method']} {last_http['url']}"]
            for k,v in last_http.get("headers",{}).items():
                if k.lower()=="authorization": v="***"
                lines.append(f"{k}: {v}")
            lines.append("")
            if last_http.get("body") is not None:
                lines.append(json.dumps(last_http["body"], indent=2, ensure_ascii=False))
            last_http_text="\n".join(lines)
        with zipfile.ZipFile(p, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("report.json", json.dumps(snap, ensure_ascii=False, indent=2))
            z.writestr("report.md", md)
            z.writestr("log.txt", snap.get("log",""))
            if last_http_text: z.writestr("last_request.http", last_http_text)
        if messagebox: messagebox.showinfo("Report", f"Gespeichert: {p}")

    def _run_action(self, action):
        c=self._build_client(reset=False)
        try:
            if action=="init":
                c.initialize()
            elif action=="initialized":
                c.initialized()
            elif action=="tools_list":
                c.list_tools()
            elif action=="resources_list":
                c.list_resources()
            elif action=="prompts_list":
                c.list_prompts()
            elif action=="prompts_get_first":
                obj,_=c.list_prompts()
                items=(obj.get("result") or {}).get("prompts") or []
                if not items: self._sink("WARN: keine Prompts."); return
                name=items[0].get("name"); c.call("prompts/get", {"name": name, "arguments": {}}, sse_max_seconds=10)
            elif action=="resources_read_first":
                obj,_=c.list_resources()
                items=(obj.get("result") or {}).get("resources") or []
                if not items: self._sink("WARN: keine Resources."); return
                uri=items[0].get("uri"); c.call("resources/read", {"uris": [uri]}, sse_max_seconds=10)
            elif action=="tools_call_first":
                obj,_=c.list_tools()
                items=(obj.get("result") or {}).get("tools") or []
                if not items: self._sink("WARN: keine Tools."); return
                name=items[0].get("name"); c.call("tools/call", {"name": name, "arguments": {}}, sse_max_seconds=15)
            elif action=="audit_tools":
                self._run_audit()
            elif action=="get_sse":
                c.get_sse(3)
            elif action=="delete_session":
                c.delete_session()
        except Exception as e:
            self._sink(f"Aktion {action} Fehler: {e}")

# --------------- First-run wizard ---------------
class TokenManagerDialog(tk.Toplevel):
    def __init__(self, gui):
        super().__init__(gui.root)
        self.gui = gui
        self.title("Authentifizierungsmanager")
        self._closing = False
        try:
            self.transient(gui.root)
        except Exception:
            pass
        self.resizable(False, False)
        self.mode = tk.StringVar(value=gui.auth_mode.get())
        self.token = tk.StringVar(value=gui.auth_token.get())
        self.header = tk.StringVar(value=gui.auth_header.get())
        self.enabled = tk.BooleanVar(value=bool(gui.auth_enabled.get() and gui.auth_mode.get() != "None"))
        self._show_token = tk.BooleanVar(value=False)
        body = ttk.Frame(self, padding=12)
        body.pack(fill="both", expand=True)
        body.columnconfigure(1, weight=1)

        ttk.Label(body, text="Auth-Modus:").grid(row=0, column=0, sticky="w")
        self.mode_combo = ttk.Combobox(body, textvariable=self.mode, state="readonly", values=["None","Bearer","Custom header"], width=20)
        self.mode_combo.grid(row=0, column=1, sticky="we", padx=(8,0))
        self.mode_combo.bind("<<ComboboxSelected>>", self._update_states)

        ttk.Label(body, text="Token:").grid(row=1, column=0, sticky="w", pady=(10,0))
        self.token_entry = ttk.Entry(body, textvariable=self.token, show="*")
        self.token_entry.grid(row=1, column=1, sticky="we", padx=(8,0), pady=(10,0))

        ttk.Checkbutton(body, text="Token anzeigen", variable=self._show_token, command=self._toggle_show).grid(row=2, column=1, sticky="w", padx=(8,0))

        ttk.Label(body, text="Header-Name:").grid(row=3, column=0, sticky="w", pady=(10,0))
        self.header_entry = ttk.Entry(body, textvariable=self.header)
        self.header_entry.grid(row=3, column=1, sticky="we", padx=(8,0), pady=(10,0))

        self.enabled_check = ttk.Checkbutton(body, text="Aktiviert", variable=self.enabled)
        self.enabled_check.grid(row=4, column=1, sticky="w", padx=(8,0), pady=(10,0))

        ttk.Label(body, text="Hinweis: Einstellungen werden beim Schlie\u00dfen \u00fcbernommen.", foreground="#555").grid(row=5, column=0, columnspan=2, sticky="w", pady=(12,0))

        btns = ttk.Frame(self, padding=(12,0,12,12))
        btns.pack(fill="x")
        ttk.Button(btns, text="Cancel", command=self._cancel).pack(side="right")
        ttk.Button(btns, text="Save & Apply", command=self._apply_and_close).pack(side="right", padx=(0,8))

        self.protocol("WM_DELETE_WINDOW", self._apply_and_close)
        self.bind("<Return>", lambda e: self._apply_and_close())
        self.bind("<Escape>", lambda e: self._cancel())
        self.mode_combo.focus_set()
        self._update_states()
        try:
            self.grab_set()
        except Exception:
            pass

    def _toggle_show(self):
        show = "" if self._show_token.get() else "*"
        try:
            self.token_entry.config(show=show)
        except Exception:
            pass

    def _update_states(self, *_):
        mode = self.mode.get()
        token_state = "normal" if mode in ("Bearer", "Custom header") else "disabled"
        header_state = "normal" if mode == "Custom header" else "disabled"
        try:
            self.token_entry.config(state=token_state)
        except Exception:
            pass
        try:
            self.header_entry.config(state=header_state)
        except Exception:
            pass
        if mode == "Bearer" and not self.header.get().strip():
            self.header.set("Authorization")
        if mode == "None":
            self.enabled.set(False)
            try:
                self.enabled_check.state(["disabled"])
            except Exception:
                pass
        else:
            try:
                self.enabled_check.state(["!disabled"])
            except Exception:
                pass

    def _commit_to_gui(self):
        gui = self.gui
        mode = self.mode.get()
        gui.auth_mode.set(mode)
        token_value = self.token.get().strip()
        gui.auth_token.set(token_value)
        header_val = self.header.get().strip() or ("Authorization" if mode != "Custom header" else "X-Api-Key")
        gui.auth_header.set(header_val)
        enabled = bool(self.enabled.get())
        if enabled and (mode == "None" or not token_value):
            gui._sink("Auth: Token oder Modus fehlt. Auth wurde deaktiviert.")
            enabled = False
        gui.auth_enabled.set(bool(enabled))
        gui._apply_auth()
        gui._save_settings()

    def _apply_and_close(self):
        if self._closing:
            return
        self._closing = True
        try:
            self._commit_to_gui()
        except Exception:
            pass
        try:
            self.gui._token_manager = None
        except Exception:
            pass
        try:
            self.grab_release()
        except Exception:
            pass
        self.destroy()

class ProgressDialog(tk.Toplevel):
    def __init__(self, parent, title, message="", cancelable=False, on_cancel=None, modal=True):
        super().__init__(parent)
        self.title(title)
        self.resizable(False, False)
        self._on_cancel = on_cancel
        self._cancelled = False
        self._modal = bool(modal)

        self._label = ttk.Label(self, text=message or "Bitte warten...", width=40)
        self._label.pack(padx=16, pady=(12,8))
        pb = ttk.Progressbar(self, mode="indeterminate", length=220)
        pb.pack(padx=16, pady=(0,8))
        pb.start(10)

        if cancelable:
            btn_frame = ttk.Frame(self)
            btn_frame.pack(padx=16, pady=(0,12))
            self._cancel_btn = ttk.Button(btn_frame, text="Abbrechen", command=self._handle_cancel)
            self._cancel_btn.pack()
        else:
            ttk.Frame(self, height=4).pack()

        self.protocol("WM_DELETE_WINDOW", self._handle_cancel if cancelable else (lambda: None))
        try:
            self.transient(parent)
        except Exception:
            pass
        if self._modal:
            try:
                self.grab_set()
            except Exception:
                self._modal = False
        self.update_idletasks()
        self._center_on_parent(parent)

    def _center_on_parent(self, parent):
        try:
            self.update_idletasks()
            parent_x = parent.winfo_x()
            parent_y = parent.winfo_y()
            parent_width = parent.winfo_width()
            parent_height = parent.winfo_height()
            dialog_width = self.winfo_width()
            dialog_height = self.winfo_height()
            x = parent_x + (parent_width - dialog_width) // 2
            y = parent_y + (parent_height - dialog_height) // 2
            x = max(0, x)
            y = max(0, y)
            self.geometry(f"+{x}+{y}")
        except Exception:
            pass

    def _handle_cancel(self):
        if not self._cancelled:
            self._cancelled = True
            if self._on_cancel:
                try:
                    self._on_cancel()
                except Exception:
                    pass
            if hasattr(self, '_cancel_btn'):
                try:
                    self._cancel_btn.configure(state="disabled")
                    self._label.configure(text="Abbruch wird verarbeitet...")
                except Exception:
                    pass

    def update_message(self, message):
        try:
            if not self._cancelled:
                self._label.configure(text=message)
        except Exception:
            pass

    def close(self):
        if self._modal:
            try:
                self.grab_release()
            except Exception:
                pass
        try:
            self.destroy()
        except Exception:
            pass


class SummaryDetailDialog(tk.Toplevel):
    def __init__(self, gui, check_label, key, data):
        super().__init__(gui.root)
        self.gui = gui
        self.title(f"{check_label} - Details")
        self.minsize(640, 480)
        try:
            self.transient(gui.root)
        except Exception:
            pass
        container = ttk.Frame(self, padding=10)
        container.pack(fill="both", expand=True)

        ttk.Label(container, text=check_label, font=("Segoe UI", 11, "bold")).pack(anchor="w")
        ttk.Label(container, text=key, foreground="#555").pack(anchor="w", pady=(0,6))

        ttk.Label(container, text="Request").pack(anchor="w")
        req_box = ScrolledText(container, height=12)
        req_box.pack(fill="both", expand=True)
        req_box.insert("1.0", self._format_request(data.get("request")))
        req_box.configure(state="disabled")

        ttk.Label(container, text="Response").pack(anchor="w", pady=(10,0))
        resp_box = ScrolledText(container, height=14)
        resp_box.pack(fill="both", expand=True)
        resp_box.insert("1.0", self._format_response(data))
        resp_box.configure(state="disabled")

        btn_frame = ttk.Frame(container)
        btn_frame.pack(fill="x", pady=(10,0))
        ttk.Button(btn_frame, text="Schliessen", command=self.destroy).pack(side="right")

        try:
            self.focus_force()
        except Exception:
            pass

    @staticmethod
    def _format_request(request):
        if not isinstance(request, dict):
            return "Keine Request-Daten vorhanden."
        lines = []
        method = request.get("method") or ""
        url = request.get("url") or ""
        if method or url:
            lines.append(f"{method} {url}".strip())
        headers = request.get("headers") or {}
        if headers:
            lines.append("")
            lines.append("Headers:")
            for k, v in headers.items():
                lines.append(f"  {k}: {v}")
        lines.extend(SummaryDetailDialog._format_body_block("Body", request.get("body")))
        return "\n".join(lines) if lines else "Keine Request-Daten vorhanden."

    @staticmethod
    def _format_response(data):
        if not isinstance(data, dict):
            return "Keine Response-Daten vorhanden."
        lines = []
        status = data.get("http")
        if status is not None:
            lines.append(f"HTTP {status}")
        headers = data.get("headers") or {}
        if headers:
            lines.append("")
            lines.append("Headers:")
            for k, v in headers.items():
                lines.append(f"  {k}: {v}")
        lines.extend(SummaryDetailDialog._format_body_block("Body", data.get("body")))
        fallback = data.get("fallback")
        if isinstance(fallback, dict):
            lines.append("")
            lines.append("Fallback Probe:")
            fb_status = fallback.get("http")
            if fb_status is not None:
                lines.append(f"  HTTP {fb_status}")
            fb_headers = fallback.get("headers") or {}
            if fb_headers:
                lines.append("  Headers:")
                for k, v in fb_headers.items():
                    lines.append(f"    {k}: {v}")
            lines.extend(SummaryDetailDialog._format_body_block("  Body", fallback.get("body")))
        return "\n".join(lines) if lines else "Keine Response-Daten vorhanden."

    @staticmethod
    def _format_body_block(label, body):
        if body is None:
            return []
        lines = ["", f"{label}:"]
        if isinstance(body, str):
            lines.append(body)
        else:
            try:
                lines.append(json.dumps(body, ensure_ascii=False, indent=2))
            except Exception:
                lines.append(repr(body))
        return lines


class ContextNavigatorDialog(tk.Toplevel):
    def __init__(self, gui, data, title="Kontext-Navigator"):
        super().__init__(gui.root)
        self.gui=gui
        self.data=data
        self.title(title)
        self.geometry("820x520")
        try:
            self.transient(gui.root)
            self.grab_set()
        except Exception:
            pass
        container=ttk.Frame(self, padding=10)
        container.pack(fill="both", expand=True)
        container.columnconfigure(1, weight=1)
        container.rowconfigure(0, weight=1)

        tree_frame=ttk.Frame(container)
        tree_frame.grid(row=0, column=0, sticky="ns", padx=(0,10))
        tree_scroll=ttk.Scrollbar(tree_frame, orient="vertical")
        tree_scroll.pack(side="right", fill="y")
        self.tree=ttk.Treeview(tree_frame, show="tree", yscrollcommand=tree_scroll.set)
        self.tree.pack(side="left", fill="y")
        tree_scroll.config(command=self.tree.yview)
        self.tree.bind("<<TreeviewSelect>>", self._on_select)

        right=ttk.Frame(container)
        right.grid(row=0, column=1, sticky="nsew")
        right.columnconfigure(0, weight=1)
        right.rowconfigure(0, weight=1)

        self.detail=ScrolledText(right, width=60, height=20)
        self.detail.grid(row=0, column=0, sticky="nsew")
        self.detail.configure(font=("Consolas", 10), state="disabled")
        btns=ttk.Frame(right)
        btns.grid(row=1, column=0, sticky="e", pady=(8,0))
        ttk.Button(btns, text="Export JSON...", command=self._export_json).pack(side="right")
        ttk.Button(btns, text="Schliessen", command=self._close).pack(side="right", padx=(0,6))
        self.protocol("WM_DELETE_WINDOW", self._close)

        self.sections=data.get("layers", [])
        self._populate_tree()

    def _populate_tree(self):
        for idx, section in enumerate(self.sections):
            parent=self.tree.insert("", "end", text=section.get("title", f"Ebene {idx+1}"), open=True, values=("section",idx,-1))
            for item_idx, item in enumerate(section.get("items", [])):
                label=item.get("label") or f"Eintrag {item_idx+1}"
                self.tree.insert(parent, "end", text=label, values=("item", idx, item_idx))

    def _on_select(self, event):
        selection=self.tree.selection()
        if not selection:
            return
        kind, sec_idx, item_idx = self.tree.item(selection[0], "values")
        if kind != "item":
            return
        try:
            sec_idx=int(sec_idx)
            item_idx=int(item_idx)
        except Exception:
            return
        section=self.sections[sec_idx]
        item=section.get("items", [])[item_idx]
        details=item.get("details")
        self.detail.configure(state="normal")
        self.detail.delete("1.0","end")
        if isinstance(details, (dict, list)):
            self.detail.insert("end", json.dumps(details, ensure_ascii=False, indent=2))
        else:
            self.detail.insert("end", details or "keine Angaben")
        self.detail.configure(state="disabled")

    def _export_json(self):
        if filedialog is None:
            self.gui._sink("JSON export not available (Tkinter fehlt).")
            return
        path=filedialog.asksaveasfilename(
            initialfile="mcp_context_layers.json",
            defaultextension=".json",
            filetypes=[("JSON", "*.json"), ("All files", "*.*")]
        )
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(self.data, fh, ensure_ascii=False, indent=2)
        except Exception as exc:
            self.gui._sink(f"Kontext-Export fehlgeschlagen: {exc}")
        else:
            self.gui._sink(f"Kontext-Export gespeichert: {path}")

    def _close(self):
        try:
            self.gui._context_layers = None
        except Exception:
            pass
        self.destroy()


class SSEMonitorDialog(tk.Toplevel):
    def __init__(self, gui):
        super().__init__(gui.root)
        self.gui = gui
        self.title("Live-Verbindung (SSE)")
        self._thread = None
        self._stop_event = threading.Event()
        self._response = None
        self.status = tk.StringVar(value="Bereit")
        self.last_event = tk.StringVar(value=" - ")
        self.event_count = tk.IntVar(value=0)
        self._status_label=None
        self._last_event_ts=None
        self._heartbeat_job=None

        frame = ttk.Frame(self, padding=12)
        frame.pack(fill="both", expand=True)
        info = ttk.Frame(frame)
        info.pack(fill="x")
        ttk.Label(info, text="Status:").grid(row=0, column=0, sticky="w")
        self._status_label = ttk.Label(info, textvariable=self.status)
        self._status_label.grid(row=0, column=1, sticky="w", padx=(4,0))
        ttk.Label(info, text="Letztes Ereignis:").grid(row=1, column=0, sticky="w")
        ttk.Label(info, textvariable=self.last_event).grid(row=1, column=1, sticky="w", padx=(4,0))
        ttk.Label(info, text="Anzahl Events:").grid(row=2, column=0, sticky="w")
        ttk.Label(info, textvariable=self.event_count).grid(row=2, column=1, sticky="w", padx=(4,0))

        self.log = ScrolledText(frame, height=18, width=80)
        self.log.pack(fill="both", expand=True, pady=(10,0))
        self.log.configure(state="disabled", font=("Consolas", 10))

        buttons = ttk.Frame(frame)
        buttons.pack(fill="x", pady=(10,0))
        self.start_btn = ttk.Button(buttons, text="Starten", command=self._start_monitor)
        self.start_btn.pack(side="left")
        self.stop_btn = ttk.Button(buttons, text="Stoppen", command=self._stop_monitor, state="disabled")
        self.stop_btn.pack(side="left", padx=(6,0))
        ttk.Button(buttons, text="Schlie\u00dfen", command=self._close).pack(side="right")

        self.protocol("WM_DELETE_WINDOW", self._close)
        try:
            self.transient(gui.root)
            self.grab_set()
        except Exception:
            pass
        self._heartbeat_loop()

    def _set_running(self, running: bool):
        try:
            if running:
                self.start_btn.config(state="disabled")
                self.stop_btn.config(state="normal")
            else:
                self.start_btn.config(state="normal")
                self.stop_btn.config(state="disabled")
        except Exception:
            pass

    def _append_log(self, text):
        self.log.configure(state="normal")
        self.log.insert("end", text + "\n")
        self.log.see("end")
        self.log.configure(state="disabled")

    def _set_status(self, text, color=None):
        self.status.set(text)
        if self._status_label is not None:
            try:
                if color:
                    self._status_label.configure(foreground=color)
                else:
                    self._status_label.configure(foreground="")
            except Exception:
                pass

    def _post(self, func, *args):
        try:
            self.after(0, lambda: func(*args))
        except Exception:
            pass

    def _heartbeat_loop(self):
        try:
            if self._last_event_ts:
                diff = time.time() - self._last_event_ts
                if diff >= 0:
                    color = "#C27C00" if diff > 5 else ""
                    self._set_status(f"Verbunden - letztes Ereignis vor {diff:.1f}s", color)
            elif self._thread and self._thread.is_alive():
                self._set_status("Verbunden - noch keine Ereignisse", "#C27C00")
        finally:
            self._heartbeat_job = self.after(1000, self._heartbeat_loop)

    def _start_monitor(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self.event_count.set(0)
        self.last_event.set(" - ")
        self._last_event_ts=None
        self._set_status("Verbinde ...")
        self.log.configure(state="normal")
        self.log.delete("1.0", "end")
        self.log.configure(state="disabled")
        self._set_running(True)
        self._thread = threading.Thread(target=self._run_monitor, daemon=True)
        self._thread.start()

    def _stop_monitor(self):
        if not self._thread or not self._thread.is_alive():
            return
        self._stop_event.set()
        self._set_status("Beende ...")

    def _close(self):
        self._stop_monitor()
        try:
            if self._thread and self._thread.is_alive():
                self._thread.join(timeout=1.0)
        except Exception:
            pass
        if self._heartbeat_job is not None:
            try:
                self.after_cancel(self._heartbeat_job)
            except Exception:
                pass
        self._heartbeat_job=None
        try:
            self.gui._sse_monitor = None
        except Exception:
            pass
        try:
            self.grab_release()
        except Exception:
            pass
        self.destroy()

    def _run_monitor(self):
        client = None
        try:
            client = self.gui._create_client(silent=True)
            start = time.monotonic()
            client.initialize()
            client.initialized()
            init_latency = int((time.monotonic() - start) * 1000)
            self._post(self._set_status, f"Handshake OK ({init_latency} ms)")
            self._last_event_ts = time.time()
            headers = client._h_get()
            resp = requests.get(client.url, headers=headers, stream=True, verify=client.verify, timeout=client.timeout)
            self._response = resp
            ct = (resp.headers.get("Content-Type") or "").lower()
            if "text/event-stream" not in ct:
                self._post(self._set_status, f"Kein Event-Stream (HTTP {resp.status_code})", "#B00020")
                return
            self._post(self._set_status, "Verbunden - lausche auf Ereignisse ...")
            sse = SSEClient(resp)
            for ev in sse.events():
                if self._stop_event.is_set():
                    break
                now = time.strftime("%H:%M:%S")
                data = ev.data.strip()
                try:
                    parsed = json.loads(data)
                    preview = json.dumps(parsed, ensure_ascii=False)
                    valid = True
                except Exception:
                    preview = data
                    valid = False
                preview = preview[:300]
                self._post(self._record_event, now, ev.event or "message", preview, valid)
            self._post(self._set_status, "Verbindung beendet")
        except Exception as exc:
            self._post(self._set_status, f"Fehler: {exc}", "#B00020")
            self._post(self._append_log, f"\u26a0 {exc}")
        finally:
            self._last_event_ts = None
            if self._response is not None:
                try:
                    self._response.close()
                except Exception:
                    pass
            if client is not None:
                try:
                    if getattr(client, "sid", ""):
                        client.delete_session()
                except Exception:
                    pass
            self._post(self._set_running, False)

    def _record_event(self, timestamp, event_name, preview, valid=True):
        self.event_count.set(self.event_count.get() + 1)
        self.last_event.set(f"{timestamp} \u00b7 {event_name}")
        self._last_event_ts = time.time()
        if valid:
            self._append_log(f"[{timestamp}] {event_name}: {preview}")
        else:
            self._append_log(f"[{timestamp}] {event_name}: \u26a0 Ung\u00fcltiges JSON -> {preview}")
        try:
            self.gui._append_event_line(f"[SSE] {timestamp} \u00b7 {event_name}: {preview}")
        except Exception:
            pass


class TestLabDialog(tk.Toplevel):
    def __init__(self, gui):
        super().__init__(gui.root)
        self.gui = gui
        self.title("Testlabor")
        self._thread=None
        self._closing=False
        frame=ttk.Frame(self, padding=12)
        frame.pack(fill="both", expand=True)
        ttk.Label(frame, text="Schnelltests f\u00fcr typische Fehlerszenarien").pack(anchor="w")
        ttk.Label(frame, text="W\u00e4hle einen Test. Ergebnisse erscheinen unten und werden zus\u00e4tzlich im Log aufgezeichnet.", foreground="#555").pack(anchor="w", pady=(0,8))

        btns=ttk.Frame(frame)
        btns.pack(fill="x", pady=(0,8))
        ttk.Button(btns, text="Ung\u00fcltige Argumente senden", command=lambda: self._start("invalid_args")).pack(side="left")
        ttk.Button(btns, text="Unbekannte Methode testen", command=lambda: self._start("unknown_method")).pack(side="left", padx=(6,0))
        ttk.Button(btns, text="SSE nach 2s abbrechen", command=lambda: self._start("sse_abort")).pack(side="left", padx=(6,0))
        btns2=ttk.Frame(frame)
        btns2.pack(fill="x", pady=(0,8))
        ttk.Button(btns2, text="Tool mit Mini-Timeout", command=lambda: self._start("tool_timeout")).pack(side="left")
        ttk.Button(btns2, text="Gro\u00dfe Payload schicken", command=lambda: self._start("large_payload")).pack(side="left", padx=(6,0))
        ttk.Button(btns2, text="Initialize ohne Accept", command=lambda: self._start("missing_accept")).pack(side="left", padx=(6,0))

        self.output=ScrolledText(frame, height=14, width=80)
        self.output.pack(fill="both", expand=True)
        self.output.configure(state="disabled", font=("Consolas", 10))

        ttk.Button(frame, text="Schlie\u00dfen", command=self._close).pack(pady=(8,0))
        self.protocol("WM_DELETE_WINDOW", self._close)
        try:
            self.transient(gui.root)
            self.grab_set()
        except Exception:
            pass

    def _append(self, text):
        self.output.configure(state="normal")
        self.output.insert("end", text+"\n")
        self.output.see("end")
        self.output.configure(state="disabled")

    def _post(self, func, *args):
        try:
            self.after(0, lambda: func(*args))
        except Exception:
            pass

    def _start(self, action):
        if self._thread and self._thread.is_alive():
            self._append("Bitte warte, aktueller Test l\u00e4uft noch.")
            return
        self._append(f"-> Test gestartet: {action}")
        self._thread=threading.Thread(target=self._run_action, args=(action,), daemon=True)
        self._thread.start()

    def _run_action(self, action):
        try:
            if action=="invalid_args":
                self._test_invalid_args()
            elif action=="unknown_method":
                self._test_unknown_method()
            elif action=="sse_abort":
                self._test_sse_abort()
            elif action=="tool_timeout":
                self._test_tool_timeout()
            elif action=="large_payload":
                self._test_large_payload()
            elif action=="missing_accept":
                self._test_missing_accept()
            self._post(self._append, f"Test abgeschlossen: {action}")
        finally:
            self._thread=None

    def _test_invalid_args(self):
        client=self.gui._create_client(silent=True)
        try:
            client.initialize(); client.initialized()
            tools = (client.list_tools()[0].get("result") or {}).get("tools") or []
            if not tools:
                self._post(self._append, "\u26a0 Keine Tools vorhanden - Test \u00fcbersprungen.")
                return
            name = tools[0].get("name")
            self._post(self._append, f"Teste Tool '{name}' mit leeren Argumenten...")
            _, resp = client.call("tools/call", {"name": name, "arguments": {}}, stream=False, sse_max_seconds=5)
            http = getattr(resp, "status_code", "n/a")
            self._post(self._append, f"Ergebnis HTTP {http}. Details siehe Log.")
        except Exception as exc:
            self._post(self._append, f"\u26a0 Fehler: {exc}")
        finally:
            try:
                if getattr(client, "sid", ""):
                    client.delete_session()
            except Exception:
                pass

    def _test_unknown_method(self):
        client=self.gui._create_client(silent=True)
        try:
            client.initialize(); client.initialized()
            self._post(self._append, "Frage unbekannte Methode an (sollte Fehler liefern)...")
            obj, resp = client.call("rpc/does_not_exist", {}, stream=False, accept_json_only=True)
            http = getattr(resp, "status_code", "n/a")
            self._post(self._append, f"Antwort HTTP {http}: {json.dumps(obj, ensure_ascii=False)[:200]}")
        except Exception as exc:
            self._post(self._append, f"\u26a0 Fehler: {exc}")
        finally:
            try:
                if getattr(client, "sid", ""):
                    client.delete_session()
            except Exception:
                pass


    def _test_tool_timeout(self):
        client=self.gui._create_client(silent=True)
        try:
            client.initialize(); client.initialized()
            items=(client.list_tools()[0].get("result") or {}).get("tools") or []
            if not items:
                self._post(self._append, "\u26a0 Keine Tools vorhanden - Test \u00fcbersprungen.")
                return
            tool=items[0]
            name=tool.get("name","(ohne Name)")
            schema=tool.get("inputSchema") or {}
            try:
                args=client._gen_from_schema(schema)
            except Exception:
                args={}
            if not isinstance(args, dict):
                args={}
            self._post(self._append, f"Tool '{name}' mit sehr knappem Timeout (0.5s)...")
            try:
                with client.temp_timeout(0.5):
                    client.call("tools/call", {"name": name, "arguments": args}, stream=False, sse_max_seconds=2)
                self._post(self._append, "\u21b3 Antwort kam innerhalb des Timeouts (Server reagiert schnell).")
            except requests.exceptions.Timeout:
                self._post(self._append, "\u21b3 Timeout wie erwartet ausgel\u00f6st (Server braucht l\u00e4nger als 0.5s).")
            except Exception as exc:
                self._post(self._append, f"\u21b3 Unerwarteter Fehler: {exc}")
        except Exception as exc:
            self._post(self._append, f"\u26a0 Fehler beim Aufbau: {exc}")
        finally:
            try:
                if getattr(client, "sid", ""):
                    client.delete_session()
            except Exception:
                pass

    def _test_large_payload(self):
        client=self.gui._create_client(silent=True)
        try:
            client.initialize(); client.initialized()
            items=(client.list_tools()[0].get("result") or {}).get("tools") or []
            if not items:
                self._post(self._append, "\u26a0 Keine Tools vorhanden - Test \u00fcbersprungen.")
                return
            tool=items[0]
            name=tool.get("name","(ohne Name)")
            schema=tool.get("inputSchema") or {}
            try:
                args=client._gen_from_schema(schema)
            except Exception:
                args={}
            if not isinstance(args, dict):
                args={}
            payload="A"*5000
            if not args:
                args={"payload": payload}
            else:
                first_key=next(iter(args))
                if isinstance(args[first_key], str):
                    args[first_key]=payload
                else:
                    args["payload"]=payload
            self._post(self._append, f"Sende gro\u00dfe Payload (5000 Zeichen) an Tool '{name}'...")
            try:
                obj, resp = client.call("tools/call", {"name": name, "arguments": args}, stream=False, sse_max_seconds=10)
                http = getattr(resp, "status_code", "n/a")
                self._post(self._append, f"\u21b3 Serverantwort HTTP {http}. Details siehe Log.")
            except Exception as exc:
                self._post(self._append, f"\u21b3 Fehler beim Senden: {exc}")
        except Exception as exc:
            self._post(self._append, f"\u26a0 Fehler beim Aufbau: {exc}")
        finally:
            try:
                if getattr(client, "sid", ""):
                    client.delete_session()
            except Exception:
                pass

    def _test_missing_accept(self):
        client=self.gui._create_client(silent=True)
        try:
            self._post(self._append, "Sende initialize ohne Accept-Header...")
            headers=client._h_post()
            headers.pop("Accept", None)
            body={"jsonrpc":"2.0","id":999,"method":"initialize","params":{"protocolVersion":DEFAULT_PROTOCOL_VERSION}}
            resp=requests.post(client.url, headers=headers, json=body, verify=client.verify, timeout=client.timeout)
            detail=f"HTTP {resp.status_code}; Content-Type: {resp.headers.get('Content-Type','')}"
            preview=resp.text[:200]
            self._post(self._append, f"\u21b3 Antwort: {detail}")
            self._post(self._append, f"\u21b3 Auszug: {preview}")
        except Exception as exc:
            self._post(self._append, f"\u26a0 Fehler bei der Anfrage: {exc}")

    def _test_sse_abort(self):
        client=self.gui._create_client(silent=True)
        response=None
        try:
            client.initialize(); client.initialized()
            self._post(self._append, "SSE-Verbindung wird aufgebaut und nach 2 Sekunden beendet.")
            headers = client._h_get()
            response = requests.get(client.url, headers=headers, stream=True, verify=client.verify, timeout=client.timeout)
            start = time.time()
            count = 0
            if (response.headers.get("Content-Type") or "").lower().startswith("text/event-stream"):
                sse = SSEClient(response)
                for ev in sse.events():
                    count += 1
                    if time.time() - start > 2.0:
                        break
            else:
                self._post(self._append, f"\u26a0 Kein SSE-Stream (HTTP {response.status_code})")
            self._post(self._append, f"Verbindung nach {time.time()-start:.1f}s beendet. Empfangen: {count} Ereignisse.")
        except Exception as exc:
            self._post(self._append, f"\u26a0 Fehler: {exc}")
        finally:
            try:
                if response is not None:
                    response.close()
            except Exception:
                pass
            try:
                if getattr(client, "sid", ""):
                    client.delete_session()
            except Exception:
                pass

    def _close(self):
        if self._closing:
            return
        self._closing=True
        try:
            if self._thread and self._thread.is_alive():
                self._append("Testlabor schlie\u00dft - laufender Test wird beendet, bitte kurz warten ...")
                self._thread.join(timeout=1.0)
        except Exception:
            pass
        try:
            self.gui._test_lab = None
        except Exception:
            pass
        try:
            self.grab_release()
        except Exception:
            pass
        self.destroy()
    def _cancel(self):
        if self._closing:
            return
        self._closing = True
        try:
            self.gui._token_manager = None
        except Exception:
            pass
        try:
            self.grab_release()
        except Exception:
            pass
        self.destroy()

class SetupWizard(tk.Toplevel):
    def __init__(self, gui: ProGUI):
        super().__init__(gui.root)
        self.gui = gui
        self.title("MCP Debugger Setup Wizard")
        self.resizable(False, False)
        self.protocol("WM_DELETE_WINDOW", self._cancel)

        self.cert_choice = tk.StringVar(value="generate")
        self.cert_choice.trace_add("write", self._update_cert_controls)
        default_abs = os.path.join(os.path.dirname(__file__), "certs", "ca.cert.pem")
        initial_ca = self.gui.ca.get()
        if initial_ca:
            if os.path.normcase(os.path.abspath(initial_ca)) == os.path.normcase(default_abs):
                initial_display = self._default_ca_display()
            else:
                initial_display = initial_ca
        else:
            initial_display = self._default_ca_display()
        self.custom_ca = tk.StringVar(value=initial_display)
        self.tls_choice = tk.StringVar(value=self.gui.tls_mode.get())
        self.tls_choice.trace_add("write", self._update_tls_controls)
        self._tls_options = [
            ("System trust store (recommended)", "System Trust"),
            ("Insecure (accept self-signed certificates)", "Insecure (not recommended)"),
            ("Use embedded CA from ./certs/ca.cert.pem", "Embedded CA (./certs/ca.cert.pem)"),
            ("Pick a custom CA bundle...", "Pick file..."),
        ]
        self.url_choice = tk.StringVar(value=self.gui.url.get())

        self.steps = [
            ("Safety Warning", self._step_warning),
            ("Certificates", self._step_certificates),
            ("TLS Verification", self._step_tls_mode),
            ("Target MCP Server", self._step_server),
            ("Summary", self._step_summary),
        ]
        self.step_index = 0

        container = ttk.Frame(self, padding=10)
        container.pack(fill="both", expand=True)

        self.header = ttk.Label(container, text="", font=("Segoe UI", 12, "bold"))
        self.header.pack(anchor="w", pady=(0,6))

        self.body = ttk.Frame(container)
        self.body.pack(fill="both", expand=True)

        nav = ttk.Frame(container)
        nav.pack(fill="x", pady=(12,0))
        self.back_btn = ttk.Button(nav, text="Back", command=self._back)
        self.back_btn.pack(side="left")
        ttk.Button(nav, text="Cancel", command=self._cancel).pack(side="left", padx=(8,0))
        self.next_btn = ttk.Button(nav, text="Next", command=self._next)
        self.next_btn.pack(side="right")

        self.bind("<Return>", lambda *_: self._next())
        self.bind("<Escape>", lambda *_: self._cancel())

        self._render_step()
        self._center_on_parent()
        self.grab_set()
        try:
            self.transient(gui.root)
        except Exception:
            pass
        try:
            self.lift()
        except Exception:
            pass
        try:
            self.focus_force()
        except Exception:
            pass

    def _default_ca_display(self):
        return os.path.join(".", "certs", "ca.cert.pem")

    # ----- step renderers -----
    def _render_step(self):
        for child in self.body.winfo_children():
            child.destroy()
        for attr in ("_cert_entry", "_cert_browse", "_tls_entry", "_tls_browse", "_tls_combo"):
            if hasattr(self, attr):
                setattr(self, attr, None)
        title, builder = self.steps[self.step_index]
        self.header.config(text=f"Step {self.step_index+1} of {len(self.steps)} - {title}")
        builder(self.body)
        self.back_btn.config(state="normal" if self.step_index > 0 else "disabled")
        self.next_btn.config(text="Finish" if self.step_index == len(self.steps)-1 else "Next")
        self._update_cert_controls()
        self._update_tls_controls()

    def _step_warning(self, frame):
        ttk.Label(frame, text="\u26a0  Run audit executes every available tool against the selected MCP server.\n"
                              "Use this only in an isolated test environment. Never target production systems.",
                  justify="left", wraplength=420).pack(anchor="w")
        ttk.Label(frame, text="Read the README for full guidance before proceeding.",
                  justify="left", wraplength=420, foreground="#444").pack(anchor="w", pady=(12,0))

    def _step_certificates(self, frame):
        ttk.Label(frame, text="Certificates", font=("Segoe UI", 10, "bold")).pack(anchor="w")
        ttk.Radiobutton(frame, text="Generate new localhost certificate bundle now",
                        variable=self.cert_choice, value="generate").pack(anchor="w", pady=(6,0))
        ttk.Radiobutton(frame, text="Use existing certificates",
                        variable=self.cert_choice, value="existing").pack(anchor="w")
        ca_box = ttk.Frame(frame)
        ca_box.pack(fill="x", pady=(8,0))
        ttk.Label(ca_box, text="CA file:").pack(side="left")
        self._cert_entry = ttk.Entry(ca_box, textvariable=self.custom_ca, width=38)
        self._cert_entry.pack(side="left", padx=(4,4))
        self._cert_browse = ttk.Button(ca_box, text="Browse...", command=self._browse_ca)
        self._cert_browse.pack(side="left")
        ttk.Button(frame, text="Generate now", command=self._generate_certificates).pack(anchor="w", pady=(10,0))
        ttk.Label(frame, text="Output is stored under ./certs (ca.cert.pem, localhost.cert.pem, ...).",
                  foreground="#555", wraplength=420, justify="left").pack(anchor="w", pady=(6,0))

    def _step_tls_mode(self, frame):
        ttk.Label(frame, text="TLS verification mode", font=("Segoe UI", 10, "bold")).pack(anchor="w")
        combo_values=[label for label,_ in self._tls_options]
        self._tls_combo = ttk.Combobox(frame, state="readonly", values=combo_values, width=46)
        self._tls_combo.pack(anchor="w", pady=(6,4))
        current=self.tls_choice.get() or "System Trust"
        display = next((label for label,value in self._tls_options if value==current), None)
        if display is None:
            display = combo_values[0]
            self.tls_choice.set(next(value for label,value in self._tls_options if label==display))
        self._tls_combo.set(display)
        self._tls_combo.bind("<<ComboboxSelected>>", self._on_tls_selected)
        ttk.Label(frame, text="Choose how certificate validation is performed for MCP connections.", foreground="#444", wraplength=420, justify="left").pack(anchor="w")
        tls_box = ttk.Frame(frame)
        tls_box.pack(fill="x", pady=(10,0))
        ttk.Label(tls_box, text="CA bundle:").pack(side="left")
        self._tls_entry = ttk.Entry(tls_box, textvariable=self.custom_ca, width=38)
        self._tls_entry.pack(side="left", padx=(4,4))
        self._tls_browse = ttk.Button(tls_box, text="Browse...", command=self._browse_ca)
        self._tls_browse.pack(side="left")
        ttk.Label(frame, text="For embedded mode this points to ./certs/ca.cert.pem generated earlier.",
                  foreground="#555", wraplength=420, justify="left").pack(anchor="w", pady=(6,0))

    def _step_server(self, frame):
        ttk.Label(frame, text="Target MCP endpoint", font=("Segoe UI", 10, "bold")).pack(anchor="w")
        ttk.Label(frame, text="Enter the full HTTPS URL of your MCP server.", foreground="#444").pack(anchor="w", pady=(6,0))
        ttk.Entry(frame, textvariable=self.url_choice, width=50).pack(anchor="w", pady=(10,0))
        ttk.Label(frame, text="Example: https://localhost:8443/mcp", foreground="#555").pack(anchor="w", pady=(6,0))

    def _step_summary(self, frame):
        ttk.Label(frame, text="Summary", font=("Segoe UI", 10, "bold")).pack(anchor="w")
        summary = ttk.Frame(frame)
        summary.pack(anchor="w", pady=(6,0))
        entries = [
            ("Certificates", "Generated locally" if self.cert_choice.get()=="generate" else (self.custom_ca.get() or "Existing path")),
            ("TLS mode", next((label for label,value in self._tls_options if value==self.tls_choice.get()), self.tls_choice.get() or "System Trust")),
            ("MCP server", self.url_choice.get().strip() or self.gui.url.get()),
        ]
        for label, value in entries:
            row = ttk.Frame(summary)
            row.pack(anchor="w", fill="x", pady=2)
            ttk.Label(row, text=f"{label}:", width=14).pack(side="left")
            ttk.Label(row, text=value or "-", foreground="#222").pack(side="left")
        ttk.Label(frame, text="You can adjust any of these settings later in the main window.",
                  foreground="#444").pack(anchor="w", pady=(12,0))

    # ----- actions -----
    def _browse_ca(self):
        if filedialog is None:
            return
        path = filedialog.askopenfilename(title="CA-Bundle ausw\u00e4hlen",
                                          filetypes=[("Certificate files","*.pem *.crt *.cer *.ca-bundle"),("All files","*.*")])
        if path:
            self.custom_ca.set(path)
            self.gui.ca.set(path)

    def _generate_certificates(self):
        self.gui._gen_ca()
        default_ca = os.path.join(os.path.dirname(__file__), "certs", "ca.cert.pem")
        self.custom_ca.set(self._default_ca_display())
        self.gui.ca.set(default_ca)
        self.tls_choice.set("Embedded CA (./certs/ca.cert.pem)")

    def _update_cert_controls(self, *_):
        mode = self.cert_choice.get()
        state = "normal" if mode == "existing" else "disabled"
        entry = getattr(self, "_cert_entry", None)
        if entry is not None and str(entry) and entry.winfo_exists():
            entry.config(state=state)
        browse = getattr(self, "_cert_browse", None)
        if browse is not None and str(browse) and browse.winfo_exists():
            browse.config(state=state)

    def _update_tls_controls(self, *_):
        mode = self.tls_choice.get()
        use_custom = mode == "Pick file..."
        entry_state = "normal" if use_custom else "disabled"
        tls_entry = getattr(self, "_tls_entry", None)
        if tls_entry is not None and str(tls_entry) and tls_entry.winfo_exists():
            tls_entry.config(state=entry_state)
        tls_browse = getattr(self, "_tls_browse", None)
        if tls_browse is not None and str(tls_browse) and tls_browse.winfo_exists():
            tls_browse.config(state="normal" if use_custom else "disabled")
        combo = getattr(self, "_tls_combo", None)
        if combo is not None and str(combo) and combo.winfo_exists():
            target = next((label for label,value in self._tls_options if value==self.tls_choice.get()), None)
            if target:
                combo.set(target)
        if mode == "Embedded CA (./certs/ca.cert.pem)":
            self.custom_ca.set(self._default_ca_display())
        elif mode != "Pick file...":
            self.custom_ca.set("")

    def _apply_validations(self):
        if self.step_index == 1:
            if self.cert_choice.get() == "generate":
                self._generate_certificates()
            else:
                path = self.custom_ca.get().strip()
                if not path:
                    if messagebox: messagebox.showwarning("Certificates", "Bitte w\u00e4hle eine CA-Datei aus.")
                    return False
                self.gui.ca.set(path)
        elif self.step_index == 2:
            choice = self.tls_choice.get() or "System Trust"
            if choice == "Pick file..." and not self.custom_ca.get().strip():
                if messagebox: messagebox.showwarning("TLS", "Bitte CA-Bundle ausw\u00e4hlen oder anderen Modus w\u00e4hlen.")
                return False
            if choice == "Embedded CA (./certs/ca.cert.pem)":
                default_ca = os.path.join(os.path.dirname(__file__), "certs", "ca.cert.pem")
                self.gui.ca.set(default_ca)
                self.custom_ca.set(self._default_ca_display())
            if choice == "Insecure (not recommended)":
                self.gui.ca.set("")
            self.gui.tls_mode.set(choice)
        elif self.step_index == 3:
            url = self.url_choice.get().strip()
            if not url:
                if messagebox: messagebox.showwarning("MCP Server", "Bitte eine MCP-Server-URL eingeben.")
                return False
            self.gui.url.set(url)
        return True

    def _center_on_parent(self):
        parent = self.gui.root if hasattr(self.gui, "root") else None
        if not parent:
            return
        try:
            parent.update_idletasks()
            self.update_idletasks()
            pw, ph = parent.winfo_width(), parent.winfo_height()
            if pw <= 0: pw = 900
            if ph <= 0: ph = 640
            px, py = parent.winfo_rootx(), parent.winfo_rooty()
            w, h = self.winfo_width(), self.winfo_height()
            if w < 480: w = 480
            if h < 320: h = 320
            x = px + max((pw - w)//2, 0)
            y = py + max((ph - h)//2, 0)
            self.geometry(f"{w}x{h}+{x}+{y}")
        except Exception:
            pass

    def _on_tls_selected(self, *_):
        display = self._tls_combo.get()
        value = next((value for label,value in self._tls_options if label==display), None)
        if value:
            self.tls_choice.set(value)

    def _next(self):
        if not self._apply_validations():
            return
        if self.step_index >= len(self.steps)-1:
            self._finish()
            return
        self.step_index += 1
        self._render_step()

    def _back(self):
        if self.step_index == 0:
            return
        self.step_index -= 1
        self._render_step()

    def _finish(self):
        self._close(True)

    def _cancel(self, *_):
        self._close(False)

    def _close(self, completed):
        self.gui._wizard_closed(completed=completed)
        try:
            self.grab_release()
        except Exception:
            pass
        self.destroy()

# --------------- CLI ---------------
def run_cli(args):
    sink=Sink()
    verify=True
    if args.insecure: verify=False
    elif args.ca: verify=args.ca
    extra={}
    if args.bearer:
        extra[args.header if args.header else "Authorization"] = "Bearer " + args.bearer
    elif args.api_key and args.header:
        extra[args.header]=args.api_key
    if verify is False:
        try:
            from urllib3.exceptions import InsecureRequestWarning
            warnings.simplefilter("ignore", InsecureRequestWarning)
        except Exception:
            pass
    c=MCP(args.url, verify=verify, timeout=args.timeout, extra=extra, sink=sink, verbose=args.verbose)
    if args.mode=="overall":
        try:
            step_delay=max(0.0, float(getattr(args, "delay_ms", 0.0)))/1000.0
        except (TypeError, ValueError):
            step_delay=0.0
        summary, details = c.overall(timeout_override=args.timeout, step_delay=step_delay)
        out={"summary":summary,"details":details,"meta":{"url":args.url,"time":time.strftime("%Y-%m-%d %H:%M:%S"),"protocol_version":c.proto,"session_id":c.sid}}
        if args.out:
            with open(args.out, "w", encoding="utf-8") as f:
                json.dump(out, f, ensure_ascii=False, indent=2)
        else:
            print(json.dumps(out, ensure_ascii=False, indent=2))
        return
    if args.mode=="audit":
        c.initialize(); c.initialized()
        try:
            throttle=max(0.0, float(getattr(args, "delay_ms", 0.0)))/1000.0
        except (TypeError, ValueError):
            throttle=0.0
        out = c.audit_tools(limit=args.limit, per_call_timeout=args.per_timeout, parallelism=max(1,args.parallel), validate_outputs=True, throttle_seconds=throttle)
        print(json.dumps(out, ensure_ascii=False, indent=2)); return
    c.initialize(); c.initialized()
    if args.lists:
        c.list_tools(); c.list_resources(); c.list_prompts()
    if args.sse_seconds>0:
        c.get_sse(args.sse_seconds)

def main():
    ap=argparse.ArgumentParser(description="MCP Diagnoser v4.3")
    sub=ap.add_subparsers(dest="mode")
    p=sub.add_parser("diagnose")
    p.add_argument("--url", required=True)
    p.add_argument("--timeout", type=float, default=30.0)
    p.add_argument("--insecure", action="store_true")
    p.add_argument("--ca", default=None)
    p.add_argument("--lists", action="store_true")
    p.add_argument("--sse-seconds", type=int, default=0)
    p.add_argument("--verbose", action="store_true")
    p.add_argument("--bearer", default=None)
    p.add_argument("--api-key", default=None)
    p.add_argument("--header", default=None)

    pov=sub.add_parser("overall")
    pov.add_argument("--url", required=True)
    pov.add_argument("--timeout", type=float, default=30.0)  # also acts as overall timeout
    pov.add_argument("--insecure", action="store_true")
    pov.add_argument("--ca", default=None)
    pov.add_argument("--out", default=None)
    pov.add_argument("--verbose", action="store_true")
    pov.add_argument("--bearer", default=None)
    pov.add_argument("--api-key", default=None)
    pov.add_argument("--header", default=None)
    pov.add_argument("--delay-ms", type=float, default=0.0, help="Delay between overall steps in milliseconds")

    pa=sub.add_parser("audit")
    pa.add_argument("--url", required=True)
    pa.add_argument("--timeout", type=float, default=30.0)
    pa.add_argument("--insecure", action="store_true")
    pa.add_argument("--ca", default=None)
    pa.add_argument("--limit", type=int, default=None)
    pa.add_argument("--per-timeout", type=float, default=10.0, dest="per_timeout")
    pa.add_argument("--parallel", type=int, default=1)
    pa.add_argument("--verbose", action="store_true")
    pa.add_argument("--bearer", default=None)
    pa.add_argument("--api-key", default=None)
    pa.add_argument("--header", default=None)
    pa.add_argument("--delay-ms", type=float, default=0.0, help="Delay between audit tool calls in milliseconds")

    args=ap.parse_args()
    if args.mode in ("diagnose","overall","audit"):
        run_cli(args); return
    if tk is None:
        print("Tkinter nicht verfuegbar. CLI verwenden.", file=sys.stderr); sys.exit(2)
    root=tk.Tk(); ProGUI(root); root.mainloop()

if __name__=="__main__":
    main()

