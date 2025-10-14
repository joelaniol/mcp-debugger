import argparse, json, time, threading, queue, sys, os, logging, zipfile, concurrent.futures, shlex, warnings, math, copy
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

DEFAULT_PROTOCOL_VERSION = "2025-06-18"

def ts():
    return time.strftime("%H:%M:%S")

class Sink:
    def __init__(self, gui_cb=None, mem_log=None):
        self.gui_cb=gui_cb
        self.mem_log = mem_log if mem_log is not None else []
        self.session_resets = 0
    def write(self, line):
        msg = f"[{ts()}] {line}"
        print(msg, flush=True)
        self.mem_log.append(msg)
        if "Session-Objekt zurückgesetzt" in line or "Session-Objekt zur\u00fcckgesetzt" in line:
            self.session_resets += 1
        if self.gui_cb: self.gui_cb(msg)

class MCP:
    def __init__(self, url, verify=True, timeout=30.0, extra=None, sink=None, verbose=False):
        self.url=url; self.verify=verify; self.timeout=timeout
        self.extra=dict(extra or {}); self.sid=""; self.proto=""; self._id=1
        self.sink=sink or Sink()
        self.verbose = verbose
        self.last_request = None
        self.last_http = None
        self.last_body = None
        self._id_lock = threading.Lock()
        self._thread_local = threading.local()

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
        r=requests.post(self.url, data=json.dumps(payload), headers=h, stream=True, verify=self.verify, timeout=self.timeout)
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
        r=requests.post(self.url, data=json.dumps(payload), headers=h, stream=False, verify=self.verify, timeout=self.timeout)
        self.sink.write(f"<< HTTP {r.status_code} (initialized)")
        return r

    def call(self, method, params=None, stream=True, accept_json_only=False, sse_max_seconds=None):
        payload={"jsonrpc":"2.0","id":self._next(),"method":method}
        if params is not None: payload["params"]=params
        h=self._h_post(accept_json_only=accept_json_only)
        self.last_request={"method":method,"headers":h,"payload":payload}
        self.last_http={"method":"POST","url":self.url,"headers":h.copy(),"body":payload}
        snapshot = copy.deepcopy(self.last_request)
        try:
            self._thread_local.last_request = snapshot
        except Exception:
            self._thread_local.last_request = snapshot
        self.sink.write(f">> POST {self.url} [{method}]"); self._log_h(h)
        self.sink.write(">> Body: " + json.dumps(payload, ensure_ascii=False))
        if self.sid: self.sink.write(f">> Using session: {self.sid}")
        r=requests.post(self.url, data=json.dumps(payload), headers=h, stream=stream, verify=self.verify, timeout=self.timeout)
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

        # If server unexpectedly returns SSE but we explicitly asked JSON-only or stream=False, don't block
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
                    obj={"_raw": r.text, "_note":"event-stream without parsable JSON"}
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
            return obj, r

        if "text/event-stream" in ct:
            client=SSEClient(r)
            deadline = time.time() + (sse_max_seconds or 30)
            for ev in client.events():
                try:
                    d=json.loads(ev.data); self.last_body=d; self.sink.write(f"<< [SSE {ev.event or 'message'}] " + json.dumps(d, ensure_ascii=False))
                    if isinstance(d,dict) and d.get("id")==payload["id"] and ("result" in d or "error" in d):
                        return d, r
                except Exception:
                    self.sink.write(f"<< [SSE raw] {ev.data}")
                if time.time() >= deadline:
                    self.sink.write("<< WARN: SSE read timed out; continuing.")
                    break
            return {}, r
        else:
            try: obj=r.json()
            except Exception: obj={"_raw": r.text}
            self.last_body = obj
            self.sink.write("<< Body: " + json.dumps(obj, ensure_ascii=False))
            return obj, r

    def list_tools(self): return self.call("tools/list", {"cursor": None}, sse_max_seconds=5)
    def list_resources(self): return self.call("resources/list", {"cursor": None}, sse_max_seconds=5)
    def list_prompts(self): return self.call("prompts/list", {"cursor": None}, sse_max_seconds=5)

    def get_sse(self, seconds=3):
        h=self._h_get()
        self.last_http={"method":"GET","url":self.url,"headers":h.copy(),"body":None}
        self.sink.write(f">> GET {self.url} [SSE] {seconds}s"); self._log_h(h)
        r=requests.get(self.url, headers=h, stream=True, verify=self.verify, timeout=self.timeout)
        self.sink.write(f"<< HTTP {r.status_code}  Content-Type: {r.headers.get('Content-Type','')}")
        ct=(r.headers.get("Content-Type") or "").lower()
        if "text/event-stream" not in ct:
            self.sink.write("<< Kein text/event-stream (405 oder JSON)."); return r
        client=SSEClient(r); end=time.time()+max(0,seconds)
        for ev in client.events():
            try: d=json.loads(ev.data); self.last_body=d; self.sink.write(f"<< [SSE {ev.event or 'message'}] " + json.dumps(d, ensure_ascii=False))
            except Exception: self.sink.write("<< [SSE raw] " + ev.data)
            if seconds and time.time()>=end: break
        return r

    def delete_session(self):
        h=self._h_post()
        self.last_http={"method":"DELETE","url":self.url,"headers":h.copy(),"body":None}
        self.sink.write(f">> DELETE {self.url} [session]"); self._log_h(h)
        r=requests.delete(self.url, headers=h, verify=self.verify, timeout=self.timeout)
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
                if not ok:
                    res={"tool":name,"status":status,"detail":detail,"ms":ms,"kb":kb,"tokens":tokens,"args":args,"http":None}
                    if on_progress: on_progress(res)
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
                    res={"tool":name,"status":status,"detail":detail,"ms":ms,"kb":kb,"tokens":tokens,"args":args,"http":resp.status_code,"request":req_snapshot,"response":obj,"http_headers":dict(getattr(resp, "headers", {}))}
                except requests.exceptions.Timeout as e:
                    ms = int(round((time.monotonic()-start)*1000))
                    try:
                        req_snapshot_timeout = copy.deepcopy(getattr(self._thread_local, 'last_request', self.last_request))
                    except Exception:
                        req_snapshot_timeout = getattr(self._thread_local, 'last_request', self.last_request)
                    res={"tool":name,"status":"TIMEOUT","detail":str(e),"ms":ms,"kb":0.0,"tokens":0,"args":args,"http":None,"request":req_snapshot_timeout,"response":None,"http_headers":{}}
                except Exception as e:
                    ms = int(round((time.monotonic()-start)*1000))
                    try:
                        req_snapshot_exc = copy.deepcopy(getattr(self._thread_local, 'last_request', self.last_request))
                    except Exception:
                        req_snapshot_exc = getattr(self._thread_local, 'last_request', self.last_request)
                    res={"tool":name,"status":"EXCEPTION","detail":str(e),"ms":ms,"kb":0.0,"tokens":0,"args":args,"http":None,"request":req_snapshot_exc,"response":None,"http_headers":{}}
                if on_progress: on_progress(res)
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

    def overall(self, timeout_override=None, step_delay=None, stage_callback=None):
        summary=[]; details={}
        delay_seconds=0.0
        if step_delay:
            try:
                delay_seconds=max(0.0, float(step_delay))
            except (TypeError, ValueError):
                delay_seconds=0.0
        def add(level, name, status, detail):
            summary.append({"level":level,"check":name,"status":status,"detail":detail})

        def notify_stage(label):
            if stage_callback:
                try:
                    stage_callback(label)
                except Exception:
                    pass

        def stage(label, first=False):
            if not first and delay_seconds>0.0:
                time.sleep(delay_seconds)
            notify_stage(label)

        with (self.temp_timeout(timeout_override) if timeout_override is not None else self.temp_timeout(None)):
            stage("POST initialize", first=True)
            try:
                obj, r = self.initialize()
                details["initialize"]={"http":r.status_code,"headers":dict(r.headers),"body":obj}
                j_ok = isinstance(obj, dict) and obj.get("jsonrpc")=="2.0" and ("result" in obj or "error" in obj)
                add("MUST","JSON-RPC 2.0 response", "OK" if j_ok else "FAIL", "jsonrpc='2.0' & result|error required")
                h=self.last_http.get("headers",{}) if self.last_http else {}
                acc=h.get("Accept",""); ct=h.get("Content-Type","")
                add("MUST","Accept header", "OK" if ("application/json" in acc and "text/event-stream" in acc) else "FAIL", acc or "missing")
                add("MUST","Content-Type header", "OK" if ct.lower()=="application/json" else "FAIL", ct or "missing")
                pv=(obj.get("result") or {}).get("protocolVersion") if isinstance(obj,dict) else None
                add("MUST","Protocol-Version negotiated", "OK" if isinstance(pv,str) and pv else "FAIL", pv or "missing")
                caps=(obj.get("result") or {}).get("capabilities") if isinstance(obj,dict) else None
                add("MUST","Capabilities object in InitializeResult", "OK" if isinstance(caps, dict) else "FAIL", "present" if isinstance(caps,dict) else "missing")
                s_info=(obj.get("result") or {}).get("serverInfo") if isinstance(obj,dict) else None
                add("SHOULD","serverInfo provided", "OK" if isinstance(s_info, dict) else "WARN", "present" if isinstance(s_info,dict) else "absent")
            except Exception as e:
                add("MUST","initialize", "FAIL", str(e))
                return summary, details

            stage("notifications/initialized")
            try:
                rr=self.initialized(); details["initialized"]={"http":rr.status_code}
                add("MUST","notifications/initialized -> 202", "OK" if rr.status_code==202 else "FAIL", f"HTTP {rr.status_code}")
            except Exception as e:
                add("MUST","notifications/initialized", "FAIL", str(e))

            tools=[]
            stage("tools/list")
            try:
                o,r=self.list_tools(); details["tools/list"]={"http":r.status_code,"headers":dict(r.headers),"body":o}
                tools=((o.get("result") or {}).get("tools") or []) if isinstance(o,dict) else []
                has_tools_cap = isinstance(caps,dict) and isinstance(caps.get("tools"), dict)
                if has_tools_cap or (isinstance(tools, list) and len(tools)>0):
                    add("MUST","tools/list returns list", "OK" if isinstance(tools,list) else "FAIL", f"count={len(tools) if isinstance(tools,list) else 'n/a'}")
                else:
                    add("OPTIONAL","tools/list (no tools advertised)", "OK" if r.ok else "WARN", f"HTTP {r.status_code}")
            except Exception as e:
                add("MUST","tools/list", "FAIL", str(e))

            if isinstance(tools, list) and tools:
                t=tools[0]; name=t.get("name")
                stage("tools/call (sample)")
                try:
                    obj, resp = self.call("tools/call", {"name": name, "arguments": {}}, stream=True, sse_max_seconds=15)
                    ok = resp.ok and isinstance(obj, dict) and ("result" in obj or "error" in obj)
                    add("MUST","tools/call JSON-RPC", "OK" if ok else "FAIL", f"HTTP {getattr(resp,'status_code', 'n/a')}")
                except Exception as e:
                    add("MUST","tools/call", "FAIL", str(e))
            else:
                add("OPTIONAL","tools/call (no tools)", "OK", "skipped")

            # Robust error-object probe: try unknown method JSON-only; fallback to invalid params
            stage("JSON-RPC error probe")
            try:
                bad, br = self.call("rpc/does_not_exist", {}, stream=False, accept_json_only=True)
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
                add("MUST","JSON-RPC error format", "OK" if err_ok else "FAIL", detail)
            except Exception as e:
                add("MUST","JSON-RPC error format", "WARN", f"probe failed: {e}")

            stage("GET SSE (1s)")
            try:
                r=self.get_sse(1); details["GET-SSE"]={"http":r.status_code,"headers":dict(r.headers)}
                ct=(r.headers.get("Content-Type") or "").lower()
                if "text/event-stream" in ct or r.status_code==405:
                    add("MUST","HTTP SSE endpoint behavior", "OK", "event-stream or 405")
                else:
                    add("MUST","HTTP SSE endpoint behavior", "FAIL", f"{r.status_code} {ct}")
            except Exception as e:
                add("MUST","HTTP SSE endpoint", "FAIL", str(e))

            try:
                sid_present = bool(details.get("initialize",{}).get("headers",{}).get("Mcp-Session-Id") or self.sid)
                add("SHOULD","Mcp-Session-Id issued", "OK" if sid_present else "WARN", "present" if sid_present else "not issued")
            except Exception as e:
                add("SHOULD","Mcp-Session-Id", "WARN", str(e))

            stage("prompts/list")
            try:
                op, rp = self.list_prompts()
                ok = rp.ok and isinstance(op, dict) and "result" in op
                add("OPTIONAL","prompts/list", "OK" if ok else "WARN", f"HTTP {getattr(rp,'status_code','n/a')}")
            except Exception as e:
                add("OPTIONAL","prompts/list", "WARN", str(e))
            stage("resources/list")
            try:
                orc, rr2 = self.list_resources()
                ok = rr2.ok and isinstance(orc, dict) and "result" in orc
                add("OPTIONAL","resources/list", "OK" if ok else "WARN", f"HTTP {getattr(rr2,'status_code','n/a')}")
            except Exception as e:
                add("OPTIONAL","resources/list", "WARN", str(e))

            stage("DELETE session")
            try:
                r=self.delete_session(); details["DELETE"]={"http":r.status_code}
                add("OPTIONAL","DELETE session", "OK" if 200 <= r.status_code < 400 else "WARN", f"HTTP {r.status_code}")
            except Exception as e:
                add("OPTIONAL","DELETE session", "WARN", str(e))

            try:
                resets=getattr(self.sink, "session_resets", 0)
                if resets and resets > 1:
                    add("INFO","Session resets", "WARN", f"{resets} resets observed during run")
            except Exception:
                pass

        return summary, details

# ---------------- GUI ----------------
class ProGUI:
    def __init__(self, root):
        self.root=root; self.root.title("MCP Diagnoser v4.2")
        self.mem_log=[]
        self.q=queue.Queue(); self.client=None; self.last_report=None
        self._audit_stop=False
        self._audit_total=0
        self._audit_done=0
        self._audit_running=0



        self._state = self._load_state()
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
        }
        merged={k:self._state.get(k, v) for k,v in state_defaults.items()}
        self.url=tk.StringVar(value=merged["url"])
        self.tls_mode=tk.StringVar(value=merged["tls_mode"])
        self.timeout=tk.StringVar(value=merged["timeout"])
        self.overall_timeout=tk.StringVar(value=merged["overall_timeout"])
        self.overall_delay=tk.StringVar(value=merged["overall_delay"])
        self.audit_delay=tk.StringVar(value=merged["audit_delay"])
        self.summary_status=tk.StringVar(value="Bereit")
        self.ca=tk.StringVar(value=merged["ca"])
        self.auth_mode=tk.StringVar(value=merged["auth_mode"])
        self.auth_token=tk.StringVar(value=merged["auth_token"])
        self.auth_header=tk.StringVar(value=merged["auth_header"])
        default_enabled = bool(merged["auth_mode"] != "None" and merged["auth_token"])
        enabled_val = self._state.get("auth_enabled", default_enabled)
        self.auth_enabled=tk.BooleanVar(value=bool(enabled_val if enabled_val is not None else default_enabled))
        if self.auth_mode.get()=="None" or not self.auth_token.get().strip():
            self.auth_enabled.set(False)
        self.auth_status=tk.StringVar(value="")
        self.auth_toggle_text=tk.StringVar(value="")
        self._wizard_active=False
        self._token_manager=None
        self._build()
        self._apply_auth(silent=True)
        self._center_window(self.root, min_w=900, min_h=640)
        self._pump()
        if self.root is not None and not self._state.get("wizard_done"):
            self.root.after(200, self._show_wizard)

    def _sink(self, m):
        self.mem_log.append(m)
        self.q.put(m)

    def _pump(self):
        try:
            while True:
                m=self.q.get_nowait()
                self.console.insert("end", m+"\n"); self.console.see("end")
        except queue.Empty: pass
        self.root.after(60, self._pump)

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
        ttk.Button(top, text="…", width=3, command=self._pick_ca).grid(row=1, column=3, sticky="w")
        ttk.Button(top, text="Generate CA+Server", command=self._gen_ca).grid(row=1, column=4, sticky="w")
        ttk.Button(top, text="Clear console", command=self._clear).grid(row=1, column=5, sticky="w")
        ttk.Button(top, text="Save settings", command=self._save_settings).grid(row=1, column=6, sticky="w")

        ttk.Label(top, text="Auth:").grid(row=2, column=0, sticky="e")
        ttk.Label(top, textvariable=self.auth_status, width=38).grid(row=2, column=1, columnspan=3, sticky="we")
        ttk.Button(top, textvariable=self.auth_toggle_text, command=self._toggle_auth, width=14).grid(row=2, column=4, sticky="w", padx=(0,4))
        ttk.Button(top, text="Authentifizierungsmanager…", command=self._open_token_manager).grid(row=2, column=5, sticky="w")
        ttk.Label(top, text="Konfiguration und Token im Authentifizierungsmanager pflegen.", foreground="#555").grid(row=3, column=1, columnspan=5, sticky="w", pady=(2,0))

        prof=ttk.Frame(self.root); prof.pack(fill="x", **p)
        ttk.Label(prof, text="Profiles:").pack(side="left")
        ttk.Button(prof, text="Save (per URL)", command=self._save_profile).pack(side="left")
        ttk.Button(prof, text="Load", command=self._load_profile).pack(side="left")
        ttk.Button(prof, text="Delete", command=self._delete_profile).pack(side="left")
        ttk.Label(prof, text="⚠ Token wird lokal im Klartext gespeichert. Nur auf vertrauenswürdigen Geräten.").pack(side="left")

        body=ttk.PanedWindow(self.root, orient="horizontal"); body.pack(fill="both", expand=True, **p)
        left=ttk.Frame(body); right=ttk.Frame(body)
        body.add(left, weight=1); body.add(right, weight=2)

        ttk.Label(left, text="Checks & Samples").pack(anchor="w")
        self.tree=ttk.Treeview(left, show="tree")
        self.tree.pack(fill="both", expand=True)
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
        self.tree.insert(a, "end", iid="audit_tools", text="Audit all tools (schema→args→validate→call)")
        m = self.tree.insert("", "end", text="Misc", open=True)
        self.tree.insert(m, "end", iid="get_sse", text="GET SSE (3s)")
        self.tree.insert(m, "end", iid="delete_session", text="DELETE session")

        btns=ttk.Frame(left); btns.pack(fill="x")
        ttk.Button(btns, text="Run selected", command=self._run_selected).pack(side="left")
        ttk.Button(btns, text="Run all", command=self._run_all).pack(side="left")
        ttk.Button(btns, text="Reset session", command=self._reset_session).pack(side="right")

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
        ttk.Button(sumbtns, text="Clear summary", command=lambda: self.summary.delete(*self.summary.get_children())).pack(side="left")

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

        ttk.Label(right, text="JSON-RPC Payload (für POST-Sample):").pack(anchor="w")
        self.payload=ScrolledText(right, height=10); self.payload.pack(fill="x")
        self._prefill_payload()

        rightbtns=ttk.Frame(right); rightbtns.pack(fill="x")
        ttk.Button(rightbtns, text="Open Tree Viewer (last JSON)", command=self._open_tree).pack(side="left")
        ttk.Button(rightbtns, text="Show cURL (last request)", command=self._show_curl).pack(side="left")
        ttk.Button(rightbtns, text="Save last request (.http)", command=self._save_httpfile).pack(side="left")

        ttk.Label(right, text="Console:").pack(anchor="w")
        self.console=ScrolledText(right, height=24); self.console.pack(fill="both", expand=True)

        tip = ttk.Label(self.root, text="Hinweis: Overall timeout gilt nur für den Gesamtcheck. Bearer nur via TLS.", foreground="#444")
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

    def _clear(self): self.console.delete("1.0","end"); self.mem_log.clear()
    def _reset_session(self): self.client=None; self._sink("Session-Objekt zurückgesetzt.")

    def _pick_ca(self):
        p=filedialog.askopenfilename(title="CA-Bundle wählen", filetypes=[("Zertifikate","*.pem *.crt *.cer *.ca-bundle"),("Alle Dateien","*.*")])
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
        self._state["url"] = self.url.get().strip()
        self._state["tls_mode"] = self.tls_mode.get()
        self._state["timeout"] = self.timeout.get()
        self._state["overall_timeout"] = self.overall_timeout.get()
        self._state["overall_delay"] = self.overall_delay.get()
        self._state["audit_delay"] = self.audit_delay.get()
        self._state["ca"] = self.ca.get().strip()
        self._state["auth_mode"] = self.auth_mode.get()
        self._state["auth_token"] = self.auth_token.get()
        self._state["auth_header"] = self.auth_header.get()
        self._state["auth_enabled"] = bool(self.auth_enabled.get())
        self._save_state()
        self._sink("Settings saved.")

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
        self._write_profiles_file(data); self._sink(f"Profile gespeichert für URL: {url}")
    def _load_profile(self):
        url=self.url.get().strip(); data=self._load_profiles_file()
        if url not in data:
            if messagebox: messagebox.showinfo("Profile", "Kein Profil für diese URL.")
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
        self._sink(f"Profile geladen für URL: {url}")
    def _delete_profile(self):
        url=self.url.get().strip(); data=self._load_profiles_file()
        if url in data:
            del data[url]; self._write_profiles_file(data); self._sink(f"Profile gelöscht für URL: {url}")
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

    def _build_client(self, reset=False, extra_override=None):
        if reset or self.client is None:
            mode = self.tls_mode.get()
            verify=True
            if mode=="Insecure (not recommended)":
                verify=False
            elif mode=="Embedded CA (./certs/ca.cert.pem)":
                p=os.path.join(os.path.dirname(__file__),"certs","ca.cert.pem")
                verify=p if os.path.exists(p) else True
                if not os.path.exists(p):
                    self._sink("WARN: ./certs/ca.cert.pem nicht gefunden. 'Generate CA+Server' ausführen oder TLS Mode wechseln.")
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
            self.client = MCP(url, verify=verify, timeout=to, extra=extra, sink=Sink(self._sink, self.mem_log), verbose=False)
        return self.client

    def _run_selected(self):
        sel=self.tree.selection()
        if not sel: return
        action=sel[0]
        threading.Thread(target=lambda: self._run_action(action), daemon=True).start()

    def _start_overall(self, reset_session):
        for i in self.summary.get_children(): self.summary.delete(i)
        c=self._build_client(reset=reset_session)
        try: ov_to=float(self.overall_timeout.get() or "30")
        except: ov_to=30.0
        try: delay_ms=float(self.overall_delay.get() or "0")
        except: delay_ms=0.0
        step_delay=max(0.0, delay_ms/1000.0)
        self.summary_status.set("Overall-Test läuft …")
        def stage_cb(stage):
            def _set():
                if stage:
                    self.summary_status.set(f"Aktuell: {stage}")
                else:
                    self.summary_status.set("Aktuell: –")
            try:
                self.root.after(0, _set)
            except Exception:
                pass
        def run():
            try:
                summary, details = c.overall(timeout_override=ov_to, step_delay=step_delay, stage_callback=stage_cb)
                status_msg="✔ Gesamtcheck abgeschlossen"
            except Exception as e:
                summary=[{"level":"MUST","check":"overall()", "status":"FAIL","detail":str(e)}]; details={}
                status_msg=f"Fehler: {e}"
            self.last_report={"summary":summary,"details":details,"log":"\n".join(self.mem_log),"meta":{"url":self.url.get().strip(),"tls_mode":self.tls_mode.get(),"time":time.strftime("%Y-%m-%d %H:%M:%S"),"protocol_version":getattr(c,'proto',''),"session_id":getattr(c,'sid','')}}
            def _finalize():
                self._populate_summary(summary)
                self.summary_status.set(status_msg)
            self.root.after(0, _finalize)
        threading.Thread(target=run, daemon=True).start()

    def _run_all(self):
        self._start_overall(reset_session=True)

    def _run_overall(self):
        self._start_overall(reset_session=False)

    def _populate_summary(self, summary):
        warn_statuses={"WARN","INFO","WARN_BLOCKED","WARN_ACTION_REQUIRED","WARN_STATE_UNCLEAR","WARN_NOT_IMPLEMENTED"}
        for it in summary:
            status=it.get("status","")
            if status=="OK":
                tag="ok"
            elif status in warn_statuses:
                tag="warn"
            else:
                tag="err"
            self.summary.insert("", "end", values=(it["check"], it["level"], status, it.get("detail","")), tags=(tag,))

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
        self._sink("Audit stop requested. Läuft bis zum Ende des aktuellen Requests weiter.")
        if self._audit_running:
            self.audit_progress.set(f"Stop requested · {self._audit_running} running")
        else:
            self.audit_progress.set("Stop requested")

    def _run_audit(self):
        for i in self.audit.get_children(): self.audit.delete(i)
        self._audit_row_data = {}
        self._audit_stop=False
        c=self._build_client(reset=False)
        if c.sid=="":
            self._sink("Keine Session aktiv. Bitte zuerst 'POST initialize' ausführen."); return
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
            self.audit_progress.set(" · ".join(parts) if parts else "")

        def on_progress(event):
            if event is None: 
                return
            def _ins(): 
                meta = event.get("meta") if isinstance(event, dict) else None
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
                detail_display = "View…"
                item=self.audit.insert("", "end", values=(res.get("tool","?"), status, f"{int(res.get('ms',0))}", tokens_str, f"{res.get('kb',0.0):.2f}", detail_display), tags=((tag,) if tag else ()))
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
                    self.audit_progress.set(f"{self._audit_done}/{total} done · Finished")
                else:
                    self.audit_progress.set(f"Finished: {len(out)} tools processed")
            self.root.after(0, _finalize)
        threading.Thread(target=run, daemon=True).start()

    def _clear_audit(self):
        self._audit_row_data = {}
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
            self._sink("Authentifizierungsmanager nicht verfügbar (Tkinter fehlt).")
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

    def _show_curl(self):
        c=self._build_client(reset=False)
        s_bash=c.last_curl(redact=True, windows=False) if c else ""
        s_win=c.last_curl(redact=True, windows=True) if c else ""
        top=tk.Toplevel(self.root); top.title("cURL (last request)")
        txt=ScrolledText(top, height=20); txt.pack(fill="both", expand=True)
        txt.insert("1.0", "# Bash\n"+s_bash+"\n\n# Windows CMD/PowerShell\n"+s_win); txt.see("1.0")

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

        ttk.Label(body, text="Hinweis: Einstellungen werden beim Schließen übernommen.", foreground="#555").grid(row=5, column=0, columnspan=2, sticky="w", pady=(12,0))

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
            ("Pick a custom CA bundle…", "Pick file..."),
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
        ttk.Label(frame, text="⚠️  Run audit executes every available tool against the selected MCP server.\n"
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
        self._cert_browse = ttk.Button(ca_box, text="Browse…", command=self._browse_ca)
        self._cert_browse.pack(side="left")
        ttk.Button(frame, text="Generate now", command=self._generate_certificates).pack(anchor="w", pady=(10,0))
        ttk.Label(frame, text="Output is stored under ./certs (ca.cert.pem, localhost.cert.pem, …).",
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
        self._tls_browse = ttk.Button(tls_box, text="Browse…", command=self._browse_ca)
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
        path = filedialog.askopenfilename(title="CA-Bundle auswählen",
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
                    if messagebox: messagebox.showwarning("Certificates", "Bitte wähle eine CA-Datei aus.")
                    return False
                self.gui.ca.set(path)
        elif self.step_index == 2:
            choice = self.tls_choice.get() or "System Trust"
            if choice == "Pick file..." and not self.custom_ca.get().strip():
                if messagebox: messagebox.showwarning("TLS", "Bitte CA-Bundle auswählen oder anderen Modus wählen.")
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
    ap=argparse.ArgumentParser(description="MCP Diagnoser v4.2")
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
