from __future__ import annotations

from dataclasses import dataclass
from typing import Dict


@dataclass
class AuthComputation:
    headers: Dict[str, str]
    effective: bool
    ready: bool
    status: str
    toggle: str
    log: str


@dataclass
class AuthState:
    mode: str = "None"
    token: str = ""
    header: str = "Authorization"
    enabled: bool = False

    def _normalized_mode(self) -> str:
        value = (self.mode or "").strip()
        return value if value else "None"

    def _trimmed_token(self) -> str:
        return (self.token or "").strip()

    def _normalized_header(self) -> str:
        header = (self.header or "").strip()
        return header if header else "Authorization"

    def ready(self) -> bool:
        return self._normalized_mode() != "None" and bool(self._trimmed_token())

    def _supports_headers(self) -> bool:
        return self._normalized_mode() in {"Bearer", "Custom header"}

    def effective(self) -> bool:
        return bool(self.enabled and self.ready() and self._supports_headers())

    def build_headers(self) -> Dict[str, str]:
        if not self.effective():
            return {}
        header = self._normalized_header()
        token = self._trimmed_token()
        mode = self._normalized_mode()
        if mode == "Bearer":
            return {header: f"Bearer {token}"}
        if mode == "Custom header":
            return {header: token}
        return {}

    def _masked_token(self) -> str:
        token = self._trimmed_token()
        if not token:
            return ""
        return token if len(token) <= 4 else f"{token[:4]}…"

    def status_text(self) -> str:
        mode = self._normalized_mode()
        if not self.ready():
            return "Nicht konfiguriert"
        if not self.effective():
            return f"{mode}: deaktiviert"
        masked = self._masked_token() or "Token fehlt"
        return f"{mode} · {self._normalized_header()} · {masked}"

    def toggle_text(self) -> str:
        if not self.ready():
            return "Konfigurieren…"
        return "Deaktivieren" if self.effective() else "Aktivieren"

    def log_message(self) -> str:
        mode = self._normalized_mode()
        if not self.ready():
            return "Auth nicht konfiguriert."
        if not self.effective():
            return f"Auth deaktiviert ({mode})."
        headers = self.build_headers()
        if not headers:
            return "Auth deaktiviert."
        return "Auth aktiv: " + "; ".join(f"{k}: ***" for k in headers)

    def compute(self) -> AuthComputation:
        headers = self.build_headers()
        effective = self.effective()
        ready = self.ready()
        status = self.status_text()
        toggle = self.toggle_text()
        log = self.log_message()
        return AuthComputation(
            headers=headers,
            effective=effective,
            ready=ready,
            status=status,
            toggle=toggle,
            log=log,
        )
