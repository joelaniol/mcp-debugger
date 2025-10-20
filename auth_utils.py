from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Dict, Optional

Translator = Optional[Callable[[str, Optional[str]], str]]


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

    def _translate(self, translator: Translator, english: str, german: Optional[str] = None) -> str:
        if translator:
            return translator(english, german)
        return english if german is None else english

    def _masked_token(self) -> str:
        token = self._trimmed_token()
        if not token:
            return ""
        return token if len(token) <= 4 else f"{token[:4]}..."

    def status_text(self, translator: Translator = None) -> str:
        T = lambda en, de=None: self._translate(translator, en, de)
        mode = self._normalized_mode()
        if not self.ready():
            return T("Not configured", "Nicht konfiguriert")
        if not self.effective():
            return T(f"{mode}: disabled", f"{mode}: deaktiviert")
        masked = self._masked_token()
        masked_en = masked or "Token missing"
        masked_de = masked or "Token fehlt"
        header = self._normalized_header()
        return T(f"{mode} | {header} | {masked_en}", f"{mode} | {header} | {masked_de}")

    def toggle_text(self, translator: Translator = None) -> str:
        T = lambda en, de=None: self._translate(translator, en, de)
        if not self.ready():
            return T("Configure...", "Konfigurieren...")
        return T("Disable", "Deaktivieren") if self.effective() else T("Enable", "Aktivieren")

    def log_message(self, translator: Translator = None) -> str:
        T = lambda en, de=None: self._translate(translator, en, de)
        mode = self._normalized_mode()
        if not self.ready():
            return T("Auth not configured.", "Auth nicht konfiguriert.")
        if not self.effective():
            return T(f"Auth disabled ({mode}).", f"Auth deaktiviert ({mode}).")
        headers = self.build_headers()
        if not headers:
            return T("Auth disabled.", "Auth deaktiviert.")
        active = "; ".join(f"{k}: ***" for k in headers)
        return T(f"Auth active: {active}", f"Auth aktiv: {active}")

    def compute(self, translator: Translator = None) -> AuthComputation:
        headers = self.build_headers()
        effective = self.effective()
        ready = self.ready()
        status = self.status_text(translator=translator)
        toggle = self.toggle_text(translator=translator)
        log = self.log_message(translator=translator)
        return AuthComputation(
            headers=headers,
            effective=effective,
            ready=ready,
            status=status,
            toggle=toggle,
            log=log,
        )
