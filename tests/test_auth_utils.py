import unittest

from auth_utils import AuthState


class AuthStateTests(unittest.TestCase):
    def test_defaults_not_ready(self):
        state = AuthState()
        result = state.compute()
        self.assertFalse(result.ready)
        self.assertFalse(result.effective)
        self.assertEqual(result.headers, {})
        self.assertEqual(result.status, "Nicht konfiguriert")
        self.assertEqual(result.toggle, "Konfigurieren…")
        self.assertEqual(result.log, "Auth nicht konfiguriert.")

    def test_bearer_enabled(self):
        state = AuthState(mode="Bearer", token="abc12345", enabled=True)
        result = state.compute()
        self.assertTrue(result.ready)
        self.assertTrue(result.effective)
        self.assertEqual(result.headers, {"Authorization": "Bearer abc12345"})
        self.assertEqual(result.status, "Bearer · Authorization · abc1…")
        self.assertEqual(result.toggle, "Deaktivieren")
        self.assertEqual(result.log, "Auth aktiv: Authorization: ***")

    def test_bearer_disabled(self):
        state = AuthState(mode="Bearer", token="abc12345", enabled=False)
        result = state.compute()
        self.assertTrue(result.ready)
        self.assertFalse(result.effective)
        self.assertEqual(result.headers, {})
        self.assertEqual(result.status, "Bearer: deaktiviert")
        self.assertEqual(result.toggle, "Aktivieren")
        self.assertEqual(result.log, "Auth deaktiviert (Bearer).")

    def test_custom_header_trim_and_mask(self):
        state = AuthState(mode="Custom header", token=" secret token ", header=" X-API ", enabled=True)
        result = state.compute()
        self.assertTrue(result.ready)
        self.assertTrue(result.effective)
        self.assertEqual(result.headers, {"X-API": "secret token"})
        self.assertEqual(result.status, "Custom header · X-API · secr…")
        self.assertEqual(result.toggle, "Deaktivieren")

    def test_enabled_without_token_is_not_ready(self):
        state = AuthState(mode="Bearer", token="   ", enabled=True)
        result = state.compute()
        self.assertFalse(result.ready)
        self.assertFalse(result.effective)
        self.assertEqual(result.headers, {})
        self.assertEqual(result.status, "Nicht konfiguriert")
        self.assertEqual(result.toggle, "Konfigurieren…")


if __name__ == "__main__":
    unittest.main()
