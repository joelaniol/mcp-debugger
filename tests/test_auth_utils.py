import unittest

from auth_utils import AuthState


class AuthStateTests(unittest.TestCase):
    def test_defaults_not_ready(self):
        state = AuthState()
        result = state.compute()
        self.assertFalse(result.ready)
        self.assertFalse(result.effective)
        self.assertEqual(result.headers, {})
        self.assertEqual(result.status, "Not configured")
        self.assertEqual(result.toggle, "Configure...")
        self.assertEqual(result.log, "Auth not configured.")

    def test_bearer_enabled(self):
        state = AuthState(mode="Bearer", token="abc12345", enabled=True)
        result = state.compute()
        self.assertTrue(result.ready)
        self.assertTrue(result.effective)
        self.assertEqual(result.headers, {"Authorization": "Bearer abc12345"})
        self.assertEqual(result.status, "Bearer | Authorization | abc1...")
        self.assertEqual(result.toggle, "Disable")
        self.assertEqual(result.log, "Auth active: Authorization: ***")

    def test_bearer_disabled(self):
        state = AuthState(mode="Bearer", token="abc12345", enabled=False)
        result = state.compute()
        self.assertTrue(result.ready)
        self.assertFalse(result.effective)
        self.assertEqual(result.headers, {})
        self.assertEqual(result.status, "Bearer: disabled")
        self.assertEqual(result.toggle, "Enable")
        self.assertEqual(result.log, "Auth disabled (Bearer).")

    def test_custom_header_trim_and_mask(self):
        state = AuthState(mode="Custom header", token=" secret token ", header=" X-API ", enabled=True)
        result = state.compute()
        self.assertTrue(result.ready)
        self.assertTrue(result.effective)
        self.assertEqual(result.headers, {"X-API": "secret token"})
        self.assertEqual(result.status, "Custom header | X-API | secr...")
        self.assertEqual(result.toggle, "Disable")

    def test_enabled_without_token_is_not_ready(self):
        state = AuthState(mode="Bearer", token="   ", enabled=True)
        result = state.compute()
        self.assertFalse(result.ready)
        self.assertFalse(result.effective)
        self.assertEqual(result.headers, {})
        self.assertEqual(result.status, "Not configured")
        self.assertEqual(result.toggle, "Configure...")

    def test_translator_returns_german_strings(self):
        translator = lambda en, de=None: de or en
        state = AuthState(mode="Bearer", token="abc12345", enabled=False)
        result = state.compute(translator=translator)
        self.assertEqual(result.status, "Bearer: deaktiviert")
        self.assertEqual(result.toggle, "Aktivieren")
        self.assertEqual(result.log, "Auth deaktiviert (Bearer).")


if __name__ == "__main__":
    unittest.main()
