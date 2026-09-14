import unittest

from citrix_probe.auth_detection import detect_auth_requirements


class AuthDetectionTests(unittest.TestCase):
    def test_detects_password_form(self) -> None:
        findings = detect_auth_requirements(
            '<form><input name="username"><input type="password"></form>',
            ["https://gateway.example.com/logon/LogonPoint/tmindex.html"],
        )

        self.assertEqual(findings["password"]["status"], "detected")
        self.assertEqual(findings["username"]["status"], "detected")

    def test_detects_microsoft_sso_and_mfa(self) -> None:
        findings = detect_auth_requirements(
            "Enter your verification code for multi-factor authentication",
            ["https://login.microsoftonline.com/tenant/oauth2/authorize"],
        )

        self.assertEqual(findings["sso"]["status"], "detected")
        self.assertEqual(findings["mfa_or_otp"]["status"], "detected")

    def test_detects_yubikey_and_epa(self) -> None:
        findings = detect_auth_requirements(
            "Run the Endpoint Analysis scan, then use your YubiKey security key",
            ["https://gateway.example.com/epa/scripts/nsepa.js"],
        )

        self.assertEqual(findings["epa_device_posture"]["status"], "detected")
        self.assertEqual(findings["security_key"]["status"], "detected")

    def test_does_not_claim_requirements_without_evidence(self) -> None:
        findings = detect_auth_requirements(
            "Citrix Gateway is available",
            ["https://gateway.example.com/"],
        )

        self.assertTrue(all(item["status"] == "not_observed" for item in findings.values()))


if __name__ == "__main__":
    unittest.main()
