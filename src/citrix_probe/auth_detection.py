"""Conservative authentication-requirement hints from public login responses."""

from __future__ import annotations

import re


RequirementMap = dict[str, dict[str, str | list[str]]]


def _has(pattern: str, value: str) -> bool:
    return re.search(pattern, value, flags=re.IGNORECASE) is not None


def detect_auth_requirements(page_text: str, urls: list[str]) -> RequirementMap:
    """Infer possible Citrix auth factors without submitting credentials.

    Results are hints from a pre-authentication page, not proof that a factor
    will be demanded for every user or policy branch.
    """
    url_text = "\n".join(urls)
    combined = f"{page_text}\n{url_text}"
    findings: RequirementMap = {
        "username": {"status": "not_observed", "evidence": []},
        "password": {"status": "not_observed", "evidence": []},
        "mfa_or_otp": {"status": "not_observed", "evidence": []},
        "sso": {"status": "not_observed", "evidence": []},
        "security_key": {"status": "not_observed", "evidence": []},
        "epa_device_posture": {"status": "not_observed", "evidence": []},
        "client_certificate": {"status": "not_observed", "evidence": []},
    }

    rules: dict[str, list[tuple[str, str]]] = {
        "username": [
            (r'name=["\'](?:username|login|user)["\']', "username field"),
            (r'\buser(?:name| name)\b', "username wording"),
        ],
        "password": [
            (r'type=["\']password["\']', "password input"),
            (r'\bpassword\b', "password wording"),
        ],
        "mfa_or_otp": [
            (r'\b(?:multi[- ]?factor|two[- ]?factor|2fa|mfa)\b', "MFA wording"),
            (r'\b(?:one[- ]?time (?:password|passcode)|otp|verification code)\b', "OTP wording"),
            (r'\b(?:duo|rsa securid|authenticator)\b', "MFA provider"),
        ],
        "sso": [
            (r'\b(?:saml|openid|oauth2?|single sign[- ]?on|sso)\b', "SSO protocol"),
            (r'(?:login\.microsoftonline\.com|okta\.com|adfs|pingidentity)', "identity-provider redirect"),
        ],
        "security_key": [
            (r'\b(?:yubikey|yubi key|webauthn|fido2?)\b', "security-key protocol/device"),
            (r'\bsecurity key\b', "security-key wording"),
        ],
        "epa_device_posture": [
            (r'\b(?:endpoint analysis|device posture|epa scan|epa client)\b', "EPA wording"),
            (r'(?:\bnsepa\b|/epa/|epaclient)', "EPA resource"),
        ],
        "client_certificate": [
            (r'\b(?:client|device) certificate\b', "client-certificate wording"),
            (r'\bsmart ?card\b', "smart-card wording"),
        ],
    }

    for requirement, patterns in rules.items():
        evidence = [label for pattern, label in patterns if _has(pattern, combined)]
        if evidence:
            findings[requirement] = {"status": "detected", "evidence": evidence}
    return findings
