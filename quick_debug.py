"""Edit the CONFIG section, then run: python quick_debug.py"""

from __future__ import annotations

import getpass
import sys
import time
import webbrowser
from pathlib import Path
from typing import Any

from citrix_probe.probe import ClientCertificateError, append_jsonl, run_probe


# ---------------------------------------------------------------------------
# CONFIG: edit these values. Do not paste passwords or 2FA codes into this file.
# ---------------------------------------------------------------------------
CITRIX_URL = "https://YOUR-CITRIX-HOST/logon/LogonPoint/tmindex.html"
EPA_CERTIFICATE = ""  # Example: r"C:\Certificates\maquina.pfx"
EPA_PRIVATE_KEY = ""  # Only for a separate PEM .key file
CERTIFICATE_HAS_PASSWORD = False
ATTEMPTS = 5
SECONDS_BETWEEN_ATTEMPTS = 5.0
TIMEOUT_SECONDS = 10.0
EXPECTED_PAGE_TEXT = ""  # Optional stable text, such as "Citrix"
OPEN_BROWSER_WHEN_REACHABLE = False
OUTPUT_FILE = "citrix-quick-debug.jsonl"
# ---------------------------------------------------------------------------


LABELS = {
    "username": "Username",
    "password": "Password",
    "mfa_or_otp": "2FA / MFA / OTP",
    "sso": "SSO / identity provider",
    "security_key": "YubiKey / security key",
    "epa_device_posture": "EPA / device posture",
    "client_certificate": "Client/device certificate",
}


def stage_line(name: str, stage: Any) -> str:
    if stage is None:
        return f"  {name:<5} NOT RUN"
    state = "OK" if stage.ok else f"FAILED ({stage.error_type})"
    return f"  {name:<5} {state:<24} {stage.elapsed_ms:>9.2f} ms"


def certificate_requirement(result: Any) -> tuple[str, list[str]]:
    configured = result.environment["client_certificate"]["configured"]
    errors = " ".join(
        stage.error or ""
        for stage in (result.tls, result.http)
        if stage is not None
    ).lower()
    if configured and result.tls and result.tls.ok:
        return "supplied", ["certificate loaded and TLS handshake completed"]
    if "certificate required" in errors or "certificate unknown" in errors:
        return "detected", ["TLS peer requested/rejected a client certificate"]
    if configured:
        return "supplied_unconfirmed", ["certificate loaded; TLS did not complete"]
    return "not_observed", []


def print_report(result: Any) -> None:
    print("\nConnection layers")
    print(stage_line("DNS", result.dns))
    print(stage_line("TCP", result.tcp))
    print(stage_line("TLS", result.tls))
    print(stage_line("HTTP", result.http))

    findings = (
        result.http.details.get("auth_requirements", {}) if result.http else {}
    )
    certificate_status, certificate_evidence = certificate_requirement(result)
    findings["client_certificate"] = {
        "status": certificate_status,
        "evidence": certificate_evidence,
    }

    print("\nAuthentication requirements visible before login")
    for key, label in LABELS.items():
        finding = findings.get(key, {"status": "not_observed", "evidence": []})
        evidence = ", ".join(finding["evidence"])
        suffix = f" — {evidence}" if evidence else ""
        print(f"  {label:<28} {finding['status']}{suffix}")

    print("\nInterpretation")
    if result.success:
        print("  The public Citrix connection path is reachable.")
    else:
        print(f"  The connection failed first at: {result.failure_stage or 'unknown'}.")
    print("  'not_observed' does not prove a factor is unnecessary; Citrix may")
    print("  reveal additional factors only after username/password or SSO.")
    print("  This tool does not submit passwords, 2FA codes, or bypass EPA.")


def main() -> int:
    if "YOUR-CITRIX-HOST" in CITRIX_URL:
        print("Edit CITRIX_URL in quick_debug.py before running it.", file=sys.stderr)
        return 2
    if ATTEMPTS < 1:
        print("ATTEMPTS must be at least 1.", file=sys.stderr)
        return 2

    certificate = Path(EPA_CERTIFICATE).expanduser() if EPA_CERTIFICATE else None
    private_key = Path(EPA_PRIVATE_KEY).expanduser() if EPA_PRIVATE_KEY else None
    password = (
        getpass.getpass("EPA/client certificate password: ")
        if certificate and CERTIFICATE_HAS_PASSWORD
        else None
    )
    output = Path(OUTPUT_FILE)
    last_result = None

    for attempt in range(1, ATTEMPTS + 1):
        print(f"\nAttempt {attempt}/{ATTEMPTS}: {CITRIX_URL}")
        try:
            last_result = run_probe(
                CITRIX_URL,
                timeout=TIMEOUT_SECONDS,
                expected_text=EXPECTED_PAGE_TEXT or None,
                client_cert=certificate,
                client_key=private_key,
                client_cert_password=password,
            )
        except ClientCertificateError as exc:
            print(f"Certificate error: {exc}", file=sys.stderr)
            return 2
        append_jsonl(output, last_result)
        state = "OK" if last_result.success else f"FAIL/{last_result.failure_stage}"
        print(f"Result: {state}; {last_result.total_ms:.2f} ms")
        if attempt < ATTEMPTS:
            time.sleep(SECONDS_BETWEEN_ATTEMPTS)

    if last_result is None:
        return 1
    print_report(last_result)
    print(f"\nDetailed evidence: {output.resolve()}")
    if last_result.success and OPEN_BROWSER_WHEN_REACHABLE:
        webbrowser.open(CITRIX_URL)
    return 0 if last_result.success else 1


if __name__ == "__main__":
    raise SystemExit(main())
