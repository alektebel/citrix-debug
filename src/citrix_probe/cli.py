"""Command-line entry point for Citrix connection diagnostics."""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
import time
import webbrowser
from collections import Counter
from pathlib import Path

from .probe import (
    ClientCertificateError,
    ProbeResult,
    append_jsonl,
    normalize_url,
    run_probe,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="citrix-probe",
        description="Repeatedly diagnose a Citrix logon endpoint by network layer.",
    )
    parser.add_argument("target", help="Gateway hostname, base URL, or full logon URL")
    parser.add_argument("--count", type=int, default=1, help="Number of probes; 0 runs forever")
    parser.add_argument("--interval", type=float, default=5.0, help="Seconds between probes")
    parser.add_argument("--timeout", type=float, default=10.0, help="Timeout per network operation")
    parser.add_argument("--output", type=Path, default=Path("citrix-probe.jsonl"))
    parser.add_argument(
        "--expect",
        help="Text that must appear in the first 1 MB of the final response",
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Continue without certificate verification (diagnostics only)",
    )
    parser.add_argument(
        "--client-cert",
        type=Path,
        help="EPA/client certificate as PFX, P12, or PEM",
    )
    parser.add_argument(
        "--client-key",
        type=Path,
        help="Private-key PEM when it is separate from --client-cert",
    )
    password_group = parser.add_mutually_exclusive_group()
    password_group.add_argument(
        "--client-cert-password-env",
        metavar="ENV_NAME",
        help="Read the certificate password from this environment variable",
    )
    password_group.add_argument(
        "--prompt-client-cert-password",
        action="store_true",
        help="Securely prompt for the certificate password",
    )
    parser.add_argument(
        "--wait-until-ready",
        action="store_true",
        help="Run until one successful probe, ignoring --count",
    )
    parser.add_argument(
        "--open-browser",
        action="store_true",
        help="Open the endpoint after --wait-until-ready succeeds",
    )
    parser.add_argument("--verbose", action="store_true", help="Print complete JSON samples")
    return parser


def validate_args(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    if args.count < 0:
        parser.error("--count must be 0 or greater")
    if args.interval < 0:
        parser.error("--interval must be 0 or greater")
    if args.timeout <= 0:
        parser.error("--timeout must be greater than 0")
    if args.open_browser and not args.wait_until_ready:
        parser.error("--open-browser requires --wait-until-ready")
    if args.client_key and not args.client_cert:
        parser.error("--client-key requires --client-cert")
    if (args.client_cert_password_env or args.prompt_client_cert_password) and not args.client_cert:
        parser.error("certificate password options require --client-cert")


def get_client_certificate_password(
    parser: argparse.ArgumentParser, args: argparse.Namespace
) -> str | None:
    """Resolve a password without accepting it on the command line."""
    if args.client_cert_password_env:
        try:
            return os.environ[args.client_cert_password_env]
        except KeyError:
            parser.error(
                f"environment variable {args.client_cert_password_env!r} is not set"
            )
    if args.prompt_client_cert_password:
        return getpass.getpass("EPA/client certificate password: ")
    return None


def concise_line(index: int, result: ProbeResult) -> str:
    state = "OK" if result.success else f"FAIL/{result.failure_stage or 'unknown'}"
    http_status = result.http.details.get("status") if result.http else "-"
    peer = "-"
    if result.tls:
        peer = result.tls.details.get("peer_ip", "-")
    elif result.tcp:
        peer = result.tcp.details.get("peer_ip", "-")
    return (
        f"[{index:04d}] {result.timestamp} {state} "
        f"http={http_status} peer={peer} total={result.total_ms:.2f}ms"
    )


def print_summary(results: list[ProbeResult], output: Path) -> None:
    failures = Counter(result.failure_stage or "success" for result in results)
    successes = sum(result.success for result in results)
    print(
        f"Summary: {successes}/{len(results)} successful; "
        f"outcomes={dict(failures)}; evidence={output.resolve()}"
    )


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    validate_args(parser, args)
    client_cert_password = get_client_certificate_password(parser, args)
    target = normalize_url(args.target)
    results: list[ProbeResult] = []
    index = 0

    print(f"Probing {target}; TLS verification={'off' if args.insecure else 'on'}")
    try:
        while args.wait_until_ready or args.count == 0 or index < args.count:
            index += 1
            try:
                result = run_probe(
                    target,
                    timeout=args.timeout,
                    verify_tls=not args.insecure,
                    expected_text=args.expect,
                    client_cert=args.client_cert,
                    client_key=args.client_key,
                    client_cert_password=client_cert_password,
                )
            except ClientCertificateError as exc:
                print(f"Client certificate error: {exc}", file=sys.stderr)
                return 2
            results.append(result)
            append_jsonl(args.output, result)
            print(json.dumps(result.to_dict(), indent=2) if args.verbose else concise_line(index, result))

            if args.wait_until_ready and result.success:
                if args.open_browser:
                    webbrowser.open(target)
                break
            if not args.wait_until_ready and args.count != 0 and index >= args.count:
                break
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\nStopped by user.")

    if results:
        print_summary(results, args.output)
    return 0 if results and results[-1].success else 1


if __name__ == "__main__":
    sys.exit(main())
