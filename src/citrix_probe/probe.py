"""Network and HTTP probes for an intermittent Citrix logon endpoint."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import socket
import ssl
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from http.cookiejar import CookieJar
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import pkcs12

from .auth_detection import detect_auth_requirements


DEFAULT_PATH = "/logon/LogonPoint/tmindex.html"
REDACTED_HEADERS = {"authorization", "cookie", "proxy-authorization", "set-cookie"}


class ClientCertificateError(ValueError):
    """Raised when a client certificate cannot be loaded safely."""


def utc_now() -> str:
    """Return a stable UTC timestamp."""
    return datetime.now(timezone.utc).isoformat()


def normalize_url(value: str) -> str:
    """Accept a Citrix host, base URL, or complete endpoint URL."""
    candidate = value.strip()
    if "://" not in candidate:
        candidate = f"https://{candidate}"
    parsed = urllib.parse.urlsplit(candidate)
    if not parsed.hostname:
        raise ValueError(f"Invalid Citrix URL: {value!r}")
    path = parsed.path
    if not path or path == "/":
        path = DEFAULT_PATH
    return urllib.parse.urlunsplit(
        (parsed.scheme, parsed.netloc, path, parsed.query, "")
    )


def safe_url(value: str) -> str:
    """Keep URL structure while removing query values and user information."""
    parsed = urllib.parse.urlsplit(value)
    host = parsed.hostname or ""
    try:
        port = f":{parsed.port}" if parsed.port else ""
    except ValueError:
        port = ""
    netloc = f"{host}{port}"
    redacted_query = urllib.parse.urlencode(
        [(key, "<redacted>") for key, _ in urllib.parse.parse_qsl(parsed.query)]
    )
    return urllib.parse.urlunsplit(
        (parsed.scheme, netloc, parsed.path, redacted_query, "")
    )


def safe_headers(headers: Any) -> dict[str, str]:
    """Return response headers without authentication or cookie material."""
    result: dict[str, str] = {}
    for key, value in headers.items():
        lowered = key.lower()
        if lowered in REDACTED_HEADERS:
            result[key] = "<redacted>"
        elif lowered == "location":
            result[key] = safe_url(value)
        else:
            result[key] = value
    return result


def safe_proxy_map() -> dict[str, str]:
    """Report proxy routing without leaking embedded credentials."""
    result: dict[str, str] = {}
    for scheme, value in urllib.request.getproxies().items():
        parsed = urllib.parse.urlsplit(value)
        host = parsed.hostname or "configured"
        try:
            port = f":{parsed.port}" if parsed.port else ""
        except ValueError:
            port = ""
        result[scheme] = f"{parsed.scheme or scheme}://{host}{port}"
    return result


@dataclass
class Stage:
    """One diagnostic stage."""

    ok: bool
    elapsed_ms: float
    details: dict[str, Any] = field(default_factory=dict)
    error_type: str | None = None
    error: str | None = None


@dataclass
class ProbeResult:
    """One end-to-end sample."""

    timestamp: str
    target: str
    success: bool
    failure_stage: str | None
    total_ms: float
    dns: Stage
    tcp: Stage | None
    tls: Stage | None
    http: Stage | None
    environment: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        """Convert the sample to JSON-safe primitives."""
        return asdict(self)


class RecordingRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Track each hop while retaining urllib's redirect behavior."""

    def __init__(self) -> None:
        self.hops: list[dict[str, Any]] = []

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> urllib.request.Request | None:
        self.hops.append(
            {
                "status": code,
                "from": safe_url(req.full_url),
                "to": safe_url(newurl),
                "headers": safe_headers(headers),
            }
        )
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _timed_failure(start: float, exc: BaseException) -> Stage:
    return Stage(
        ok=False,
        elapsed_ms=round((time.perf_counter() - start) * 1000, 2),
        error_type=type(exc).__name__,
        error=str(exc),
    )


def probe_dns(host: str, port: int) -> Stage:
    """Resolve all IPv4 and IPv6 addresses for the target."""
    start = time.perf_counter()
    try:
        records = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        addresses = sorted({record[4][0] for record in records})
        return Stage(
            ok=bool(addresses),
            elapsed_ms=round((time.perf_counter() - start) * 1000, 2),
            details={"addresses": addresses, "count": len(addresses)},
        )
    except (socket.gaierror, OSError) as exc:
        return _timed_failure(start, exc)


def probe_tcp(host: str, port: int, timeout: float) -> Stage:
    """Open a TCP connection using the OS-selected resolved address."""
    start = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            peer = sock.getpeername()
        return Stage(
            ok=True,
            elapsed_ms=round((time.perf_counter() - start) * 1000, 2),
            details={"peer_ip": peer[0], "peer_port": peer[1]},
        )
    except (TimeoutError, socket.timeout, OSError) as exc:
        return _timed_failure(start, exc)


def _certificate_metadata(
    certificate: x509.Certificate, certificate_format: str
) -> dict[str, Any]:
    """Return useful identity data without exposing private material."""
    return {
        "configured": True,
        "format": certificate_format,
        "sha256": certificate.fingerprint(hashes.SHA256()).hex(),
        "not_before": certificate.not_valid_before_utc.isoformat(),
        "not_after": certificate.not_valid_after_utc.isoformat(),
    }


def _load_pkcs12_certificate(
    context: ssl.SSLContext, path: Path, password: str | None
) -> dict[str, Any]:
    try:
        private_key, certificate, chain = pkcs12.load_key_and_certificates(
            path.read_bytes(), password.encode() if password is not None else None
        )
    except (OSError, ValueError) as exc:
        raise ClientCertificateError(
            "Unable to load the PFX/P12 client certificate. Check the file and "
            "password; use --client-cert-password-env or "
            "--prompt-client-cert-password for a protected bundle."
        ) from exc
    if private_key is None or certificate is None:
        raise ClientCertificateError(
            "The PFX/P12 bundle must contain both a client certificate and private key."
        )

    key_bytes = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    cert_bytes = certificate.public_bytes(serialization.Encoding.PEM)
    cert_bytes += b"".join(
        item.public_bytes(serialization.Encoding.PEM) for item in (chain or [])
    )
    # SSLContext consumes the files during load_cert_chain. They are removed
    # before this function returns and are never written to the evidence log.
    with tempfile.TemporaryDirectory(prefix="citrix-probe-") as directory:
        cert_file = Path(directory) / "client-chain.pem"
        key_file = Path(directory) / "client-key.pem"
        cert_file.write_bytes(cert_bytes)
        key_file.write_bytes(key_bytes)
        cert_file.chmod(0o600)
        key_file.chmod(0o600)
        context.load_cert_chain(certfile=cert_file, keyfile=key_file)
    return _certificate_metadata(certificate, "PKCS#12")


def _load_pem_certificate(
    context: ssl.SSLContext,
    certificate_path: Path,
    key_path: Path | None,
    password: str | None,
) -> dict[str, Any]:
    try:
        context.load_cert_chain(
            certfile=certificate_path,
            keyfile=key_path,
            password=password,
        )
        certificate = x509.load_pem_x509_certificate(certificate_path.read_bytes())
    except (OSError, ValueError, ssl.SSLError) as exc:
        raise ClientCertificateError(
            "Unable to load the PEM client certificate/private key. Check the "
            "paths and password."
        ) from exc
    return _certificate_metadata(certificate, "PEM")


def make_ssl_context(
    verify_tls: bool,
    client_cert: Path | None = None,
    client_key: Path | None = None,
    client_cert_password: str | None = None,
) -> tuple[ssl.SSLContext, dict[str, Any]]:
    """Build the TLS context used by both TLS and HTTP probes."""
    if verify_tls:
        context = ssl.create_default_context()
    else:
        context = ssl._create_unverified_context()  # noqa: SLF001 - diagnostic mode

    if client_cert is None:
        if client_key is not None:
            raise ClientCertificateError("--client-key requires --client-cert")
        return context, {"configured": False}
    if not client_cert.is_file():
        raise ClientCertificateError("The client certificate file does not exist or is unreadable.")

    if client_cert.suffix.lower() in {".pfx", ".p12"}:
        if client_key is not None:
            raise ClientCertificateError("--client-key cannot be used with a PFX/P12 bundle")
        metadata = _load_pkcs12_certificate(context, client_cert, client_cert_password)
    else:
        if client_key is not None and not client_key.is_file():
            raise ClientCertificateError("The client key file does not exist or is unreadable.")
        metadata = _load_pem_certificate(
            context, client_cert, client_key, client_cert_password
        )
    return context, metadata


def probe_tls(
    host: str, port: int, timeout: float, context: ssl.SSLContext
) -> Stage:
    """Perform a TLS handshake and capture certificate identity metadata."""
    start = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with context.wrap_socket(raw, server_hostname=host) as secured:
                der_certificate = secured.getpeercert(binary_form=True) or b""
                certificate = secured.getpeercert() or {}
                peer = secured.getpeername()
                details = {
                    "peer_ip": peer[0],
                    "tls_version": secured.version(),
                    "cipher": secured.cipher()[0] if secured.cipher() else None,
                    "certificate_sha256": hashlib.sha256(der_certificate).hexdigest(),
                    "certificate_subject": certificate.get("subject"),
                    "certificate_issuer": certificate.get("issuer"),
                    "certificate_not_after": certificate.get("notAfter"),
                }
        return Stage(
            ok=True,
            elapsed_ms=round((time.perf_counter() - start) * 1000, 2),
            details=details,
        )
    except (TimeoutError, socket.timeout, OSError, ssl.SSLError) as exc:
        return _timed_failure(start, exc)


def probe_http(
    url: str,
    timeout: float,
    context: ssl.SSLContext,
    expected_text: str | None,
    max_body_bytes: int,
) -> Stage:
    """Follow the browser-like HTTP path and fingerprint the response."""
    start = time.perf_counter()
    redirect_handler = RecordingRedirectHandler()
    cookie_jar = CookieJar()
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(cookie_jar),
        redirect_handler,
        urllib.request.HTTPSHandler(context=context),
    )
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "CitrixConnectionProbe/0.1",
            "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
            "Cache-Control": "no-cache",
        },
    )
    try:
        with opener.open(request, timeout=timeout) as response:
            body = response.read(max_body_bytes)
            status = response.status
            final_url = response.url
            headers = safe_headers(response.headers)
        decoded = body.decode("utf-8", errors="replace")
        marker_found = expected_text in decoded if expected_text else None
        ok = status < 500 and marker_found is not False
        details = {
            "status": status,
            "reason": response.reason,
            "final_url": safe_url(final_url),
            "redirects": redirect_handler.hops,
            "response_headers": headers,
            "cookie_names": sorted({cookie.name for cookie in cookie_jar}),
            "body_bytes_read": len(body),
            "body_sha256": hashlib.sha256(body).hexdigest(),
            "expected_text": expected_text,
            "expected_text_found": marker_found,
            "auth_requirements": detect_auth_requirements(
                decoded,
                [url, final_url]
                + [hop["to"] for hop in redirect_handler.hops],
            ),
        }
        error = None if ok else "HTTP response did not meet the success criteria"
        return Stage(
            ok=ok,
            elapsed_ms=round((time.perf_counter() - start) * 1000, 2),
            details=details,
            error_type=None if ok else "UnexpectedResponse",
            error=error,
        )
    except urllib.error.HTTPError as exc:
        body = exc.read(max_body_bytes)
        decoded = body.decode("utf-8", errors="replace")
        return Stage(
            ok=False,
            elapsed_ms=round((time.perf_counter() - start) * 1000, 2),
            details={
                "status": exc.code,
                "reason": exc.reason,
                "final_url": safe_url(exc.url),
                "redirects": redirect_handler.hops,
                "response_headers": safe_headers(exc.headers),
                "body_bytes_read": len(body),
                "body_sha256": hashlib.sha256(body).hexdigest(),
                "auth_requirements": detect_auth_requirements(
                    decoded,
                    [url, exc.url]
                    + [hop["to"] for hop in redirect_handler.hops],
                ),
            },
            error_type=type(exc).__name__,
            error=str(exc),
        )
    except (urllib.error.URLError, TimeoutError, OSError, ssl.SSLError) as exc:
        return _timed_failure(start, exc)


def run_probe(
    target: str,
    *,
    timeout: float = 10.0,
    verify_tls: bool = True,
    expected_text: str | None = None,
    max_body_bytes: int = 1_000_000,
    client_cert: Path | None = None,
    client_key: Path | None = None,
    client_cert_password: str | None = None,
) -> ProbeResult:
    """Run each layer in order while preserving partial failure evidence."""
    started = time.perf_counter()
    url = normalize_url(target)
    parsed = urllib.parse.urlsplit(url)
    host = parsed.hostname
    if host is None:
        raise ValueError(f"URL has no host: {url}")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    context, client_certificate = make_ssl_context(
        verify_tls,
        client_cert=client_cert,
        client_key=client_key,
        client_cert_password=client_cert_password,
    )
    environment = {
        "hostname": socket.gethostname(),
        "platform": platform.platform(),
        "python": platform.python_version(),
        "proxy_routes": safe_proxy_map(),
        "no_proxy_configured": bool(os.environ.get("NO_PROXY") or os.environ.get("no_proxy")),
        "tls_verification": verify_tls,
        "client_certificate": client_certificate,
    }

    dns = probe_dns(host, port)
    tcp = probe_tcp(host, port, timeout) if dns.ok else None
    tls = (
        probe_tls(host, port, timeout, context)
        if tcp and tcp.ok and parsed.scheme == "https"
        else None
    )
    # The browser-like HTTP route may use a configured proxy, so run it even
    # when a direct DNS/TCP/TLS diagnostic fails.
    http = probe_http(url, timeout, context, expected_text, max_body_bytes)

    stages = (("dns", dns), ("tcp", tcp), ("tls", tls), ("http", http))
    success = http.ok
    failure_stage = (
        None
        if success
        else next(
            (name for name, stage in stages if stage is not None and not stage.ok),
            "http",
        )
    )
    return ProbeResult(
        timestamp=utc_now(),
        target=safe_url(url),
        success=success,
        failure_stage=failure_stage,
        total_ms=round((time.perf_counter() - started) * 1000, 2),
        dns=dns,
        tcp=tcp,
        tls=tls,
        http=http,
        environment=environment,
    )


def append_jsonl(path: Path, result: ProbeResult) -> None:
    """Append one atomic line suitable for long-running collection."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        json.dump(result.to_dict(), handle, sort_keys=True)
        handle.write("\n")
