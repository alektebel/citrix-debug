from datetime import datetime, timedelta, timezone
from email.message import Message
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID

from citrix_probe.probe import (
    DEFAULT_PATH,
    ClientCertificateError,
    make_ssl_context,
    normalize_url,
    safe_headers,
    safe_url,
)


def create_test_certificate() -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "EPA test device")])
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    return key, certificate


class ProbeTests(unittest.TestCase):
    def test_normalize_url(self) -> None:
        cases = [
            ("gateway.example.com", f"https://gateway.example.com{DEFAULT_PATH}"),
            ("https://gateway.example.com", f"https://gateway.example.com{DEFAULT_PATH}"),
            (
                "https://gateway.example.com/logon/LogonPoint/tmindex.html?x=1#fragment",
                "https://gateway.example.com/logon/LogonPoint/tmindex.html?x=1",
            ),
        ]
        for value, expected in cases:
            with self.subTest(value=value):
                self.assertEqual(normalize_url(value), expected)

    def test_normalize_url_rejects_missing_host(self) -> None:
        with self.assertRaises(ValueError):
            normalize_url("https://")

    def test_safe_headers_redacts_secrets(self) -> None:
        headers = Message()
        headers["Content-Type"] = "text/html"
        headers["Set-Cookie"] = "secret=value"
        headers["Authorization"] = "Bearer secret"
        headers["Location"] = "https://example.com/next?ticket=secret"

        self.assertEqual(
            safe_headers(headers),
            {
                "Content-Type": "text/html",
                "Set-Cookie": "<redacted>",
                "Authorization": "<redacted>",
                "Location": "https://example.com/next?ticket=%3Credacted%3E",
            },
        )

    def test_safe_url_removes_credentials_and_query_values(self) -> None:
        self.assertEqual(
            safe_url("https://user:password@example.com:8443/path?token=secret&x=1"),
            "https://example.com:8443/path?token=%3Credacted%3E&x=%3Credacted%3E",
        )

    def test_loads_password_protected_pfx_without_logging_identity(self) -> None:
        key, certificate = create_test_certificate()
        bundle = pkcs12.serialize_key_and_certificates(
            b"epa-device",
            key,
            certificate,
            None,
            serialization.BestAvailableEncryption(b"test-password"),
        )
        with TemporaryDirectory() as directory:
            path = Path(directory) / "device.pfx"
            path.write_bytes(bundle)
            _, metadata = make_ssl_context(
                True, client_cert=path, client_cert_password="test-password"
            )

        self.assertTrue(metadata["configured"])
        self.assertEqual(metadata["format"], "PKCS#12")
        self.assertEqual(metadata["sha256"], certificate.fingerprint(hashes.SHA256()).hex())
        self.assertNotIn("EPA test device", str(metadata))
        self.assertNotIn("test-password", str(metadata))

    def test_rejects_incorrect_pfx_password(self) -> None:
        key, certificate = create_test_certificate()
        bundle = pkcs12.serialize_key_and_certificates(
            b"epa-device",
            key,
            certificate,
            None,
            serialization.BestAvailableEncryption(b"correct-password"),
        )
        with TemporaryDirectory() as directory:
            path = Path(directory) / "device.p12"
            path.write_bytes(bundle)
            with self.assertRaises(ClientCertificateError):
                make_ssl_context(
                    True, client_cert=path, client_cert_password="wrong-password"
                )


if __name__ == "__main__":
    unittest.main()
