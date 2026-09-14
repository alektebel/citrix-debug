# Citrix connection probe

This project captures evidence when a Citrix ADC/Gateway logon page works only
intermittently. It separates failures into DNS, TCP, TLS, and HTTP stages and
writes one JSON object per attempt, making successful and failed requests easy to
compare.

It does **not** log credentials, cookie values, authorization headers, or full
page bodies. Run it only against a gateway you are authorized to test.

## Simplest option: edit one file and run it

Open `quick_debug.py` and edit only the CONFIG section near the top:

```python
CITRIX_URL = "https://citrix.your-company.com/logon/LogonPoint/tmindex.html"
EPA_CERTIFICATE = ""  # Or: r"C:\Certificates\device.pfx"
EPA_PRIVATE_KEY = ""  # Only when a separate PEM key exists
CERTIFICATE_HAS_PASSWORD = False
ATTEMPTS = 5
```

Do not put an account password, 2FA code, or certificate password in the file.
If the PFX/P12 is protected, set `CERTIFICATE_HAS_PASSWORD = True`; the script
will prompt without displaying or saving the password.

After completing the installation below, run:

```bash
python quick_debug.py
```

It prints the result of DNS, TCP, TLS, and HTTP checks, then reports which
pre-login requirements it can see:

- Username and password
- 2FA, MFA, OTP, Duo, RSA SecurID, or authenticator
- SAML/OAuth/SSO and common identity-provider redirects
- YubiKey, WebAuthn, FIDO, or another security key
- Citrix EPA/device-posture resources
- A client/device certificate

These are conservative hints from the public pre-login flow. Citrix nFactor may
reveal later requirements only after the first factor succeeds, so
`not_observed` means “not visible yet,” not “definitely unnecessary.” The script
does not submit account credentials or 2FA codes and therefore cannot lock the
account or approve/bypass an authentication challenge.

## Windows PowerShell toolkit (no PFX required)

The scripts in `windows/` can use a certificate whose private key is already in
the Windows Certificate Store. They do not export the private key.

A certificate **thumbprint** is its hexadecimal identifier, for example
`A1B2C3D4...`. It is not a password, certificate body, or private key.

### Simplest PowerShell option

Open `windows\Run-Me.ps1` in Notepad and change:

```powershell
$CitrixUrl = "https://YOUR-HOST/logon/LogonPoint/tmindex.html"
$MaquinaCer = ".\maquina.cer"
```

Then right-click `Run-Me.ps1` and choose **Run with PowerShell**, or execute:

```powershell
powershell.exe -NoProfile -File .\windows\Run-Me.ps1
```

If `maquina.cer` is not beside the repository, put its complete path in
`$MaquinaCer`. If you do not have the file, set `$MaquinaCer = ""`; DNS, TCP,
HTTPS, and visible authentication tests will still run.

### Easiest test when you have `maquina.cer`

Open PowerShell in the repository and run:

```powershell
powershell.exe -NoProfile -File .\windows\Test-CitrixConnection.ps1 `
  -Url "https://YOUR-HOST/logon/LogonPoint/tmindex.html" `
  -CerFile ".\maquina.cer" `
  -Attempts 5
```

The script reads the thumbprint from `maquina.cer`, searches both the Current
User and Local Machine Personal stores, verifies that the installed match has a
private key, and then asks Windows `curl.exe`/Schannel to use it. No PFX or key
file is needed when the matching private key is installed in Windows.

### Find candidate certificates

```powershell
powershell.exe -NoProfile -File .\windows\Get-CitrixCertificates.ps1
```

Check whether `maquina.cer` matches an installed certificate:

```powershell
powershell.exe -NoProfile -File .\windows\Get-CitrixCertificates.ps1 `
  -CerFile ".\maquina.cer"
```

### Test only DNS, TCP, and proxy configuration

```powershell
powershell.exe -NoProfile -File .\windows\Test-CitrixNetwork.ps1 `
  -Url "https://YOUR-HOST/logon/LogonPoint/tmindex.html"
```

`Test-CitrixConnection.ps1` records safe JSONL evidence and reports visible
password, MFA/OTP, SSO, YubiKey/security-key, EPA/device-posture, and certificate
requirements. It never submits login credentials. If no installed certificate
with `HasPrivateKey = True` matches `maquina.cer`, IT must enroll or reissue the
device certificate; importing a public `.cer` cannot reconstruct its private key.

## Quick start

Python 3.10 or newer is required.

```bash
cd /home/diego/Documents/PwC/citrix
python3 -m venv .venv
. .venv/bin/activate              # Windows: .venv\Scripts\activate
python -m pip install -e .

citrix-probe https://citrix.example.com --count 30 --interval 5
```

## EPA/device client certificate

Citrix Gateway can request a device/client certificate during the TLS handshake,
before the EPA scan. Supply an exported PFX/P12 bundle like this:

```bash
citrix-probe https://citrix.example.com/logon/LogonPoint/tmindex.html \
  --client-cert ~/certificates/epa-device.pfx \
  --prompt-client-cert-password \
  --count 30
```

For unattended collection, keep the password out of shell history by placing it
in an environment variable and passing only that variable's name:

```bash
export EPA_CERT_PASSWORD='your-password'
citrix-probe citrix.example.com \
  --client-cert ~/certificates/epa-device.pfx \
  --client-cert-password-env EPA_CERT_PASSWORD \
  --count 30
unset EPA_CERT_PASSWORD
```

PEM files are also supported. If certificate and key are separate:

```bash
citrix-probe citrix.example.com \
  --client-cert epa-device.crt \
  --client-key epa-device.key \
  --prompt-client-cert-password
```

The log records only whether a client certificate was configured, its format,
SHA-256 fingerprint, and validity dates. It never records the password, private
key, certificate path, or certificate subject.

This validates the client-certificate TLS and HTTP path. It does not emulate the
full native Citrix EPA posture plug-in (antivirus, registry, device compliance,
and similar checks). Also, `--open-browser` cannot inject a file-based certificate
into the browser; install the certificate in the operating-system/browser store
if the browser must select it without prompting.

When only a hostname or base URL is supplied, the default endpoint is:

```text
/logon/LogonPoint/tmindex.html
```

If your deployment uses different capitalization or a different path, pass the
complete URL exactly as shown in the browser.

## Useful modes

Collect samples until the fault appears:

```bash
citrix-probe citrix.example.com --count 0 --interval 10
```

Require a stable piece of text from the real login page. This catches a load
balancer returning the wrong page with HTTP 200:

```bash
citrix-probe citrix.example.com --count 50 --expect "Citrix"
```

Wait for a healthy response and then open the system browser:

```bash
citrix-probe citrix.example.com --wait-until-ready --open-browser
```

Inspect one complete sample on screen:

```bash
citrix-probe citrix.example.com --verbose
```

If certificate verification is the suspected failure, make one comparison run
with `--insecure`. Do not use that flag as the permanent solution; it is intended
to prove whether trust, expiry, hostname, or an inconsistent certificate chain is
involved.

## Reading the result

Each console line identifies the first failing layer:

- `FAIL/dns`: resolver, VPN DNS, split DNS, or DNS availability.
- `FAIL/tcp`: routing, firewall, proxy bypass, port 443, or a dead backend path.
- `FAIL/tls`: expired/untrusted certificate, hostname mismatch, TLS interception,
  or inconsistent certificates across gateway nodes.
- `FAIL/http`: HTTP error, redirect loop, gateway/service error, or expected login
  marker missing.
- `OK`: the configured success criteria passed.

The JSONL evidence includes resolved address sets, selected peer IP, TLS version,
certificate fingerprint, redirects, response fingerprint, cookie **names**, and
timings. Compare fields between working and failed attempts. Different peer IPs,
certificate fingerprints, redirects, or response hashes are especially useful
when reporting a faulty load-balancer node to the Citrix/network team.

The HTTP probe honors the machine's normal proxy environment. The DNS/TCP/TLS
stages connect directly, which helps reveal proxy-versus-direct routing issues.

## Tests

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
```
