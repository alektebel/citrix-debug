# Citrix connection debugger

Evidence-first diagnostics for an intermittent Citrix ADC/Gateway logon page,
especially `/logon/LogonPoint/tmindex.html`.

The toolkit separates DNS, TCP, TLS, HTTP, certificate, proxy, redirect, and
visible authentication requirements. Repeated samples help identify a bad
load-balancer node, changing certificate, slow route, redirect problem, or
EPA/client-certificate failure.

> Run these tools only against a gateway you are authorized to test. They do
> not submit passwords or 2FA codes, approve MFA, or bypass EPA.

## Choose the right tool

| Situation | Recommended tool |
|---|---|
| Windows, easiest edit-and-run workflow | `windows\Run-Me.ps1` |
| Windows private key is installed but not exportable | `windows\Test-CitrixConnection.ps1` |
| Find EPA/client certificates in Windows | `windows\Get-CitrixCertificates.ps1` |
| Test only DNS, TCP, and proxy configuration | `windows\Test-CitrixNetwork.ps1` |
| Windows/Linux/macOS with PFX/P12 or PEM files | `citrix-probe` |
| Simple editable Python configuration | `quick_debug.py` |

The Windows route is recommended when Citrix uses a certificate installed in
the Windows Certificate Store. Python cannot directly use a non-exportable
Windows private key; PowerShell delegates HTTPS to Windows `curl.exe`/Schannel.

## Windows: fastest start

First installation:

```powershell
git clone https://github.com/alektebel/citrix-debug.git
cd citrix-debug
```

Update an existing installation:

```powershell
cd citrix-debug
git pull
```

Open `windows\Run-Me.ps1` in Notepad and change:

```powershell
$CitrixUrl = "https://YOUR-HOST/logon/LogonPoint/tmindex.html"
$MaquinaCer = ".\maquina.cer"
$Attempts = 5
$SecondsBetweenAttempts = 5
```

- Use the exact URL and capitalization shown by the browser.
- Place `maquina.cer` in the repository root, or enter its complete path.
- If it is unavailable, set `$MaquinaCer = ""`.
- Never paste passwords, 2FA codes, certificate contents, or private keys.

Run:

```powershell
powershell.exe -NoProfile -File .\windows\Run-Me.ps1
```

Evidence is written to `citrix-windows-debug.jsonl`. If company policy blocks
unsigned PowerShell scripts, do not bypass it; ask IT to approve or sign them.

## PowerShell command reference

Complete test without a certificate:

```powershell
powershell.exe -NoProfile -File .\windows\Test-CitrixConnection.ps1 `
  -Url "https://YOUR-HOST/logon/LogonPoint/tmindex.html" `
  -Attempts 5 -IntervalSeconds 5
```

Complete test using `maquina.cer`:

```powershell
powershell.exe -NoProfile -File .\windows\Test-CitrixConnection.ps1 `
  -Url "https://YOUR-HOST/logon/LogonPoint/tmindex.html" `
  -CerFile ".\maquina.cer" `
  -Attempts 10 -IntervalSeconds 5 -TimeoutSeconds 15
```

The `.cer` supplies a thumbprint, not a private key. The script uses the
thumbprint to find the matching certificate/private key in `CurrentUser\MY` or
`LocalMachine\MY`.

Complete test using a known thumbprint:

```powershell
powershell.exe -NoProfile -File .\windows\Test-CitrixConnection.ps1 `
  -Url "https://YOUR-HOST/logon/LogonPoint/tmindex.html" `
  -Thumbprint "A1B2C3D4_REPLACE_WITH_REAL_VALUE" `
  -StoreLocation CurrentUser -Attempts 5
```

A certificate **thumbprint** is its hexadecimal identifier. It is not a
password or private key. Valid stores are `Auto`, `CurrentUser`, and
`LocalMachine`.

Write evidence to a specific file:

```powershell
New-Item -ItemType Directory -Path .\evidence -Force
powershell.exe -NoProfile -File .\windows\Test-CitrixConnection.ps1 `
  -Url "https://YOUR-HOST/logon/LogonPoint/tmindex.html" `
  -Attempts 30 -OutputFile ".\evidence\citrix-morning.jsonl"
```

List usable Windows certificates:

```powershell
powershell.exe -NoProfile -File .\windows\Get-CitrixCertificates.ps1
```

Relevant entries normally show `HasPrivateKey: True`, `ClientAuthEKU: True`,
and a future `NotAfter` date.

Match `maquina.cer` to the Windows store:

```powershell
powershell.exe -NoProfile -File .\windows\Get-CitrixCertificates.ps1 `
  -CerFile ".\maquina.cer"
```

Include expired certificates:

```powershell
powershell.exe -NoProfile -File .\windows\Get-CitrixCertificates.ps1 `
  -IncludeExpired
```

Test only DNS, TCP, and proxy configuration:

```powershell
powershell.exe -NoProfile -File .\windows\Test-CitrixNetwork.ps1 `
  -Url "https://YOUR-HOST/logon/LogonPoint/tmindex.html" `
  -TimeoutSeconds 10
```

## Native Windows debugging helpers

```powershell
# Resolve every gateway address
Resolve-DnsName YOUR-HOST

# Test port 443
Test-NetConnection YOUR-HOST -Port 443 -InformationLevel Detailed

# Show WinHTTP proxy configuration
netsh.exe winhttp show proxy

# Confirm that Windows curl uses Schannel
curl.exe --version

# Inspect public metadata in maquina.cer
certutil.exe -dump .\maquina.cer

# Show recent Windows TLS/Schannel errors
Get-WinEvent -FilterHashtable @{ LogName = "System"; ProviderName = "Schannel" } `
  -MaxEvents 20 |
  Select-Object TimeCreated, Id, LevelDisplayName, Message |
  Format-List
```

`Schannel` must appear in `curl.exe --version` when using a private key from the
Windows Certificate Store.

## Python installation

Python 3.10 or newer is required.

Linux/macOS:

```bash
git clone https://github.com/alektebel/citrix-debug.git
cd citrix-debug
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
```

Windows PowerShell:

```powershell
git clone https://github.com/alektebel/citrix-debug.git
cd citrix-debug
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e .
```

## Python command reference

One detailed test:

```bash
citrix-probe "https://YOUR-HOST/logon/LogonPoint/tmindex.html" --verbose
```

Repeated intermittent-failure test:

```bash
citrix-probe "https://YOUR-HOST/logon/LogonPoint/tmindex.html" \
  --count 50 --interval 5 --timeout 15 \
  --output citrix-evening.jsonl
```

Run until `Ctrl+C`:

```bash
citrix-probe YOUR-HOST --count 0 --interval 10
```

When only a hostname/base URL is supplied, the default path is
`/logon/LogonPoint/tmindex.html`.

Require stable text from the real login page:

```bash
citrix-probe YOUR-HOST --count 30 --expect "Citrix"
```

This catches a load balancer returning the wrong page with HTTP 200.

Wait until reachable and open the browser:

```bash
citrix-probe YOUR-HOST --wait-until-ready --open-browser
```

Opening the browser does not inject a file-based certificate. Install it in the
operating-system/browser store if the browser requires it.

Use a PFX/P12 client certificate:

```bash
citrix-probe YOUR-HOST \
  --client-cert /path/to/device.pfx \
  --prompt-client-cert-password --count 10
```

Unattended certificate-password handling:

```bash
export EPA_CERT_PASSWORD='certificate-password'
citrix-probe YOUR-HOST \
  --client-cert /path/to/device.pfx \
  --client-cert-password-env EPA_CERT_PASSWORD --count 30
unset EPA_CERT_PASSWORD
```

Do not commit the environment variable or password.

Use separate PEM certificate/key files:

```bash
citrix-probe YOUR-HOST \
  --client-cert /path/to/device.crt \
  --client-key /path/to/device.key \
  --prompt-client-cert-password
```

Typical PEM markers are `BEGIN CERTIFICATE`, `BEGIN PRIVATE KEY`,
`BEGIN ENCRYPTED PRIVATE KEY`, or `BEGIN RSA PRIVATE KEY`. A file containing
only `BEGIN CERTIFICATE` has no private key. Never share private-key contents.

Certificate-verification comparison:

```bash
citrix-probe YOUR-HOST --insecure --verbose
```

Use `--insecure` for one controlled comparison only. If it succeeds while the
normal command fails, investigate trust, hostname, expiry, chain, or TLS
inspection. Never use it as a permanent fix.

Simple editable Python runner:

```python
# Edit the CONFIG section in quick_debug.py
CITRIX_URL = "https://YOUR-HOST/logon/LogonPoint/tmindex.html"
EPA_CERTIFICATE = ""  # Or a PFX/P12/PEM path
EPA_PRIVATE_KEY = ""  # Only for a separate PEM key
CERTIFICATE_HAS_PASSWORD = False
ATTEMPTS = 5
```

```bash
python quick_debug.py
```

## Complete `citrix-probe` options

| Option | Meaning |
|---|---|
| `target` | Hostname, base URL, or complete logon URL |
| `--count N` | Attempts; `0` means run forever |
| `--interval SECONDS` | Delay between attempts |
| `--timeout SECONDS` | Timeout per network operation |
| `--output FILE` | JSONL evidence destination |
| `--expect TEXT` | Text required in the first 1 MB |
| `--verbose` | Print complete sanitized samples |
| `--client-cert FILE` | PFX, P12, or PEM certificate |
| `--client-key FILE` | Separate PEM private key |
| `--prompt-client-cert-password` | Secure password prompt |
| `--client-cert-password-env NAME` | Read password from named variable |
| `--wait-until-ready` | Continue until one success |
| `--open-browser` | Open browser after readiness |
| `--insecure` | Disable server-certificate verification for diagnosis only |

```bash
citrix-probe --help
```

## Authentication findings

| Finding | Signals inspected |
|---|---|
| Username/password | Login fields and wording |
| 2FA/MFA/OTP | Verification code, authenticator, Duo, RSA SecurID, MFA wording |
| SSO | SAML, OAuth, OpenID, Microsoft, Okta, ADFS, Ping resources/redirects |
| YubiKey/security key | YubiKey, WebAuthn, FIDO, security-key wording |
| EPA/device posture | Endpoint Analysis, device posture, `nsepa`, EPA resources |
| Client certificate | Certificate/smart-card wording or supplied certificate |

`detected` means a signal was visible. `not observed` does not prove the factor
is unnecessary: Citrix nFactor can reveal later factors only after an earlier
stage succeeds. Full antivirus, registry, file, OS, and device-compliance checks
remain the native Citrix EPA client's responsibility.

## Failure and troubleshooting matrix

| Result | Meaning | Likely causes | Next checks |
|---|---|---|---|
| `FAIL/dns` / `DNS: FAILED` | Name did not resolve | VPN/split DNS, wrong host, resolver outage | `Resolve-DnsName`; compare networks; reconnect approved VPN |
| `FAIL/tcp` / `TCP: FAILED` | Port was unreachable | Firewall, route, proxy bypass, dead address | `Test-NetConnection -Port 443`; compare returned IPs |
| `FAIL/tls` | TLS handshake failed | Server trust/expiry/name, TLS inspection, client cert rejected | Schannel events; fingerprints; one `--insecure` comparison |
| `FAIL/http` | HTTP criteria failed | 4xx/5xx, redirect loop, wrong page/backend | `--verbose`; inspect status/redirects; verify `--expect` |
| HTTP 401 | Authentication required/rejected | Missing or incorrect factor/policy | Use supported client; confirm factors with IT |
| HTTP 403 | Request denied | EPA/certificate/source-network/authorization policy | Compare native EPA; check certificate/device compliance |
| HTTP 404 | Path missing | Wrong path/capitalization | Copy exact browser URL; verify `LogonPoint` case |
| HTTP 407 | Proxy authentication required | Corporate proxy needs authentication | Inspect WinHTTP and user proxy settings |
| HTTP 429 | Rate limited | Probe interval too short | Stop and increase the interval |
| HTTP 500 | Gateway/application error | Citrix policy/script/backend error | Record time, peer IP, request ID; escalate |
| HTTP 502/503/504 | Upstream unavailable/timeout | StoreFront/backend node, load balancer, network | Group failures by peer IP |
| Expected text false | Reachable, but wrong content | Maintenance/error page, changed text, wrong backend | Inspect manually; correct `--expect` if appropriate |
| Certificate not installed | `.cer` has no store match | Device not enrolled, wrong store, replaced certificate | Run certificate finder; ask IT to enroll/reissue |
| `HasPrivateKey: False` | Public certificate only | Only `.cer` was imported | Do not recreate a key; use approved enrollment/PFX |
| Certificate expired | Identity is no longer valid | Renewal/enrollment failed | Ask IT to renew; do not change system time |
| `Client certificate error` | Python could not load identity | Wrong password/path, missing/mismatched key | Inspect PEM markers or use approved PFX |
| Browser works, Python fails | Browser has integrations Python lacks | Store key, PAC proxy, integrated auth, native EPA | Prefer PowerShell/Schannel and native EPA |
| Success depends on peer IP | Selected node changes outcome | Bad gateway/load-balancer/backend node | Compare IP, body hash, cert fingerprint, redirects |

### Common curl exit codes

| Code | Meaning | Next step |
|---|---|---|
| `6` | Could not resolve host | Check DNS/VPN/hostname |
| `7` | Could not connect | Check route/firewall/proxy/443 |
| `28` | Timed out | Compare peer IPs/network; increase timeout once |
| `35` | TLS handshake failed | Check Schannel, interception, client certificate |
| `47` | Too many redirects | Investigate authentication-policy loop |
| `58` | Local client-certificate problem | Check store, key, thumbprint, Schannel |
| `60` | Server certificate not verified | Check hostname, issuer, chain, expiry, corporate CA |

## Exit codes

| Tool | `0` | `1` | `2` | `3` |
|---|---|---|---|---|
| `citrix-probe` / `quick_debug.py` | Final attempt succeeded | Failed/no final success | Arguments/config/certificate error | — |
| `Test-CitrixConnection.ps1` | All attempts passed | At least one failed | URL/certificate/curl/backend setup error | — |
| `Get-CitrixCertificates.ps1` | Candidate/match found | No usable candidate | Reference not installed | Match has no key |
| `Test-CitrixNetwork.ps1` | DNS/TCP passed | DNS/TCP failed | Invalid URL | — |

## Reading JSONL evidence

Show Windows attempts:

```powershell
Get-Content .\citrix-windows-debug.jsonl |
  ForEach-Object { $_ | ConvertFrom-Json } |
  Format-Table timestamp, attempt, dns_ok, tcp_ok, http_ok, http_status, remote_ip, total_ms
```

Group by peer IP/status:

```powershell
Get-Content .\citrix-windows-debug.jsonl |
  ForEach-Object { $_ | ConvertFrom-Json } |
  Group-Object remote_ip, http_status |
  Sort-Object Count -Descending |
  Format-Table Count, Name
```

Show failures only:

```powershell
Get-Content .\citrix-windows-debug.jsonl |
  ForEach-Object { $_ | ConvertFrom-Json } |
  Where-Object { -not $_.dns_ok -or -not $_.tcp_ok -or -not $_.http_ok } |
  Format-List
```

Summarize Python failure stages:

```bash
python - <<'PY'
import collections
import json

counts = collections.Counter()
with open("citrix-probe.jsonl", encoding="utf-8") as evidence:
    for line in evidence:
        sample = json.loads(line)
        counts[sample.get("failure_stage") or "success"] += 1
print(dict(counts))
PY
```

Compare working/failing samples by DNS addresses, peer IP, TLS version/cipher,
server-certificate fingerprint, status, redirect, body fingerprint, timing, and
client-certificate state.

## Evidence to send to IT

Provide:

1. Gateway hostname/path without secret query values.
2. Date, time, timezone, network, and VPN state.
3. JSONL samples containing successes and failures.
4. DNS addresses and peer IP for each failure.
5. First failing layer plus HTTP/curl error code.
6. Server-certificate fingerprint changes.
7. Whether the client certificate was found, private-key backed, and unexpired.
8. Whether the native Citrix EPA client/browser worked at the same time.

Never send passwords, 2FA codes, cookie values, private keys, or an unapproved
PFX.

## Data handling and limitations

Python redacts authorization headers, cookie values, URL query values,
certificate paths/subjects, and private material. PowerShell excludes response
bodies, cookie values, passwords, and keys from JSONL. Temporary response
content used for hints is deleted after each PowerShell attempt.

The tools diagnose reachability and likely boundaries. They cannot guarantee an
interactive session launch: later steps may depend on nFactor, Workspace app,
StoreFront, ICA files, native EPA, device compliance, entitlements, and MFA.

## Project structure

```text
quick_debug.py                         Editable Python runner
src/citrix_probe/cli.py                citrix-probe command
src/citrix_probe/probe.py              DNS/TCP/TLS/HTTP collection
src/citrix_probe/auth_detection.py     Authentication hints
windows/Run-Me.ps1                     Editable Windows runner
windows/Get-CitrixCertificates.ps1     Certificate-store discovery
windows/Test-CitrixNetwork.ps1         DNS/TCP/proxy checks
windows/Test-CitrixConnection.ps1      Windows-store/Schannel full test
tests/                                 Python unit tests
```

## Development verification

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
python -m compileall -q src quick_debug.py tests
```
