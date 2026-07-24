# ANISAS

ANISAS is a modular network intelligence and security analysis API. The
current release includes Module 1 ASN intelligence, Module 4 single-IPv4
surveillance and IoT fingerprinting, and Module 5 wireless network
intelligence.

## Module 4 runtime flow

`POST /api/v1/iot/fingerprint`

The service executes bounded TCP discovery, banner collection, HTTP/HTTPS,
TLS, RTSP, and ONVIF probes. It then correlates service, vendor, device type,
explicit model/firmware evidence, bounded NVD CVE candidates, risk, a concise
security summary, and a flattened inventory report.

Module 4 uses connect-only and metadata probes. It does not authenticate,
submit forms, request video streams, change device configuration, or scan a
subnet. Only a single IPv4 target is accepted.

## Run

From `backend` in PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload
```

Open `http://127.0.0.1:8000/docs` and execute the Module 4 fingerprint route
with an IPv4 address you are authorized to assess.

Example request:

```json
{
  "ip": "192.168.1.20",
  "ports": [80, 443, 554, 8000]
}
```

Optional environment settings include `NVD_API_KEY`,
`IOT_CVE_MAX_RESULTS`, and `IOT_CACHE_TTL_SECONDS`.

## Module 5 runtime flow

```text
Local wireless metadata
→ Access-point enumeration
→ MAC normalization and local IEEE OUI lookup
→ Passive client enumeration
→ Authentication analysis
→ Historical behavior analysis
→ Risk assessment
→ Wireless security report
```

Module 5 endpoints:

- `POST /api/v1/wireless/access-points`
- `POST /api/v1/wireless/clients`
- `POST /api/v1/wireless/authentication`
- `POST /api/v1/wireless/behavior`
- `POST /api/v1/wireless/report`

Windows collection uses read-only `netsh` and `arp` commands. Linux collection
uses read-only `nmcli` and `ip neigh` commands. The module does not connect to
access points, attempt credentials, capture packets, deauthenticate clients, or
change MAC addresses.

Behavior analysis accepts previously collected aggregate metadata and uses
`StandardScaler` with `IsolationForest`. At least five device records are
required before the model executes.

Download the official IEEE MA-L CSV to:

```text
backend/app/modules/wireless/data/oui.csv
```

Official source:

```text
https://standards-oui.ieee.org/oui/oui.csv
```

Only assess wireless networks and equipment you own or have explicit
authorization to test.

## Verify

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -p "test_*.py" -v
.\.venv\Scripts\python.exe -m compileall -q app tests
.\.venv\Scripts\python.exe -m pip check
```
