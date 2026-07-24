# ANISAS

ANISAS is a modular network intelligence and security analysis API. The
current release includes Module 1 ASN intelligence and Module 4 single-IPv4
surveillance and IoT fingerprinting.

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

## Verify

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -p "test_*.py" -v
.\.venv\Scripts\python.exe -m compileall -q app tests
.\.venv\Scripts\python.exe -m pip check
```
