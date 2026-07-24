# Module 5 — Wireless Network Intelligence & MAC Analysis

## Architecture

```text
app/api/v1/wireless.py
→ WirelessIntelligenceService
→ collectors / parsers / analysis
→ WirelessReportEngine
→ Pydantic response models
```

The module is independent from ASN and IoT modules. It reuses only shared
configuration and logging.

## Combined execution

`POST /api/v1/wireless/full-scan` runs interface discovery, access-point
enumeration, passive neighbor evidence collection, authentication analysis,
optional historical behavior analysis, and final reporting in one request.
The individual endpoints remain available for stage-by-stage execution.

Behavior analysis is executed only when `behavior_records` are supplied.
Current wireless scans do not invent traffic volume, session duration, or
connection-frequency history.

## Collectors

- Windows interfaces: `netsh wlan show interfaces`
- Windows access points: `netsh wlan show networks mode=bssid`
- Windows passive clients: `arp -a`
- Linux interfaces: `nmcli ... device status`
- Linux access points: `nmcli ... device wifi list`
- Linux passive clients: `ip neigh show`

Commands use argument lists, bounded output, strict timeouts, `shell=False`,
and sanitized errors. Raw command output is never returned.

## Analysis

- MAC addresses are normalized and locally administered addresses are
  identified before OUI lookup.
- Vendor evidence comes from the local IEEE MA-L CSV only.
- Authentication analysis covers Open, WEP, WPA/WPA2/WPA3, Enterprise,
  802.1X, and explicit MAC-filtering evidence.
- Access-point observations expose band, hidden-SSID state, WPS/PMF evidence,
  observation timestamps, duplicate/local MAC indicators, and explicit
  `null` values when the operating system does not expose RSSI or beacon data.
- ARP, neighbor, and DHCP records are returned as `neighbor_candidates`.
  `clients` remains empty unless evidence confirms a wireless association.
- The MAC authentication lab is documentation-only.
- Behavior analysis standardizes aggregate metadata, clusters it with DBSCAN,
  and executes Isolation Forest with a fixed random seed.
- Risk findings use deterministic rules, stable identifiers, capped scoring,
  and evidence-backed recommendations.

## External data

Place the official IEEE MA-L CSV at `data/oui.csv`. If unavailable, vendor
results remain `Unknown`; the module never invents vendor identity.

## Verification

From `backend`:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m unittest discover -s tests -p "test_*.py" -v
.\.venv\Scripts\python.exe -m compileall -q app tests
.\.venv\Scripts\python.exe -m pip check
```
