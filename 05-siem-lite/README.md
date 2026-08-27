# SIEM-lite

A small **log aggregation and alerting** lab: three synthetic log sources are normalised into SQLite, a rule engine flags brute-force SSH, blocked/unusual IPs, and HTTP 5xx spikes, and a Flask dashboard shows the alerts plus event volume.

## Problem it solves

A homelab or tiny SOC often has `auth.log`, a firewall log, and a web access log that nobody correlates. SIEM-lite is the teaching version of that pipeline: **ingest → common schema → rules → dashboard**, with no Elasticsearch cluster and no real customer data.

## Setup

Python 3.10+. From this directory:

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python ingest.py --reset
python app.py
```

Open [http://127.0.0.1:5005](http://127.0.0.1:5005). Bind is localhost-only. The page auto-refreshes every 20 seconds.

Re-ingest after editing `samples/`:

```bash
python ingest.py --reset
```

## Log sources (bundled)

| File | Dialect | What is in it |
| --- | --- | --- |
| `samples/auth.log` | syslog sshd / sudo | Failed and accepted SSH, two sudo lines |
| `samples/iptables.log` | UFW kernel lines | BLOCK / ALLOW with `SRC=` |
| `samples/access.log` | nginx combined | Mix of 200 / 404 / 500 |

All addresses are RFC 1918 or RFC 5737 documentation ranges. No real personal data.

## Common schema

Every line becomes `{timestamp, source, event_type, severity, src_ip, raw_message}` in `data/siem.db`.

## Rules (`rules.py`)

| Rule | Fires when |
| --- | --- |
| `brute_force` | ≥5 failed SSH logins from one IP in 5 minutes |
| `blocked_ip_reuse` | An IP the firewall dropped later appears in auth or web |
| `unusual_ip` | Auth/web traffic from the lab watchlist (`203.0.113.0/24`, `198.51.100.0/24`) |
| `http_error_spike` | ≥10 HTTP 5xx in 2 minutes |

## Example output

```
auth         17 events from samples/auth.log
firewall     10 events from samples/iptables.log
web          24 events from samples/access.log
stored 51 events, 4 alerts -> data/siem.db
  [high  ] brute_force          8 failed SSH logins from 203.0.113.88 within 5 minutes
  [high  ] blocked_ip_reuse     203.0.113.88 was previously dropped by the host firewall and later appeared in auth logs
  [high  ] blocked_ip_reuse     198.51.100.44 was previously dropped by the host firewall and later appeared in auth logs
  [high  ] http_error_spike     13 HTTP 5xx responses in 2 minutes
```

(Exact alert wording is in the ingest console and on the dashboard table.)

## Dashboard (what you should see)

A dark operations page with:

1. An **alerts table** (time, rule, severity, IP, details), high-severity rows highlighted.
2. A **Chart.js line chart** of event counts by hour, one series per source (auth / firewall / web).
3. A **filterable event table** (`source`, `severity` dropdowns) showing the raw normalised lines.
4. A 20-second auto-refresh so a second ingest in another terminal looks "live".

## Ethical use

- Synthetic logs only. Do not drop production `auth.log` from a machine you do not administer into this folder.
- This is not a substitute for a production SIEM (no HA, no retention policy, no case management).
- Do not point collection at networks or hosts you do not own.

## Limitations

Parsers are dialect-specific (sshd, UFW, nginx combined). Other syslog formats will be skipped. Rules are threshold heuristics, not UEBA.

## Contributors

- [Richard Justice Doe](https://github.com/Richard-Justice-Doe) — author
