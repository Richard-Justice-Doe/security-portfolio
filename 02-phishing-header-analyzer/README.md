# Phishing / Email Header Analyzer

A local Flask app that scores pasted or uploaded email headers for common phishing tells: **SPF/DKIM/DMARC failures**, **Reply-To / Return-Path mismatches**, **display-name spoofing**, and **suspicious Received-chain jumps**. It never fetches URLs, never opens attachments, and never leaves localhost.

## Problem it solves

Most people (and many first-line analysts) look at the *body* of a suspicious message. The more reliable clues are in the headers: who was authorised to send as that domain, where replies will actually go, and which servers touched the message. This tool makes those clues readable.

## Setup

Python 3.10+. From this directory:

```bash
python -m venv .venv
.venv\Scripts\activate          # Windows
pip install -r requirements.txt
python app.py
```

Open [http://127.0.0.1:5001](http://127.0.0.1:5001). Bind is localhost-only.

CLI (same engine, no browser):

```bash
python analyzer.py samples/01-clean-invoice.eml
python analyzer.py samples/02-spoofed-bank.eml
python analyzer.py samples/03-suspicious-relay.eml
```

## How to run

1. Use a **bundled sample** from the home page, or
2. **Paste** raw headers into the text area, or
3. **Upload** a `.eml` saved from your mail client (your own mail only).

## What is extracted

From, Reply-To, Return-Path, the Received chain (newest hop first), and SPF / DKIM / DMARC verdicts from `Authentication-Results` when that header is present.

## Example output

Clean invoice (`samples/01-clean-invoice.eml`):

```
Risk    : 0/100 (Low)
SPF=pass  DKIM=pass  DMARC=pass
Flags: none
```

Spoofed bank (`samples/02-spoofed-bank.eml`):

```
From    : Ghana Commercial Bank Security <secure-alert@gmail.com>
Reply-To: gcb-verify@attacker-mailbox.xyz
SPF=fail  DKIM=fail  DMARC=fail
Risk    : 100/100 (Critical)

Flags:
  [HIGH] SPF did not pass
  [HIGH] DKIM signature failed
  [CRITICAL] DMARC alignment failed
  [HIGH] Reply-To domain does not match From
  [HIGH] Display name impersonates 'ghana commercial bank'
```

Each flag on the results page has a plain-language explanation (what the check means, why it matters) plus the evidence string.

## Sample files

| File | Intent |
| --- | --- |
| `samples/01-clean-invoice.eml` | Aligned From / Reply-To / Return-Path; SPF+DKIM+DMARC pass |
| `samples/02-spoofed-bank.eml` | Brand impersonation, failed auth, reply channel on another domain |
| `samples/03-suspicious-relay.eml` | Claimed Ghana origin with a `.ru` hop in the middle of the Received chain |

All three are synthetic. Documentation IPs (`192.0.2.0/24`, `203.0.113.0/24`) only.

## Ethical use

- Analyse **your own** mail, or samples you have permission to handle.
- Do not use this to probe other people's inboxes or to craft phishing campaigns.
- A low score is **not** a verdict that a message is safe; payload and URL analysis are out of scope.

## Screenshot (what the results page shows)

A dark analyst-style page: a large **risk score / 100** with a Low–Critical band, a table of extracted headers with colour-coded SPF/DKIM/DMARC pills, a list of red flags each with a severity chip and a short explanation, and the Received chain as a numbered hop list (newest first). The home page has a paste box, a file upload, and links to the three bundled `.eml` files.
