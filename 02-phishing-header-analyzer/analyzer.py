"""Email-header parsing and phishing heuristics.

This module is deliberately header-only: it never fetches URLs, never
opens attachments, and never contacts the network. All judgements are
explained in plain language so a reviewer can see *why* a flag fired.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from email import policy
from email.header import decode_header, make_header
from email.message import EmailMessage
from email.parser import Parser
from email.utils import parseaddr
from pathlib import Path
from typing import Any

# Country-code TLDs used only as a coarse "hop jumped regions" hint.
# Generic TLDs (.com, .net, .org) are ignored because they are not geographic.
TLD_REGION = {
    "gh": "Ghana",
    "ng": "Nigeria",
    "ke": "Kenya",
    "za": "South Africa",
    "uk": "United Kingdom",
    "ru": "Russia",
    "cn": "China",
    "br": "Brazil",
    "de": "Germany",
    "fr": "France",
    "in": "India",
    "au": "Australia",
    "jp": "Japan",
    "ua": "Ukraine",
    "tr": "Turkey",
}

# Display-name tokens that impersonate well-known brands if the From domain
# is not actually that organisation. Domains are compared on the registrable
# suffix (e.g. mtn.com.gh).
BRAND_DOMAINS: dict[str, tuple[str, ...]] = {
    "paypal": ("paypal.com",),
    "microsoft": ("microsoft.com", "outlook.com", "live.com", "hotmail.com"),
    "apple": ("apple.com", "icloud.com"),
    "amazon": ("amazon.com",),
    "google": ("google.com", "gmail.com"),
    "mtn": ("mtn.com.gh", "mtn.com"),
    "vodafone": ("vodafone.com.gh", "vodafone.com", "telecel.com.gh"),
    "gcb": ("gcbbank.com.gh", "gcb.com.gh"),
    "ghana commercial bank": ("gcbbank.com.gh", "gcb.com.gh"),
    "ecobank": ("ecobank.com",),
    "stanbic": ("stanbic.com.gh",),
    "bank of ghana": ("bog.gov.gh",),
    "ghipss": ("ghipss.net", "ghipss.com"),
}

MULTI_TLD_SUFFIXES = (
    ".com.gh",
    ".org.gh",
    ".edu.gh",
    ".gov.gh",
    ".co.uk",
    ".org.uk",
    ".co.za",
    ".com.ng",
    ".co.ke",
)

AUTH_RESULT_RE = re.compile(
    r"\b(spf|dkim|dmarc)=(pass|fail|softfail|neutral|none|temperror|permerror|bestguesspass)\b",
    re.IGNORECASE,
)


@dataclass
class Flag:
    code: str
    title: str
    severity: str  # low | medium | high | critical
    weight: int
    explanation: str
    evidence: str = ""


@dataclass
class ReceivedHop:
    raw: str
    from_host: str | None = None
    by_host: str | None = None
    ip: str | None = None
    date: str | None = None


@dataclass
class Analysis:
    from_display: str
    from_address: str
    from_domain: str
    reply_to: str
    reply_to_domain: str
    return_path: str
    return_path_domain: str
    subject: str
    auth_raw: list[str]
    spf: str
    dkim: str
    dmarc: str
    hops: list[ReceivedHop]
    flags: list[Flag] = field(default_factory=list)
    score: int = 0
    band: str = "Low"
    summary: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "from_display": self.from_display,
            "from_address": self.from_address,
            "from_domain": self.from_domain,
            "reply_to": self.reply_to,
            "reply_to_domain": self.reply_to_domain,
            "return_path": self.return_path,
            "return_path_domain": self.return_path_domain,
            "subject": self.subject,
            "spf": self.spf,
            "dkim": self.dkim,
            "dmarc": self.dmarc,
            "auth_raw": self.auth_raw,
            "hops": [h.__dict__ for h in self.hops],
            "flags": [f.__dict__ for f in self.flags],
            "score": self.score,
            "band": self.band,
            "summary": self.summary,
        }


def _decode(value: str | None) -> str:
    if not value:
        return ""
    try:
        return str(make_header(decode_header(value)))
    except Exception:
        return value


def registrable_domain(host: str) -> str:
    """Best-effort eTLD+1 without an external PSL dependency."""
    host = (host or "").lower().strip().strip(".")
    if "@" in host:
        host = host.rsplit("@", 1)[-1]
    if not host:
        return ""
    for suffix in MULTI_TLD_SUFFIXES:
        if host.endswith(suffix):
            rest = host[: -len(suffix)]
            label = rest.rsplit(".", 1)[-1] if rest else ""
            return f"{label}{suffix}" if label else suffix.lstrip(".")
    parts = [p for p in host.split(".") if p]
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host


def _address_parts(header_value: str) -> tuple[str, str, str]:
    display, addr = parseaddr(_decode(header_value))
    addr = addr.lower()
    domain = registrable_domain(addr)
    return display.strip(), addr, domain


def _country_from_host(host: str | None) -> str | None:
    if not host:
        return None
    host = host.lower().strip().strip(".")
    tld = host.rsplit(".", 1)[-1]
    if tld in TLD_REGION:
        return TLD_REGION[tld]
    # Handle .com.gh style: last two labels already classified via suffix.
    if host.endswith(".gh"):
        return "Ghana"
    return None


def parse_received(raw_headers: list[str]) -> list[ReceivedHop]:
    hops: list[ReceivedHop] = []
    for raw in raw_headers:
        collapsed = " ".join(raw.split())
        hop = ReceivedHop(raw=collapsed)
        from_m = re.search(r"\bfrom\s+(\S+)", collapsed, re.I)
        by_m = re.search(r"\bby\s+(\S+)", collapsed, re.I)
        ip_m = re.search(r"\[([0-9]{1,3}(?:\.[0-9]{1,3}){3})\]", collapsed)
        date_m = re.search(r";\s*(.+)$", collapsed)
        if from_m:
            hop.from_host = from_m.group(1).strip("()<>;")
        if by_m:
            hop.by_host = by_m.group(1).strip("()<>;")
        if ip_m:
            hop.ip = ip_m.group(1)
        if date_m:
            hop.date = date_m.group(1).strip()
        hops.append(hop)
    return hops


def parse_auth_results(values: list[str]) -> dict[str, str]:
    results = {"spf": "not present", "dkim": "not present", "dmarc": "not present"}
    for value in values:
        for match in AUTH_RESULT_RE.finditer(value):
            mechanism, verdict = match.group(1).lower(), match.group(2).lower()
            results[mechanism] = verdict
    return results


def _parse_message(raw: str) -> EmailMessage:
    # If the user pasted headers only, the parser still produces a message.
    return Parser(policy=policy.default).parsestr(raw, headersonly=False)


def extract(raw: str) -> Analysis:
    msg = _parse_message(raw)
    from_display, from_addr, from_domain = _address_parts(msg.get("From", ""))
    _, reply_addr, reply_domain = _address_parts(msg.get("Reply-To", ""))
    _, return_addr, return_domain = _address_parts(msg.get("Return-Path", "") or msg.get("Return-path", ""))

    auth_values = msg.get_all("Authentication-Results") or []
    auth = parse_auth_results(auth_values)
    hops = parse_received(msg.get_all("Received") or [])

    return Analysis(
        from_display=from_display,
        from_address=from_addr,
        from_domain=from_domain,
        reply_to=reply_addr,
        reply_to_domain=reply_domain,
        return_path=return_addr,
        return_path_domain=return_domain,
        subject=_decode(msg.get("Subject", "")),
        auth_raw=[str(v) for v in auth_values],
        spf=auth["spf"],
        dkim=auth["dkim"],
        dmarc=auth["dmarc"],
        hops=hops,
    )


def _auth_flags(analysis: Analysis) -> list[Flag]:
    flags: list[Flag] = []
    fail_like = {"fail", "softfail", "permerror"}

    if analysis.spf in fail_like:
        flags.append(
            Flag(
                "SPF_FAIL",
                "SPF did not pass",
                "high" if analysis.spf == "fail" else "medium",
                25 if analysis.spf == "fail" else 15,
                "SPF lists which servers may send mail for a domain. A fail means this "
                "message arrived from an IP that the domain owner did not authorise - "
                "a common sign of From-address spoofing.",
                f"spf={analysis.spf}",
            )
        )
    elif analysis.spf == "none":
        flags.append(
            Flag(
                "SPF_NONE",
                "No SPF policy published",
                "low",
                5,
                "The sending domain has no SPF record (or Authentication-Results reported none). "
                "That is not proof of phishing, but it removes one authenticity check.",
                f"spf={analysis.spf}",
            )
        )

    if analysis.dkim in fail_like:
        flags.append(
            Flag(
                "DKIM_FAIL",
                "DKIM signature failed",
                "high",
                20,
                "DKIM is a cryptographic signature over selected headers and the body. "
                "A fail means the message was altered in transit or signed with a key "
                "that does not match the claimed domain.",
                f"dkim={analysis.dkim}",
            )
        )

    if analysis.dmarc in fail_like:
        flags.append(
            Flag(
                "DMARC_FAIL",
                "DMARC alignment failed",
                "critical",
                25,
                "DMARC requires SPF or DKIM to pass *and* align with the visible From domain. "
                "A fail is one of the strongest header-level signals that the From line "
                "should not be trusted.",
                f"dmarc={analysis.dmarc}",
            )
        )
    return flags


def _domain_mismatch_flags(analysis: Analysis) -> list[Flag]:
    flags: list[Flag] = []
    if analysis.reply_to_domain and analysis.from_domain and analysis.reply_to_domain != analysis.from_domain:
        flags.append(
            Flag(
                "REPLY_TO_MISMATCH",
                "Reply-To domain does not match From",
                "high",
                15,
                "Replies will go to a different organisation than the one shown in From. "
                "Phishing kits use this so the victim 'replies to security' while the "
                "visible sender looks legitimate.",
                f"From {analysis.from_domain} vs Reply-To {analysis.reply_to_domain}",
            )
        )
    if (
        analysis.return_path_domain
        and analysis.from_domain
        and analysis.return_path_domain != analysis.from_domain
        and analysis.return_path_domain not in {"gmail.com", "google.com"}  # Gmail bounces often use google.com
    ):
        flags.append(
            Flag(
                "RETURN_PATH_MISMATCH",
                "Return-Path domain does not match From",
                "medium",
                10,
                "Return-Path is the envelope sender used for bounces. When it belongs to "
                "an unrelated domain, the visible From address is often borrowed.",
                f"From {analysis.from_domain} vs Return-Path {analysis.return_path_domain}",
            )
        )
    return flags


def _display_name_flags(analysis: Analysis) -> list[Flag]:
    flags: list[Flag] = []
    name = analysis.from_display.lower()
    if not name:
        return flags

    for brand, domains in BRAND_DOMAINS.items():
        if brand not in name:
            continue
        if analysis.from_domain in domains or any(analysis.from_domain.endswith("." + d) for d in domains):
            continue
        flags.append(
            Flag(
                "DISPLAY_NAME_SPOOF",
                f"Display name impersonates '{brand}'",
                "high",
                20,
                "The friendly From name cites a well-known organisation, but the actual "
                "email address is hosted on a different domain. Mail clients show the "
                "name first; many people never inspect the address.",
                f'From name "{analysis.from_display}" vs address {analysis.from_address}',
            )
        )
        break

    embedded = re.findall(r"\b[a-z0-9.-]+\.[a-z]{2,}\b", name)
    for token in embedded:
        token_dom = registrable_domain(token)
        if token_dom and analysis.from_domain and token_dom != analysis.from_domain:
            flags.append(
                Flag(
                    "DISPLAY_DOMAIN_SPOOF",
                    "Display name contains a different domain",
                    "high",
                    15,
                    "The display name includes a domain (for example a bank hostname) that "
                    "does not match the address the message was sent from.",
                    f'name contains "{token_dom}", From domain is {analysis.from_domain}',
                )
            )
            break
    return flags


def _received_chain_flags(analysis: Analysis) -> list[Flag]:
    flags: list[Flag] = []
    hops = analysis.hops
    if not hops:
        flags.append(
            Flag(
                "NO_RECEIVED",
                "No Received headers present",
                "medium",
                8,
                "Legitimate mail almost always carries a Received chain added by each "
                "relay. A paste with none may be incomplete - or the headers were stripped "
                "to hide the true origin.",
                "",
            )
        )
        return flags

    # Received headers are prepended: index 0 is the last hop (closest to the inbox).
    # The originating hop is the last item in the list.
    regions: list[tuple[str, str]] = []
    for hop in reversed(hops):
        region = _country_from_host(hop.from_host) or _country_from_host(hop.by_host)
        host = hop.from_host or hop.by_host or "?"
        if region:
            regions.append((region, host))

    for i in range(1, len(regions)):
        prev_region, prev_host = regions[i - 1]
        region, host = regions[i]
        if region != prev_region:
            flags.append(
                Flag(
                    "RECEIVED_GEO_JUMP",
                    "Suspicious geographic jump in Received chain",
                    "medium",
                    15,
                    "Adjacent hops advertise country-code hostnames in different regions "
                    f"({prev_region} -> {region}). That can be a CDN or forwarding service, "
                    "but combined with other failures it often means a message was relayed "
                    "through infrastructure that has nothing to do with the claimed sender.",
                    f"{prev_host} ({prev_region}) then {host} ({region})",
                )
            )
            break

    origin = hops[-1]
    origin_host = (origin.from_host or origin.by_host or "").lower()
    if analysis.from_domain and origin_host:
        origin_dom = registrable_domain(origin_host)
        # Only flag when the originating hostname looks like a real domain and
        # clearly disagrees with From - skip generic hosts like 'unknown'.
        if (
            origin_dom
            and "." in origin_host
            and origin_dom != analysis.from_domain
            and origin_dom not in {"localhost", "localdomain"}
            and not origin_host.startswith("unknown")
        ):
            flags.append(
                Flag(
                    "ORIGIN_MISMATCH",
                    "Originating hop does not match From domain",
                    "medium",
                    12,
                    "The oldest Received header (the first server that accepted the "
                    "message) names a host that is not the From domain. Spoofed mail is "
                    "often injected from a bulletproof or residential relay.",
                    f"origin host {origin_host} vs From {analysis.from_domain}",
                )
            )
    return flags


def _score(flags: list[Flag]) -> tuple[int, str, str]:
    score = min(100, sum(f.weight for f in flags))
    if score >= 70:
        band = "Critical"
        summary = "Multiple strong authenticity failures. Treat this message as hostile until proven otherwise."
    elif score >= 40:
        band = "High"
        summary = "Several independent red flags. Do not click links or reply until the sender is verified out-of-band."
    elif score >= 15:
        band = "Medium"
        summary = "Some header inconsistencies. Worth a closer look, especially if the content asks for money or credentials."
    else:
        band = "Low"
        summary = "Headers look consistent with a legitimate sender. Header analysis cannot prove a message is safe."
    return score, band, summary


def analyze_headers(raw: str) -> Analysis:
    """Full pipeline: parse headers, run heuristics, attach a risk score."""
    analysis = extract(raw)
    flags: list[Flag] = []
    flags.extend(_auth_flags(analysis))
    flags.extend(_domain_mismatch_flags(analysis))
    flags.extend(_display_name_flags(analysis))
    flags.extend(_received_chain_flags(analysis))

    # De-duplicate codes (display-name checks can overlap).
    seen: set[str] = set()
    unique: list[Flag] = []
    for flag in flags:
        if flag.code in seen:
            continue
        seen.add(flag.code)
        unique.append(flag)
    analysis.flags = unique
    analysis.score, analysis.band, analysis.summary = _score(unique)
    return analysis


def format_text_report(analysis: Analysis) -> str:
    lines = [
        f"Subject : {analysis.subject or '(none)'}",
        f"From    : {analysis.from_display} <{analysis.from_address}>",
        f"Reply-To: {analysis.reply_to or '(none)'}",
        f"Return  : {analysis.return_path or '(none)'}",
        f"SPF={analysis.spf}  DKIM={analysis.dkim}  DMARC={analysis.dmarc}",
        f"Risk    : {analysis.score}/100 ({analysis.band})",
        f"Summary : {analysis.summary}",
        "",
        "Flags:" if analysis.flags else "Flags: none",
    ]
    for flag in analysis.flags:
        lines.append(f"  [{flag.severity.upper()}] {flag.title}")
        lines.append(f"           {flag.explanation}")
        if flag.evidence:
            lines.append(f"           evidence: {flag.evidence}")
    if analysis.hops:
        lines.append("")
        lines.append("Received chain (newest first):")
        for i, hop in enumerate(analysis.hops, 1):
            lines.append(
                f"  {i}. from={hop.from_host or '-'}  by={hop.by_host or '-'}  ip={hop.ip or '-'}"
            )
    return "\n".join(lines)


def load_sample(path: str | Path) -> str:
    return Path(path).read_text(encoding="utf-8")


if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(description="Analyse raw email headers or a .eml file.")
    parser.add_argument("path", help="Path to a .eml file or a raw-header text file")
    args = parser.parse_args()
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    report = analyze_headers(load_sample(args.path))
    print(format_text_report(report))
    sys.exit(0 if report.score < 70 else 2)
