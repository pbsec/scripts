#!/usr/bin/env python3
"""
SMTP Header Security Analyzer
==============================
Tool for analyzing the security of e-mail (SMTP) message headers
for pentesting / infrastructure recon.

Analyzes:
  - Infrastructure mapping (Received: chain -> IP, hostnames, hops)
  - Software fingerprinting (MTA, mailers, mail clients + versions)
  - SPF / DKIM / DMARC / ARC security
  - Other "interesting" headers (X-Originating-IP, mismatch From/Reply-To/Return-Path,
    X-Spam-*, internal IPs in headers, custom X- headers, etc.)

Author: for personal use / within authorized penetration tests.
Use only on messages you have the right to access / within the agreed
scope of a security test.

Usage:
    python3 smtp_header_analyzer.py --headers msg.txt
    python3 smtp_header_analyzer.py --headers msg.eml --json report.json
    python3 smtp_header_analyzer.py --headers msg.txt --dns --no-color
"""

import argparse
import base64
import email
import email.policy
import ipaddress
import json
import re
import socket
import sys
from datetime import datetime, timezone, timedelta

# ---------------------------------------------------------------------------
# Optional DNS support (only used with --dns, degrades gracefully if missing)
# ---------------------------------------------------------------------------
try:
    import dns.resolver  # dnspython
    HAS_DNS = True
except ImportError:
    HAS_DNS = False


# ---------------------------------------------------------------------------
# Colors
# ---------------------------------------------------------------------------
class C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    GREY = "\033[90m"

    @classmethod
    def disable(cls):
        for attr in ["RESET", "BOLD", "DIM", "RED", "GREEN", "YELLOW",
                      "BLUE", "MAGENTA", "CYAN", "GREY"]:
            setattr(cls, attr, "")


SEV_COLOR = {
    "CRITICAL": C.RED,
    "HIGH": C.RED,
    "MEDIUM": C.YELLOW,
    "LOW": C.CYAN,
    "INFO": C.GREY,
    "GOOD": C.GREEN,
}
SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4, "GOOD": 5}


# ---------------------------------------------------------------------------
# Regexes
# ---------------------------------------------------------------------------
IPV4_RE = re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b')
IPV6_RE = re.compile(r'\b(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4}\b')

FROM_RE = re.compile(r'from\s+([^\s()]+)(?:\s*\(([^)]*)\))?', re.I)
BY_RE = re.compile(r'\bby\s+([^\s()]+)', re.I)
FOR_RE = re.compile(r'\bfor\s+<?([^;>\s]+)', re.I)
WITH_RE = re.compile(r'\bwith\s+([A-Za-z0-9/.\-]+)', re.I)

# TLS info logged by many MTAs at the end of a Received header, e.g.:
# (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256)
TLS_INFO_RE = re.compile(
    r'version\s*=\s*(TLSv?[\d._]+|SSLv?\d)\s+cipher\s*=\s*([\w\-]+)(?:\s+bits\s*=\s*([\d/]+))?',
    re.I
)
WEAK_CIPHER_RE = re.compile(r'RC4|(?<![A-Z])DES(?!Simple)|3DES|EXPORT|_NULL_|MD5|_anon_', re.I)
AEAD_CIPHER_RE = re.compile(r'GCM|CHACHA20|POLY1305|CCM', re.I)

# AV / content-scanning hop signatures, typically seen wrapped in parens on
# loopback Received hops, e.g. "(amavis, port 10026)"
AV_SCANNER_PATTERNS = [
    ("Amavis", re.compile(r'\bamavis\b(?:.*?port\s*(\d+))?', re.I)),
    ("ClamAV", re.compile(r'\bclamav\b', re.I)),
    ("Rspamd", re.compile(r'\brspamd\b', re.I)),
    ("SpamAssassin", re.compile(r'\bspamassassin\b', re.I)),
    ("OpenDKIM", re.compile(r'\bopendkim\b', re.I)),
]

# Known ESP / mail-provider hostname suffixes, checked against every hostname
# seen in the Received chain and in Authentication-Results.
MAIL_PROVIDERS = [
    ("Google Workspace / Gmail", re.compile(r'(?:^|\.)(?:google\.com|gmail\.com|googlemail\.com)$', re.I)),
    ("Microsoft 365 / Outlook / EOP", re.compile(r'(?:^|\.)(?:outlook\.com|protection\.outlook\.com|office365\.com)$', re.I)),
    ("Amazon SES", re.compile(r'(?:^|\.)amazonses\.com$', re.I)),
    ("SendGrid", re.compile(r'(?:^|\.)sendgrid\.net$', re.I)),
    ("Mailgun", re.compile(r'(?:^|\.)mailgun\.org$', re.I)),
    ("Zoho Mail", re.compile(r'(?:^|\.)zoho\.com$', re.I)),
    ("Yahoo Mail", re.compile(r'(?:^|\.)(?:yahoo\.com|yahoodns\.net)$', re.I)),
    ("Proofpoint", re.compile(r'(?:^|\.)(?:pphosted\.com|proofpoint\.com)$', re.I)),
    ("Mimecast", re.compile(r'(?:^|\.)mimecast\.com$', re.I)),
    ("Barracuda", re.compile(r'(?:^|\.)barracudanetworks\.com$', re.I)),
    ("Zimbra (self-hosted)", re.compile(r'zimbra', re.I)),
]

# Header-injection recon signals: literal encoded CRLF that leaked into a
# value instead of being interpreted (classic sign of a vulnerable contact
# form / PHP mail() call without sanitisation).
INJECTION_ENCODED_CRLF_RE = re.compile(r'%0d%0a|%0D%0A|\\r\\n', re.I)
# Headers that should only ever appear once in a well-formed message.
SINGLETON_HEADERS = ["From", "Subject", "Date", "Message-ID", "Reply-To", "Return-Path", "To"]

# Internal-infrastructure-disclosure patterns (static, no network needed).
INTERNAL_DOMAIN_SUFFIX_RE = re.compile(r'\.(local|internal|corp|lan|intranet)$', re.I)
INFRA_ROLE_HOSTNAME_RE = re.compile(r'^(dc|mail|exchange|smtp|mx|mta|relay|edge|hub|cas|ex|owa)\d{1,3}([.\-]|$)', re.I)
ENV_INDICATOR_RE = re.compile(r'(?:^|[.\-_])(dev|test|staging|stage|uat|preprod|prod)(?:[.\-_]|$)', re.I)

# DKIM selectors that reveal the underlying ESP/environment by naming convention.
KNOWN_SELECTOR_PATTERNS = [
    ("Microsoft 365 (default convention)", re.compile(r'^selector[12]$', re.I)),
    ("Google Workspace", re.compile(r'^google$', re.I)),
    ("Amazon SES", re.compile(r'^[a-z0-9]+\.ses$|^ses$', re.I)),
    ("Mailchimp/Mandrill", re.compile(r'^k[1-3]$|^mandrill$', re.I)),
    ("SendGrid", re.compile(r'^s1$|^s2$|^smtpapi$', re.I)),
    ("Zoho Mail", re.compile(r'^zoho$|^zmail$', re.I)),
]

# Software fingerprint patterns -> (regex, group index for version or None)
SOFTWARE_PATTERNS = [
    ("PHPMailer", re.compile(r'PHPMailer\s*(?:\(https?://[^\)]*\))?\s*([\d.]+)?', re.I)),
    ("Exim", re.compile(r'\bExim\s*([\d.]+)?', re.I)),
    ("Postfix", re.compile(r'\bPostfix\b', re.I)),
    ("Sendmail", re.compile(r'\bSendmail\b\s*([\d.]+)?', re.I)),
    ("Microsoft Exchange", re.compile(r'Microsoft Exchange Server\s*([\d.]+)?', re.I)),
    ("Microsoft Outlook", re.compile(r'Microsoft Outlook\s*([\d.]+)?', re.I)),
    ("Zimbra", re.compile(r'\bZimbra\b\s*([\d.]+)?', re.I)),
    ("SquirrelMail", re.compile(r'SquirrelMail\s*([\d.]+)?', re.I)),
    ("Roundcube", re.compile(r'Roundcube Webmail\s*([\d.]+)?', re.I)),
    ("Apple Mail", re.compile(r'Apple Mail\s*\(([\d.]+)\)', re.I)),
    ("Thunderbird", re.compile(r'Thunderbird/?\s*([\d.]+)?', re.I)),
    ("WordPress", re.compile(r'WordPress[/ ]?([\d.]+)?', re.I)),
    ("Django", re.compile(r'\bDjango\b[/ ]?([\d.]+)?', re.I)),
    ("SendGrid", re.compile(r'\bSendGrid\b', re.I)),
    ("Mailgun", re.compile(r'\bMailgun\b', re.I)),
    ("MailChimp/Mandrill", re.compile(r'\b(?:Mandrill|MailChimp)\b', re.I)),
    ("cPanel/Exim (shared hosting)", re.compile(r'cPanel', re.I)),
    ("IIS SMTP Service", re.compile(r'Microsoft SMTPSVC\s*([\d.]+)?', re.I)),
    ("Communigate Pro", re.compile(r'CommuniGate Pro\s*([\d.]+)?', re.I)),
    ("MDaemon", re.compile(r'MDaemon\s*([\d.]+)?', re.I)),
    ("nlserver (mass mailing)", re.compile(r'\bnlserver\b,?\s*Build\s*([\d.]+)', re.I)),
    ("PowerMTA (PMTA)", re.compile(r'\bPowerMTA\b\s*(?:\(v([\d.]+)\))?', re.I)),
    ("GreenArrow", re.compile(r'\bGreenArrow\b\s*([\d.]+)?', re.I)),
    ("dotdigital/dotmailer", re.compile(r'\bdot(?:digital|mailer)\b', re.I)),
    ("Salesforce Marketing Cloud", re.compile(r'\b(?:ExactTarget|Salesforce Marketing Cloud)\b', re.I)),
    ("Klaviyo", re.compile(r'\bKlaviyo\b', re.I)),
    ("Sparkpost", re.compile(r'\bSparkPost\b', re.I)),
    ("Postmark", re.compile(r'\bPostmark\b', re.I)),
    ("KumoMTA", re.compile(r'\bKumoMTA\b\s*([\d.]+)?', re.I)),
    ("Lotus Notes/Domino", re.compile(r'Lotus Notes|Domino', re.I)),
    ("OpenDKIM Filter", re.compile(r'OpenDKIM Filter\s*v?([\d.]+)?', re.I)),
    ("Amavis", re.compile(r'\bamavisd?(?:-new)?\b\s*([\d.]+)?', re.I)),
]

# Illustrative "outdated / historically vulnerable" version ranges.
# NOT exhaustive - always verify against NVD/CVE databases for the exact version found.
def _v(tuple_str):
    return tuple(int(x) for x in re.findall(r'\d+', tuple_str)[:3])


VULN_HINTS = {
    "PHPMailer": [
        (lambda v: v and v < (5, 2, 27), "HIGH",
         "PHPMailer versions < 5.2.27 are vulnerable to known RCE-related CVEs "
         "(incl. CVE-2016-10033, CVE-2017-5223) - verify in NVD."),
        (lambda v: v and (5, 2, 27) <= v < (6, 0, 6), "MEDIUM",
         "Older PHPMailer 5.x/6.x branch - check for dedicated CVEs for this version."),
    ],
    "Exim": [
        (lambda v: v and v < (4, 94, 2), "CRITICAL",
         "Exim < 4.94.2 - historically many critical CVEs (incl. '21Nails', "
         "CVE-2020-8218/8219/etc.) - verify in NVD."),
    ],
    "Sendmail": [
        (lambda v: v and v < (8, 15, 2), "MEDIUM",
         "Older Sendmail version - check known CVEs for this branch."),
    ],
}

AUTH_RESULTS_KV_RE = re.compile(r'(spf|dkim|dmarc|arc)\s*=\s*([a-zA-Z]+)', re.I)
DKIM_TAG_RE = re.compile(r'([a-z]+)\s*=\s*([^;]+);?', re.I)
# Captures the "(p=REJECT sp=QUARANTINE dis=NONE)" style comment that follows
# dmarc=<result> in Authentication-Results.
DMARC_RESULT_RE = re.compile(r'dmarc\s*=\s*(\w+)\s*(?:\(([^)]*)\))?', re.I)
SPF_RESULT_RE = re.compile(r'spf\s*=\s*(\w+)\s*(?:\(([^)]*)\))?', re.I)

PRIVATE_NOTE = " [private/internal address per RFC1918/RFC4193 - possible disclosure of internal network topology]"

INTERESTING_HEADER_NAMES = [
    "X-Originating-IP", "X-Sender-IP", "X-Client-IP", "X-Real-IP",
    "X-Forwarded-For", "X-Env-Sender", "X-Source-IP", "X-AntiAbuse",
    "X-Spam-Status", "X-Spam-Score", "X-Spam-Flag", "X-Spam-Checker-Version",
    "X-Mailer", "X-MimeOLE", "X-PHP-Originating-Script", "X-PHP-Version",
    "X-Powered-By", "X-Generator", "X-Get-Message-Sender-Via",
    "X-Authenticated-Sender", "X-Account-Key", "X-Original-Sender",
    "Thread-Topic", "X-MS-Exchange-Organization-AuthSource",
    "X-MS-Exchange-Organization-Network-Message-Id",
]

KNOWN_STANDARD_HEADERS = {
    "from", "to", "cc", "bcc", "subject", "date", "message-id", "received",
    "return-path", "reply-to", "content-type", "content-transfer-encoding",
    "mime-version", "authentication-results", "received-spf",
    "dkim-signature", "arc-seal", "arc-message-signature",
    "arc-authentication-results", "list-unsubscribe", "in-reply-to",
    "references", "delivered-to", "sender", "precedence",
}


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------
class Finding:
    def __init__(self, category, severity, title, detail=""):
        self.category = category
        self.severity = severity
        self.title = title
        self.detail = detail

    def to_dict(self):
        return {
            "category": self.category,
            "severity": self.severity,
            "title": self.title,
            "detail": self.detail,
        }


class Report:
    def __init__(self):
        self.findings = []
        self.infra_hops = []
        self.software = []
        self.auth = {}
        self.interesting = []
        self.meta = {}
        self.providers = []
        self.hostnames = []
        self.dkim_selectors = []
        self.dmarc_dns_policy = None
        self.asn_data = {}
        self.iocs = {}
        self.mx_hosts = []
        self.posture = {}
        self.hypotheses = []
        self.spf_mechanisms = []

    def add(self, category, severity, title, detail=""):
        self.findings.append(Finding(category, severity, title, detail))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
RFC1918_V4 = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]
ULA_V6 = ipaddress.ip_network("fc00::/7")


def is_private_ip(ip_str):
    """True only for genuine internal/non-routable addresses (RFC1918, ULA,
    loopback, link-local). Deliberately excludes RFC5737 documentation
    ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) so example/public
    addresses are not mislabeled as internal infrastructure."""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    if ip.is_loopback or ip.is_link_local:
        return True
    if isinstance(ip, ipaddress.IPv4Address):
        return any(ip in net for net in RFC1918_V4)
    return ip in ULA_V6


def extract_ips(text):
    """Extract IPs from text, validating each candidate strictly so that
    things like timestamps (10:15:22) or IDs are never mistaken for IPv6."""
    ips = set()
    for m in IPV4_RE.findall(text):
        try:
            ipaddress.IPv4Address(m)
            ips.add(m)
        except ValueError:
            pass
    for m in IPV6_RE.findall(text):
        try:
            ipaddress.IPv6Address(m)
            ips.add(m)
        except ValueError:
            pass
    return ips


def get_all(msg, name):
    return msg.get_all(name, [])


# Header field name = letters/digits/hyphen followed by ':' then whitespace
# or end-of-line. Used to tell a genuine new header line apart from a
# continuation line that lost its RFC 5322 folding whitespace.
NEW_HEADER_LINE_RE = re.compile(r'^[A-Za-z0-9\-]+:(\s|$)')


def repair_unfolded_headers(raw_bytes):
    """Some sources (webmail 'show original' views, PDF/plain-text exports,
    copy-paste through certain terminals) strip the leading whitespace that
    RFC 5322 requires on continuation lines of multi-line headers. Without
    that whitespace, Python's email parser treats every physical line as its
    own (bogus) header and silently produces an almost-empty message.

    This heuristically re-folds such files: any header-section line that does
    NOT look like 'Header-Name: value' and does NOT already start with
    whitespace is assumed to be a continuation of the previous header and is
    prefixed with a tab. Returns (repaired_bytes, was_repaired)."""
    try:
        text = raw_bytes.decode("utf-8", errors="replace")
    except Exception:
        return raw_bytes, False

    lines = text.split("\n")
    out = []
    in_headers = True
    repaired_any = False

    for line in lines:
        line_nocr = line[:-1] if line.endswith("\r") else line

        if in_headers and line_nocr.strip() == "":
            in_headers = False
            out.append(line_nocr)
            continue

        if not in_headers:
            out.append(line_nocr)
            continue

        if line_nocr.startswith((" ", "\t")):
            out.append(line_nocr)  # already correctly folded
        elif NEW_HEADER_LINE_RE.match(line_nocr) or not out:
            out.append(line_nocr)  # genuine new header (or first line)
        else:
            out.append("\t" + line_nocr)  # missing fold -> repair it
            repaired_any = True

    repaired_text = "\n".join(out)
    return repaired_text.encode("utf-8"), repaired_any


def strip_dot(host):
    """Normalize FQDNs with a trailing root dot, e.g. 'host.example.com.' """
    return host.rstrip(".") if host else host


def detect_provider(hostname):
    if not hostname:
        return None
    h = strip_dot(hostname).lower()
    for name, pattern in MAIL_PROVIDERS:
        if pattern.search(h):
            return name
    return None


# ---------------------------------------------------------------------------
# 1. Infrastructure mapping
# ---------------------------------------------------------------------------
def analyze_infrastructure(msg, report):
    received = get_all(msg, "Received")
    hops = []
    providers_found = {}  # name -> example hostname
    hostnames_found = {}  # lowercase host -> display form (first seen), ordered

    # Received headers are prepended - first in the list is the LAST hop
    # (closest to the recipient); the last one in the list is usually the
    # ORIGIN (closest to the sender).
    for idx, raw in enumerate(received):
        flat = re.sub(r'\s+', ' ', raw).strip()
        from_m = FROM_RE.search(flat)
        by_m = BY_RE.search(flat)
        for_m = FOR_RE.search(flat)
        with_m = WITH_RE.search(flat)
        ips = extract_ips(flat)

        from_host = strip_dot(from_m.group(1)) if from_m else None
        by_host = strip_dot(by_m.group(1)) if by_m else None
        has_from = bool(from_m)

        # Every parenthetical group in the hop is classified individually,
        # since a single Received header commonly carries several of them:
        # "from X (Y [ip]) by Z (W) (amavis, port N) with ESMTP ... (version=... cipher=...)"
        paren_groups = re.findall(r'\(([^()]*)\)', flat)
        tls_info = None
        scanners = []
        sw_version_lookalikes = set()
        for pc in paren_groups:
            tls_m = TLS_INFO_RE.search(pc)
            if tls_m:
                tls_info = {
                    "version": tls_m.group(1),
                    "cipher": tls_m.group(2),
                    "bits": tls_m.group(3),
                }
                continue
            scanner_hit = False
            for scanner_name, scanner_re in AV_SCANNER_PATTERNS:
                if scanner_re.search(pc):
                    port_m = re.search(r'port\s*(\d+)', pc, re.I)
                    scanners.append({
                        "name": scanner_name,
                        "port": port_m.group(1) if port_m else None,
                        "raw": pc.strip(),
                    })
                    scanner_hit = True
            if scanner_hit:
                continue
            # Some MTAs (e.g. "KumoMTA 10.154.133.56") report a dotted-quad
            # BUILD/VERSION number that syntactically matches an IPv4 address.
            # Without this check it gets misread as a leaked private IP.
            for sw_name, sw_pat in SOFTWARE_PATTERNS:
                sw_m = sw_pat.search(pc)
                if sw_m and sw_m.groups() and sw_m.group(1) and IPV4_RE.fullmatch(sw_m.group(1)):
                    sw_version_lookalikes.add(sw_m.group(1))

        # A hop with no "from" clause has no attributable external client -
        # whatever follows "by" describes the RECEIVING system itself. Some
        # providers (notably Gmail) put an opaque, non-routable internal
        # cluster/shard identifier there that happens to be syntactically
        # valid IPv6 ("2002:a05:6000:..."). Don't treat that as a real
        # network address when it's literally just the raw "by" token.
        if not has_from and by_host and by_host.strip("[]") in ips:
            ips.discard(by_host.strip("[]"))

        if sw_version_lookalikes:
            bracketed = set(re.findall(r'\[([0-9a-fA-F:.]+)\]', flat))
            ips -= (sw_version_lookalikes - bracketed)

        is_loopback_hop = bool(ips) and all(is_private_ip(ip) for ip in ips) and\
            any(ipaddress.ip_address(ip).is_loopback for ip in ips)

        hop = {
            "index": idx,
            "from_host": from_host,
            "from_detail": from_m.group(2) if from_m and from_m.group(2) else None,
            "by_host": by_host,
            "has_from": has_from,
            "protocol": with_m.group(1) if with_m else None,
            "for": for_m.group(1) if for_m else None,
            "ips": sorted(ips),
            "tls": tls_info,
            "scanners": scanners,
            "is_loopback_hop": is_loopback_hop,
            "raw": flat,
        }
        hops.append(hop)

        for host in (from_host, by_host):
            prov = detect_provider(host)
            if prov and prov not in providers_found:
                providers_found[prov] = host
            if host:
                h_low = host.lower()
                is_ip_literal = h_low.strip("[]") in ips or h_low in (
                    ip.lower() for ip in extract_ips(host)
                )
                if h_low not in ("localhost", "localhost.localdomain", "unknown") and\
                        "." in host and not is_ip_literal and h_low not in hostnames_found:
                    hostnames_found[h_low] = host

        for ip in ips:
            if is_private_ip(ip):
                sev = "INFO" if is_loopback_hop else "LOW"
                report.add(
                    "Infrastructure", sev,
                    f"Internal/private IP address disclosed (RFC1918/loopback/link-local) in Received #{idx}: {ip}",
                    ("Loopback - typical for a local hand-off to an antivirus/"
                     "antispam scanner on the same machine (not a network topology leak)."
                     if is_loopback_hop else
                     "May reveal the sender's internal network topology (segmentation, "
                     "relay/mail servers behind NAT).")
                )

        for scanner in scanners:
            port_str = f", port {scanner['port']}" if scanner["port"] else ""
            report.add(
                "Infrastructure", "INFO",
                f"Hop #{idx}: content scanner '{scanner['name']}' detected{port_str}",
                f"Header: {scanner['raw']}. Reveals the mail server's antivirus/"
                f"antispam stack."
            )

    report.infra_hops = hops
    report.providers = [{"name": n, "example_host": h} for n, h in providers_found.items()]
    report.hostnames = list(hostnames_found.values())

    for name, host in providers_found.items():
        report.add("Infrastructure", "INFO", f"Mail provider detected: {name}",
                    f"Identified based on host '{host}' in the Received chain "
                    f"(or in Authentication-Results).")

    if not hops:
        report.add("Infrastructure", "INFO", "No Received headers",
                    "Cannot build the SMTP hop path - headers may have been "
                    "removed/anonymized, or the message contains only partial headers.")
    else:
        # Origin/ingress hop = the OLDEST hop (closest to the true sender)
        # that carries at least one PUBLIC IP - i.e. the point where the
        # message is first seen entering the public Internet. Loopback/AV
        # hops and hops with only private IPs (or no IP at all) are skipped
        # even if they're older, since they don't mark a real ingress point.
        origin = None
        for hop in reversed(hops):
            if hop["is_loopback_hop"]:
                continue
            public_ips_here = [ip for ip in hop["ips"] if not is_private_ip(ip)]
            if public_ips_here:
                origin = hop
                break
        if origin:
            origin_public_ips = [ip for ip in origin["ips"] if not is_private_ip(ip)]
            report.add(
                "Infrastructure", "INFO",
                f"Likely public IP address of the message source: {', '.join(origin_public_ips)}",
                f"Taken from Received header #{origin['index']}: from={origin.get('from_host')}"
            )
        else:
            report.add(
                "Infrastructure", "INFO",
                "No public IP address in the Received chain",
                "None of the hops clearly contains a public IP address - this may "
                "indicate fully internal sending (test/relay on a local network) or "
                "removal/anonymization of this information before the file was submitted for analysis."
            )

    # X-Originating-IP / X-Sender-IP etc. also help pinpoint client machine
    for hname in ["X-Originating-IP", "X-Sender-IP", "X-Client-IP", "X-Real-IP"]:
        vals = get_all(msg, hname)
        for v in vals:
            ips = extract_ips(v)
            for ip in ips:
                sev = "MEDIUM" if not is_private_ip(ip) else "LOW"
                report.add(
                    "Infrastructure", sev,
                    f"{hname} discloses the client IP address: {ip}",
                    "Direct disclosure of the sender device's IP - useful for OSINT/"
                    "geolocation, may bypass anonymity protection (e.g. the sender's VPN "
                    "if the mail client adds the real IP)."
                )

    return hops


# ---------------------------------------------------------------------------
# 2. Software / version fingerprinting
# ---------------------------------------------------------------------------
def analyze_software(msg, report):
    # Concatenate all header values (with header name) for scanning
    haystacks = []
    for name, value in msg.items():
        haystacks.append((name, str(value)))

    found = []
    seen = set()

    for name, value in haystacks:
        for sw_name, pattern in SOFTWARE_PATTERNS:
            m = pattern.search(value)
            if m:
                version_str = None
                if m.groups() and m.group(1):
                    version_str = m.group(1)
                key = (sw_name, version_str, name)
                if key in seen:
                    continue
                seen.add(key)
                found.append({
                    "software": sw_name,
                    "version": version_str,
                    "header": name,
                    "raw": value.strip()[:200],
                })

    # Fallback: X-Mailer/X-MimeOLE/X-Generator explicitly identify client
    # software by design. If nothing in SOFTWARE_PATTERNS matched that header,
    # still surface it verbatim rather than silently dropping the value.
    GENERIC_VERSION_RE = re.compile(r'(?:build|version|v)\.?\s*[:=]?\s*([\d][\d.]*)', re.I)
    for hname in ["X-Mailer", "X-MimeOLE", "X-Generator"]:
        val = msg.get(hname)
        if not val:
            continue
        val = str(val).strip()
        if not val or any(item["header"].lower() == hname.lower() for item in found):
            continue
        ver_m = GENERIC_VERSION_RE.search(val)
        version = ver_m.group(1) if ver_m else None
        name_guess = re.split(r'[,;]', val)[0].strip()
        key = (name_guess, version, hname)
        if key in seen:
            continue
        seen.add(key)
        found.append({
            "software": f"{name_guess} (unidentified)",
            "version": version,
            "header": hname,
            "raw": val[:200],
        })

    report.software = found

    for item in found:
        sw = item["software"]
        ver = item["version"]
        detail = f"Detected in header '{item['header']}': {item['raw']}"
        report.add("Software", "INFO", f"Identified: {sw}" + (f" v{ver}" if ver else ""), detail)

        if ver and sw in VULN_HINTS:
            v_tuple = _v(ver)
            for check_fn, sev, msg_text in VULN_HINTS[sw]:
                try:
                    if check_fn(v_tuple):
                        report.add("Software", sev,
                                    f"{sw} {ver} - potentially outdated/vulnerable version",
                                    msg_text)
                except Exception:
                    pass

    if not found:
        report.add("Software", "INFO", "No unambiguous software signatures detected",
                    "The server/client may deliberately hide its banner (good practice) or "
                    "uses unusual software outside the signature database.")


def classify_tls_version(version_str):
    """Return (severity, note) for a TLS/SSL version string as logged in
    Received headers (formats vary: 'TLS1_3', 'TLSv1.3', 'SSLv3', ...)."""
    v = version_str.lower()
    if "ssl" in v:
        return "CRITICAL", "The SSL protocol is obsolete and considered insecure (e.g. vulnerable to POODLE)."
    if "1_0" in v or "1.0" in v:
        return "HIGH", "TLS 1.0 is obsolete (e.g. vulnerable to BEAST) and being phased out by most clients/browsers."
    if "1_1" in v or "1.1" in v:
        return "MEDIUM", "TLS 1.1 is obsolete - disabling it in favor of TLS 1.2/1.3 is recommended."
    if "1_2" in v or "1.2" in v:
        return "GOOD", "TLS 1.2 is acceptable; supporting/preferring TLS 1.3 is still recommended."
    if "1_3" in v or "1.3" in v:
        return "GOOD", "TLS 1.3 - current, recommended transport encryption standard."
    return "INFO", "Unrecognized protocol version - verify manually."


# ---------------------------------------------------------------------------
# 2b. Encryption / TLS security of the SMTP transport hops
# ---------------------------------------------------------------------------
def analyze_encryption(report):
    hops = report.infra_hops
    if not hops:
        return

    any_tls_seen = False

    for hop in hops:
        idx = hop["index"]
        if hop["is_loopback_hop"]:
            continue  # internal loopback delivery to AV/spam scanners - not a network hop

        if hop["tls"]:
            any_tls_seen = True
            tls = hop["tls"]
            sev, note = classify_tls_version(tls["version"])
            bits_str = f", {tls['bits']} bits" if tls["bits"] else ""
            report.add(
                "Encryption", sev,
                f"Hop #{idx} ({hop.get('from_host')} -> {hop.get('by_host')}): "
                f"{tls['version']} / {tls['cipher']}{bits_str}",
                note
            )
            if WEAK_CIPHER_RE.search(tls["cipher"]):
                report.add(
                    "Encryption", "HIGH",
                    f"Hop #{idx}: weak cipher suite ({tls['cipher']})",
                    "Signs of a weak cipher suite detected (RC4/DES/3DES/EXPORT/NULL/MD5/anon) "
                    "- vulnerable to known cryptographic attacks, should be disabled on the server."
                )
            elif not AEAD_CIPHER_RE.search(tls["cipher"]):
                report.add(
                    "Encryption", "LOW",
                    f"Hop #{idx}: cipher {tls['cipher']} without an AEAD mode (GCM/ChaCha20/CCM)",
                    "Not a critical flaw, but modern AEAD modes are preferred "
                    "over older block modes (e.g. CBC)."
                )
        else:
            # No TLS evidence for this network hop. This is NOT conclusive proof
            # of plaintext (many MTAs simply don't log it) so it's kept low-severity
            # and worded as a recommendation to verify, not a confirmed finding.
            protocol = (hop.get("protocol") or "").upper()
            if protocol and "S" not in protocol and protocol not in ("LMTP",):
                report.add(
                    "Encryption", "LOW",
                    f"Hop #{idx} ({hop.get('from_host')} -> {hop.get('by_host')}): "
                    f"no confirmation of TLS encryption (protocol reported as '{protocol}')",
                    "The header contains no TLS information, and the reported protocol has no "
                    "'S' suffix (e.g. ESMTP instead of ESMTPS) - this may indicate plaintext "
                    "transmission between servers, or the server simply "
                    "does not log this information. Manual verification is recommended (e.g. testssl.sh/openssl "
                    "against the given MTA) along with enforcing STARTTLS/MTA-STS."
                )

    if not any_tls_seen and any(not h["is_loopback_hop"] for h in hops):
        report.add(
            "Encryption", "INFO",
            "No TLS information anywhere in the Received chain",
            "This message's headers contain no data on transport encryption on "
            "any of the network hops - this may result from the server configuration "
            "(no logging) or from a lack of encryption. Verifying MTA-STS/TLS-RPT "
            "and manually testing STARTTLS for the domain is recommended."
        )


# ---------------------------------------------------------------------------
# 3. SPF / DKIM / DMARC / ARC
# ---------------------------------------------------------------------------
def get_domain(addr):
    if not addr:
        return None
    m = re.search(r'@([\w.\-]+)', addr)
    return m.group(1).lower() if m else None


def analyze_auth(msg, report):
    auth_info = {
        "authentication_results": [],
        "received_spf": [],
        "dkim_signature": [],
        "arc": [],
    }

    from_addr = email.utils.parseaddr(msg.get("From", ""))[1]
    from_domain = get_domain(from_addr)
    return_path = email.utils.parseaddr(msg.get("Return-Path", ""))[1]
    return_path_domain = get_domain(return_path)

    auth_results_headers = get_all(msg, "Authentication-Results")
    received_spf_headers = get_all(msg, "Received-SPF")
    dkim_headers = get_all(msg, "DKIM-Signature")
    arc_headers = get_all(msg, "ARC-Authentication-Results")

    for h in auth_results_headers:
        server_m = re.match(r'\s*([\w.\-]+)\s*;', h)
        if server_m:
            host = server_m.group(1)
            if "." in host and host.lower() not in (hn.lower() for hn in report.hostnames):
                report.hostnames.append(host)

    auth_info["authentication_results"] = auth_results_headers
    auth_info["received_spf"] = received_spf_headers
    auth_info["dkim_signature"] = dkim_headers
    auth_info["arc"] = arc_headers

    spf_result = None
    dkim_result = None
    dmarc_result = None
    dmarc_policy_comment = None
    spf_comment = None

    for h in auth_results_headers:
        for proto, result in AUTH_RESULTS_KV_RE.findall(h):
            proto_l = proto.lower()
            result_l = result.lower()
            if proto_l == "spf":
                spf_result = result_l
            elif proto_l == "dkim":
                dkim_result = result_l
            elif proto_l == "dmarc":
                dmarc_result = result_l

        dmarc_m = DMARC_RESULT_RE.search(h)
        if dmarc_m and dmarc_m.group(2):
            dmarc_policy_comment = dmarc_m.group(2)
        spf_m = SPF_RESULT_RE.search(h)
        if spf_m and spf_m.group(2):
            spf_comment = spf_m.group(2)

    # If no Authentication-Results, fall back to Received-SPF
    if spf_result is None and received_spf_headers:
        m = re.match(r'\s*(\w+)', received_spf_headers[0])
        if m:
            spf_result = m.group(1).lower()

    def verdict(name, result, good_values=("pass",)):
        if result is None:
            report.add("Authentication", "MEDIUM",
                        f"{name}: no information in this message's headers",
                        f"No {name} result found in Authentication-Results / dedicated "
                        f"headers. This may mean the recipient server does not verify {name}, "
                        f"does not add the result, or the headers were removed.")
            return
        if result in good_values:
            report.add("Authentication", "GOOD", f"{name}: {result}",
                        f"{name} verification completed with a positive result.")
        elif result in ("fail", "hardfail"):
            report.add("Authentication", "HIGH", f"{name}: {result.upper()}",
                        f"{name} verification failed - strong indicator of possible "
                        f"spoofing / SPF/DKIM/DMARC misconfiguration.")
        elif result in ("softfail", "neutral", "none"):
            report.add("Authentication", "MEDIUM", f"{name}: {result}",
                        f"The {name} result is not clearly positive - consider verifying "
                        f"the sender domain's DNS record configuration.")
        elif result in ("temperror", "permerror"):
            report.add("Authentication", "MEDIUM", f"{name}: {result}",
                        f"Error during {name} verification (DNS problem/record syntax).")
        else:
            report.add("Authentication", "LOW", f"{name}: {result}", "Unusual result - verify manually.")

    verdict("SPF", spf_result)
    verdict("DKIM", dkim_result)
    verdict("DMARC", dmarc_result, good_values=("pass",))

    if spf_comment:
        report.add("Authentication", "INFO", "SPF verification details (from Authentication-Results)",
                    spf_comment.strip())

    # DMARC enforcement policy detail: pass/fail alone doesn't say whether the
    # domain actually enforces anything (p=none is "monitor only").
    if dmarc_policy_comment:
        pol_tags = dict((k.lower(), v) for k, v in re.findall(r'(\w+)\s*=\s*(\w+)', dmarc_policy_comment))
        p = pol_tags.get("p", "").lower()
        sp = pol_tags.get("sp", "").lower()
        if p:
            if p == "reject":
                report.add("Authentication", "GOOD", f"Domain DMARC policy: p={p}",
                            "The domain enforces rejection of messages failing SPF/DKIM (alignment) "
                            "- the strongest level of protection against spoofing.")
            elif p == "quarantine":
                report.add("Authentication", "GOOD", f"Domain DMARC policy: p={p}",
                            "The domain sends non-compliant messages to quarantine/spam - good protection, "
                            "though weaker than p=reject.")
            elif p == "none":
                report.add("Authentication", "MEDIUM", f"Domain DMARC policy: p={p}",
                            "Monitoring-only mode - non-compliant messages ARE DELIVERED. "
                            "The domain is not effectively protected against spoofing despite publishing a DMARC record.")
            if sp and sp != p:
                report.add("Authentication", "INFO", f"DMARC policy for subdomains: sp={sp}",
                            "A separate (weaker/stronger) policy is enforced for subdomains - consider "
                            "verifying consistency with the main policy.")

    # DKIM signature detail analysis (algorithm, domain alignment)
    for dk in dkim_headers:
        tags = dict((k.lower(), v.strip()) for k, v in DKIM_TAG_RE.findall(dk))
        algo = tags.get("a", "")
        d_domain = tags.get("d", "")
        selector = tags.get("s", "")
        if selector:
            report.dkim_selectors.append(f"{selector}._domainkey.{d_domain}" if d_domain else selector)
        if "sha1" in algo.lower():
            report.add("Authentication", "MEDIUM",
                        f"Weak DKIM signature algorithm: {algo}",
                        "SHA-1 is considered cryptographically weak - rsa-sha256 or stronger is recommended.")
        elif algo:
            report.add("Authentication", "GOOD",
                        f"DKIM: strong signature algorithm ({algo}), domain d={d_domain}, selector s={selector}",
                        "The DKIM signature algorithm complies with current recommendations.")
        if d_domain and from_domain and d_domain.lower() != from_domain.lower():
            report.add("Authentication", "LOW",
                        f"DKIM d={d_domain} differs from the From domain ({from_domain})",
                        "May be normal when sending through an external ESP (e.g. SendGrid/Mailgun) "
                        "but it is worth verifying consistency with the DMARC policy (alignment).")

        # l= (body length limit) lets an attacker append arbitrary unsigned
        # content after the signed portion without invalidating the DKIM
        # signature - a well-known, concrete DKIM weakness worth flagging.
        if "l" in tags:
            report.add("Authentication", "HIGH",
                        f"DKIM-Signature contains the l={tags['l']} tag (body length limit)",
                        "The l= tag limits the signed portion of the message body - it allows "
                        "appending unsigned content after the signed part without invalidating "
                        "the DKIM signature (the so-called DKIM length-attribute attack). Removing "
                        "this tag (signing the entire body) is recommended.")

        # Expiry check (t=created, x=expires, both unix timestamps)
        if "x" in tags:
            try:
                exp_ts = int(tags["x"])
                if exp_ts < datetime.now(timezone.utc).timestamp():
                    exp_dt = datetime.fromtimestamp(exp_ts, tz=timezone.utc)
                    report.add("Authentication", "LOW",
                                f"DKIM signature has an x= tag (expired: {exp_dt.isoformat()})",
                                "According to the DKIM specification, a signature past its expiry date should "
                                "be treated as invalid, although many verifiers ignore this.")
            except (ValueError, OSError):
                pass

        # Selector naming can leak the underlying ESP or environment.
        if selector:
            for prov_name, pat in KNOWN_SELECTOR_PATTERNS:
                if pat.match(selector):
                    report.add("Authentication", "INFO",
                                f"DKIM selector '{selector}' points to: {prov_name}",
                                "The selector naming reveals the likely mail provider "
                                "according to a well-known naming convention.")
                    break
            env_m = ENV_INDICATOR_RE.search(selector)
            if env_m:
                report.add("Authentication", "LOW",
                            f"DKIM selector '{selector}' reveals an environment indicator: {env_m.group(1)}",
                            "The selector name suggests an environment (dev/test/staging/prod) - a minor "
                            "leak of information about the sender's infrastructure organization.")

    if from_domain and return_path_domain and from_domain != return_path_domain:
        report.add("Authentication", "LOW",
                    f"Return-Path ({return_path_domain}) differs from the From domain ({from_domain})",
                    "Typical when using mailing lists/ESPs, but also a classic pattern "
                    "used in phishing/BEC - verify the context.")

    if not auth_results_headers and not received_spf_headers and not dkim_headers:
        report.add("Authentication", "MEDIUM",
                    "No e-mail authentication headers at all (SPF/DKIM/DMARC/ARC)",
                    "Either the recipient server does not perform/add these verifications, or "
                    "the headers were removed before the file was submitted for analysis.")

    report.auth = auth_info


# ---------------------------------------------------------------------------
# 4. Other interesting headers
# ---------------------------------------------------------------------------
def analyze_interesting(msg, report):
    interesting = []

    for hname in INTERESTING_HEADER_NAMES:
        vals = get_all(msg, hname)
        for v in vals:
            interesting.append((hname, v))

    # Any other non-standard X- header not already covered
    covered = set(h.lower() for h in INTERESTING_HEADER_NAMES) | {"received", "dkim-signature", "authentication-results"}
    for name, value in msg.items():
        low = name.lower()
        if low.startswith("x-") and low not in covered:
            interesting.append((name, value))
            covered.add(low)

    for name, value in interesting:
        report.add("Interesting Headers", "INFO", f"{name}: {str(value)[:150]}")

    report.interesting = interesting

    # From / Reply-To mismatch (classic BEC / phishing indicator)
    from_addr = email.utils.parseaddr(msg.get("From", ""))[1]
    reply_to_addr = email.utils.parseaddr(msg.get("Reply-To", ""))[1] if msg.get("Reply-To") else None
    if reply_to_addr:
        from_domain = get_domain(from_addr)
        reply_domain = get_domain(reply_to_addr)
        if from_domain and reply_domain and from_domain != reply_domain:
            report.add("Interesting Headers", "MEDIUM",
                        f"Reply-To ({reply_to_addr}) points to a different domain than From ({from_addr})",
                        "A classic pattern used in BEC/phishing attacks - replies "
                        "go to a different address/domain than the visible sender.")

    # Message-ID domain vs From domain
    msg_id = msg.get("Message-ID", "")
    mid_domain_m = re.search(r'@([\w.\-]+)>?$', msg_id.strip())
    if mid_domain_m:
        mid_domain = mid_domain_m.group(1).lower()
        from_domain = get_domain(from_addr)
        if from_domain and mid_domain != from_domain:
            report.add("Interesting Headers", "LOW",
                        f"The Message-ID domain ({mid_domain}) differs from the From domain ({from_domain})",
                        "May indicate sending through an external system (ESP/CRM/marketing "
                        "automation) generating messages on behalf of the From domain - worth identifying "
                        "the actual sending system (an additional recon vector).")

    # X-Spam-Status can reveal spam filter engine + thresholds
    spam_status = msg.get("X-Spam-Status")
    if spam_status:
        report.add("Interesting Headers", "LOW",
                    "Anti-spam filter status/parameters disclosed (X-Spam-Status)",
                    f"Value: {spam_status[:200]} - may reveal the engine in use "
                    "(e.g. SpamAssassin) and score thresholds, useful for bypassing filters.")

    # Precedence: bulk/list-unsubscribe can indicate marketing/automation infra
    if msg.get("List-Unsubscribe"):
        report.add("Interesting Headers", "INFO",
                    "List-Unsubscribe header present",
                    "Indicates bulk/marketing sending (ESP) rather than a 1:1 mail client.")


# ---------------------------------------------------------------------------
# 4a. Internal infrastructure disclosure (hostnames revealing internal topology)
# ---------------------------------------------------------------------------
def analyze_internal_disclosure(report):
    """Flags hostnames that leak internal network/organizational structure:
    internal-only TLDs (.local/.internal/.corp/.lan), infra-role naming
    conventions (dc01, mail02, exchange01...), and environment indicators
    (dev/test/staging/uat/prod). Pure pattern matching on already-collected
    hostnames - no network needed."""
    for host in report.hostnames:
        signals = []
        if INTERNAL_DOMAIN_SUFFIX_RE.search(host):
            signals.append("internal domain suffix (.local/.internal/.corp/.lan)")
        if INFRA_ROLE_HOSTNAME_RE.match(host):
            signals.append("name suggesting an infrastructure role (e.g. dcNN/mailNN/exchangeNN)")
        env_m = ENV_INDICATOR_RE.search(host)
        if env_m:
            signals.append(f"environment indicator in the name: '{env_m.group(1)}'")

        if signals:
            report.add(
                "Information Disclosure", "MEDIUM",
                f"Disclosed hostname suggesting internal infrastructure: {host}",
                "; ".join(signals) + ". Names of this kind make it easier to map the target's internal/"
                                     "organizational network structure and are useful for further recon."
            )


# ---------------------------------------------------------------------------
# 4c. DMARC/SPF/DKIM alignment correlation (auth-results vs actual headers)
# ---------------------------------------------------------------------------
def _org_domain(domain):
    """Very rough 'organizational domain' approximation (last two labels).
    Good enough for relaxed-alignment comparison; doesn't consult the Public
    Suffix List, so multi-part TLDs (co.uk, com.pl) can occasionally
    under-strip - acceptable for a recon-level heuristic."""
    if not domain:
        return domain
    parts = domain.lower().split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else domain.lower()


def analyze_dmarc_alignment(msg, report):
    """Computes actual DMARC alignment locally instead of trusting a bare
    dmarc=pass/fail verdict: DMARC passes if EITHER SPF or DKIM is aligned
    with the visible From: domain, and this can hide a real gap (e.g. SPF
    identity totally unrelated to From, masked by a passing DKIM signature).
    Runs unconditionally - pure header correlation, no network required.
    Uses adkim/aspf from report.dmarc_dns_policy (fetched under --dns/--deep)
    to pick strict vs relaxed comparison when available, else defaults to
    DMARC's own default (relaxed)."""
    from_domain = get_domain(email.utils.parseaddr(msg.get("From", ""))[1])
    if not from_domain:
        return

    spf_mailfrom_domain = None
    for h in get_all(msg, "Authentication-Results"):
        m = re.search(r'smtp\.mailfrom=([\w.\-]+@[\w.\-]+|[\w.\-]+)', h, re.I)
        if m:
            captured = m.group(1)
            spf_mailfrom_domain = get_domain(captured) if "@" in captured else captured.lower()
            break
    if not spf_mailfrom_domain:
        rp = email.utils.parseaddr(msg.get("Return-Path", ""))[1]
        spf_mailfrom_domain = get_domain(rp)

    dkim_domains = set()
    for dk in get_all(msg, "DKIM-Signature"):
        tags = dict((k.lower(), v.strip()) for k, v in DKIM_TAG_RE.findall(dk))
        if tags.get("d"):
            dkim_domains.add(tags["d"].lower())

    if not spf_mailfrom_domain and not dkim_domains:
        return  # nothing to correlate against

    adkim = "relaxed"
    aspf = "relaxed"
    if report.dmarc_dns_policy:
        adkim = "strict" if report.dmarc_dns_policy.get("adkim") == "s" else "relaxed"
        aspf = "strict" if report.dmarc_dns_policy.get("aspf") == "s" else "relaxed"

    def is_aligned(domain, mode):
        if not domain:
            return None
        if mode == "strict":
            return domain.lower() == from_domain.lower()
        return _org_domain(domain) == _org_domain(from_domain)

    spf_aligned = is_aligned(spf_mailfrom_domain, aspf)
    dkim_aligned = any(is_aligned(d, adkim) for d in dkim_domains) if dkim_domains else None

    def fmt(v):
        return "PASS" if v else ("FAIL" if v is False else "N/A")

    report.add(
        "Authentication", "GOOD" if spf_aligned else ("MEDIUM" if spf_aligned is False else "INFO"),
        f"SPF alignment (computed locally): {fmt(spf_aligned)}",
        f"From: {from_domain}  vs  SPF/mailfrom: {spf_mailfrom_domain or 'no data'}  "
        f"(mode: {aspf})."
    )
    if dkim_domains:
        report.add(
            "Authentication", "GOOD" if dkim_aligned else "MEDIUM",
            f"DKIM alignment (computed locally): {fmt(dkim_aligned)}",
            f"From: {from_domain}  vs  DKIM d=: {', '.join(sorted(dkim_domains))}  (mode: {adkim})."
        )

    if spf_aligned and dkim_aligned is False:
        report.add(
            "Authentication", "INFO",
            "DMARC passes solely thanks to SPF alignment - the present DKIM is misaligned",
            "The message formally passes DMARC (one of the two mechanisms is enough), but "
            "the DKIM signature points to a domain (d=) unrelated to the From domain. This is a legitimate pattern "
            "when sending through an ESP/relay, but it is worth verifying whether this is the expected path."
        )
    elif dkim_aligned and spf_aligned is False:
        report.add(
            "Authentication", "INFO",
            "DMARC passes solely thanks to DKIM alignment - the SPF identity is misaligned",
            "The message formally passes DMARC, but the SPF domain (smtp.mailfrom) differs "
            "from the From domain. This is a legitimate pattern when sending through an ESP/relay (e.g. bounces "
            "via another domain), but it is worth verifying whether this is the expected sending path."
        )
    elif spf_aligned is False and dkim_aligned is False:
        report.add(
            "Authentication", "HIGH",
            "Neither SPF nor DKIM is aligned with the From domain",
            "Despite a possible dmarc=pass reported by the recipient, local correlation does not "
            "confirm that any mechanism is tied to the visible sender domain - verify "
            "manually, this is an unusual/suspicious configuration."
        )


# ---------------------------------------------------------------------------
# 4d. ARC chain continuity (lightweight - instance numbering only)
# ---------------------------------------------------------------------------
def analyze_arc_chain(msg, report):
    """ARC-Seal/ARC-Message-Signature/ARC-Authentication-Results all carry an
    i= instance number that should form a contiguous 1..N sequence across an
    ARC chain. A gap or mismatch between the three header sets suggests a
    broken/tampered chain - informational for recon, not a hard verdict since
    full ARC validation requires cryptographic verification this tool doesn't
    perform."""
    def instances(header_name):
        vals = get_all(msg, header_name)
        nums = set()
        for v in vals:
            m = re.search(r'\bi\s*=\s*(\d+)', v)
            if m:
                nums.add(int(m.group(1)))
        return nums

    seal_i = instances("ARC-Seal")
    msig_i = instances("ARC-Message-Signature")
    ar_i = instances("ARC-Authentication-Results")

    if not (seal_i or msig_i or ar_i):
        return

    report.add("Authentication", "INFO", f"ARC chain present (instances: {sorted(seal_i)})",
                "ARC lets intermediaries (e.g. mailing lists) preserve the original "
                "authentication result despite modifications to the message along the way.")

    if seal_i != msig_i or seal_i != ar_i:
        report.add(
            "Authentication", "LOW",
            "Inconsistent instance numbering (i=) between ARC-Seal/ARC-Message-Signature/ARC-Authentication-Results",
            f"ARC-Seal: {sorted(seal_i)}, ARC-Message-Signature: {sorted(msig_i)}, "
            f"ARC-Authentication-Results: {sorted(ar_i)}. They should be identical - a discrepancy "
            "may indicate an incomplete/corrupted ARC chain or header tampering."
        )

    expected = set(range(1, max(seal_i, default=0) + 1))
    if seal_i and seal_i != expected:
        report.add(
            "Authentication", "LOW",
            f"ARC chain has a gap in instance numbering: {sorted(seal_i)} (expected 1..{max(seal_i)})",
            "Contiguous numbering i=1,2,3... is required for a valid ARC chain - a gap "
            "suggests a removed/skipped link in the intermediary chain."
        )


# ---------------------------------------------------------------------------
# 4b. Header injection anomalies + open-relay / spoofing heuristics
# ---------------------------------------------------------------------------
def analyze_injection(msg, raw_bytes, report):
    # 1) Duplicate singleton headers - a message should carry at most one of
    #    each of these; more than one is a classic artifact of successful or
    #    attempted header injection (e.g. unsanitised PHP mail() form field
    #    letting an attacker inject "\nBcc: ...").
    for hname in SINGLETON_HEADERS:
        vals = get_all(msg, hname)
        if len(vals) > 1:
            report.add(
                "Injection", "HIGH",
                f"Header '{hname}' appears {len(vals)} times (should appear at most once)",
                "Strong header injection indicator - e.g. a sending form (PHP mail()/"
                "PHPMailer without proper sanitization) that allows injecting additional "
                "headers (Bcc/Cc/To) via CR/LF characters in an input field."
            )

    # 2) Encoded/escaped CRLF sequences that leaked into a header value instead
    #    of being interpreted - sign of a payload that partially succeeded or
    #    was double-encoded by an intermediate system.
    for name, value in msg.items():
        val_str = str(value)
        if INJECTION_ENCODED_CRLF_RE.search(val_str):
            report.add(
                "Injection", "MEDIUM",
                f"Suspicious encoded CRLF sequence in header '{name}'",
                f"Value contains a literal '%0d%0a'/'\\r\\n': {val_str[:150]} "
                "- may be a remnant of a (failed) header injection attempt "
                "against the form generating this message."
            )

    # 3) Raw control characters in the header block of the ORIGINAL file
    #    (before the parser normalised anything away).
    try:
        header_block = raw_bytes.split(b"\r\n\r\n")[0].split(b"\n\n")[0]
        text = header_block.decode("utf-8", errors="ignore")
        control_chars = [c for c in text if ord(c) < 32 and c not in "\r\n\t"]
        if control_chars:
            report.add(
                "Injection", "MEDIUM",
                "Non-standard control characters detected in the header section",
                f"Control bytes found (ord): {sorted(set(ord(c) for c in control_chars))} "
                "- may be an artifact of a header injection attempt or file corruption."
            )
    except Exception:
        pass


def analyze_relay_heuristics(msg, report, use_dns):
    """Best-effort, clearly-labelled heuristics only - static header analysis
    cannot definitively prove an open relay (that requires active SMTP probing,
    out of scope here). These findings are recon leads to verify manually."""
    hops = report.infra_hops
    network_hops = [h for h in hops if not h["is_loopback_hop"]]
    if not network_hops:
        return

    from_addr = email.utils.parseaddr(msg.get("From", ""))[1]
    from_domain = get_domain(from_addr)

    origin = network_hops[-1]  # closest to the actual sender
    origin_host = origin.get("from_host")
    origin_domain = None
    if origin_host:
        parts = origin_host.split(".")
        origin_domain = ".".join(parts[-2:]) if len(parts) >= 2 else origin_host

    provider_names = {p["name"] for p in report.providers}

    if from_domain and origin_domain and origin_domain not in from_domain and from_domain not in origin_domain:
        if not provider_names:
            report.add(
                "Relay/Spoofing", "LOW",
                f"The source server ({origin_host}) is not associated with the sender domain ({from_domain}) "
                "or with a recognized mail provider (ESP)",
                "Heuristic - also typical of legitimate sending through an external CRM/mailing "
                "system. Verify manually whether this is an authorized sender on behalf of the "
                "domain (e.g. an SPF entry) or a potential relay/spoofing."
            )

    # Reverse-DNS (PTR) consistency check for the origin hop's public IP -
    # only run with --dns since it needs live network access.
    if use_dns:
        public_ips = [ip for ip in origin["ips"] if not is_private_ip(ip)]
        for ip in public_ips:
            try:
                socket.setdefaulttimeout(5)
                ptr_host = socket.gethostbyaddr(ip)[0]
                ptr_host_clean = strip_dot(ptr_host).lower()
                claimed = strip_dot(origin_host).lower() if origin_host else ""
                if claimed and claimed not in ("unknown",) and\
                        ptr_host_clean.split(".")[-2:] != claimed.split(".")[-2:]:
                    report.add(
                        "Relay/Spoofing", "MEDIUM",
                        f"HELO/rDNS mismatch for {ip}: the header declares '{origin_host}', "
                        f"while PTR points to '{ptr_host}'",
                        "Discrepancy between the declared hostname (HELO/EHLO) and the actual "
                        "PTR record in DNS - typical of sender spoofing or a relay without "
                        "proper DNS configuration. Verify manually."
                    )
            except (socket.herror, socket.gaierror, socket.timeout, OSError):
                report.add(
                    "Relay/Spoofing", "INFO",
                    f"No PTR record (reverse DNS) for {ip}",
                    "The source hop's IP address has no PTR record - not necessarily a problem, "
                    "but it makes verifying the server's identity harder and is characteristic of "
                    "misconfigured/illegitimate relays."
                )


# ---------------------------------------------------------------------------
# 6. OSINT / recon extras: timing consistency + Message-ID predictability
# ---------------------------------------------------------------------------
def _parse_hop_datetime(raw_hop_text):
    if ";" not in raw_hop_text:
        return None
    tail = raw_hop_text.rsplit(";", 1)[-1].strip()
    try:
        dt = email.utils.parsedate_to_datetime(tail)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None


def analyze_timing(msg, report):
    """Cross-checks Date: against the Received chain timestamps. Large or
    negative discrepancies can indicate clock skew between servers - or, less
    commonly, a manually altered Date header used to muddy an incident
    timeline during forensic/log analysis."""
    hops = report.infra_hops
    if not hops:
        return

    date_header = msg.get("Date")
    date_dt = None
    if date_header:
        try:
            date_dt = email.utils.parsedate_to_datetime(date_header)
            if date_dt.tzinfo is None:
                date_dt = date_dt.replace(tzinfo=timezone.utc)
        except Exception:
            date_dt = None

    hop_times = [(hop["index"], _parse_hop_datetime(hop["raw"])) for hop in hops]
    hop_times = [(i, dt) for i, dt in hop_times if dt is not None]

    if date_dt and hop_times:
        newest_idx, newest_dt = hop_times[0]
        delta_h = (newest_dt - date_dt).total_seconds() / 3600
        if abs(delta_h) > 24:
            sev = "MEDIUM" if abs(delta_h) > 168 else "LOW"
            report.add(
                "OSINT/Recon", sev,
                f"Discrepancy between the Date header and the time the message was received: ~{abs(delta_h):.1f}h",
                f"Date: {date_header}  vs.  Received hop #{newest_idx}: {newest_dt.isoformat()}. "
                "A large discrepancy usually results from a clock error on the sender's server, but it is worth "
                "verifying that the Date header was not manually altered (e.g. to "
                "falsify an incident's chronology)."
            )

    # Chronological order: hops[0] (most recently added / closest to recipient)
    # should be timestamped at or after every hop further down the chain.
    # Also attach the hop-to-hop delta onto each hop dict for display, and
    # flag unusually large gaps (queuing, greylisting, batch relay, or - more
    # rarely - a suspicious hold-and-forward step).
    hop_by_index = {hop["index"]: hop for hop in hops}
    for i in range(len(hop_times) - 1):
        idx_a, dt_a = hop_times[i]
        idx_b, dt_b = hop_times[i + 1]

        delta_s = (dt_a - dt_b).total_seconds()
        if idx_a in hop_by_index:
            hop_by_index[idx_a]["delta_seconds"] = delta_s

        if dt_a < dt_b - timedelta(minutes=2):
            report.add(
                "OSINT/Recon", "LOW",
                f"Received headers #{idx_a} and #{idx_b} are in reversed chronological order",
                f"Hop #{idx_a} ({dt_a.isoformat()}) should be equal to or later than "
                f"hop #{idx_b} ({dt_b.isoformat()}) in the chain, but it is earlier - typically "
                "a time zone/clock difference between servers, less often a header modification."
            )
        elif delta_s > 3600:
            report.add(
                "OSINT/Recon", "LOW",
                f"Large time gap between hops #{idx_b} and #{idx_a}: ~{delta_s/3600:.1f}h",
                "May result from queuing on an intermediate server (e.g. greylisting, "
                "anti-spam queue, batch relay) - less often from a deliberate delay "
                "introduced by an intermediary."
            )


MESSAGE_ID_NUMERIC_RE = re.compile(r'^\d{1,15}$')
MESSAGE_ID_SHORT_HEX_RE = re.compile(r'^[0-9a-fA-F]{1,8}$')


def analyze_message_id(msg, report):
    """Weak/predictable Message-ID local-parts (short, sequential, or purely
    numeric) can allow an attacker to enumerate other messages generated by
    the same system - a minor but genuine recon signal."""
    mid = (msg.get("Message-ID") or "").strip()
    m = re.match(r'<([^@>]+)@', mid)
    if not m:
        return
    local = m.group(1)

    if MESSAGE_ID_NUMERIC_RE.match(local):
        report.add(
            "OSINT/Recon", "LOW",
            f"Message-ID has a simple, numeric local part: '{local}'",
            "Suggests a possibly sequential/predictable identifier generator on the "
            "sending system's side - potentially allows guessing/enumerating other "
            "messages generated by the same system (e.g. confirmations/reservations)."
        )
    elif MESSAGE_ID_SHORT_HEX_RE.match(local):
        report.add(
            "OSINT/Recon", "LOW",
            f"Message-ID has a short, low-entropy local part: '{local}'",
            "A short hex identifier may indicate a weak randomness generator used "
            "to build the Message-ID - a potential (low) vector for enumerating messages."
        )


EMAIL_ADDR_RE = re.compile(r'\b[\w.\-+]+@[\w.\-]+\.[a-zA-Z]{2,}\b')
URL_RE = re.compile(r'\bhttps?://[^\s<>"\'\)]+', re.I)


def build_iocs(msg, report):
    """Consolidates indicators of compromise / recon artifacts already
    extracted by other analyzers into one place - handy to carry forward
    into a pentest report or a blocklist/allowlist review. Pure aggregation,
    no new network activity."""
    ipv4, ipv6 = set(), set()
    for hop in report.infra_hops:
        for ip in hop["ips"]:
            try:
                if isinstance(ipaddress.ip_address(ip), ipaddress.IPv4Address):
                    ipv4.add(ip)
                else:
                    ipv6.add(ip)
            except ValueError:
                pass

    domains = set()
    for host in report.hostnames:
        domains.add(strip_dot(host).lower())
    from_domain = get_domain(email.utils.parseaddr(msg.get("From", ""))[1])
    if from_domain:
        domains.add(from_domain)

    emails = set()
    for hname in ["From", "To", "Cc", "Reply-To", "Return-Path", "Sender"]:
        val = msg.get(hname)
        if val:
            emails.update(m.lower() for m in EMAIL_ADDR_RE.findall(str(val)))

    urls = set()
    for name, value in msg.items():
        urls.update(URL_RE.findall(str(value)))

    message_ids = set()
    for hname in ["Message-ID", "In-Reply-To", "References"]:
        val = msg.get(hname)
        if val:
            message_ids.update(re.findall(r'<[^<>]+>', str(val)))

    report.iocs = {
        "ipv4": sorted(ipv4),
        "ipv6": sorted(ipv6),
        "domains": sorted(domains),
        "emails": sorted(emails),
        "urls": sorted(urls),
        "dkim_selectors": sorted(set(report.dkim_selectors)),
        "message_ids": sorted(message_ids),
    }


# ---------------------------------------------------------------------------
# 5. Optional live DNS checks
# ---------------------------------------------------------------------------
def analyze_dns(msg, report):
    if not HAS_DNS:
        report.add("DNS", "INFO", "Live DNS queries skipped",
                    "The 'dnspython' module is not installed. Install it with: pip install dnspython")
        return

    from_addr = email.utils.parseaddr(msg.get("From", ""))[1]
    domain = get_domain(from_addr)
    if not domain:
        return

    resolver = dns.resolver.Resolver()
    resolver.lifetime = 5
    posture = {"domain": domain, "spf": None, "dmarc": None, "mx": None,
               "mta_sts": None, "tls_rpt": None, "dnssec": None}

    # SPF (TXT record starting with v=spf1)
    try:
        answers = resolver.resolve(domain, "TXT")
        spf_records = [r.to_text() for r in answers if "v=spf1" in r.to_text()]
        if spf_records:
            posture["spf"] = "found"
            report.add("DNS", "INFO", f"SPF record found for domain {domain}",
                        "; ".join(spf_records))
            for rec in spf_records:
                if "+all" in rec:
                    posture["spf"] = "weak (+all)"
                    report.add("DNS", "CRITICAL", f"SPF of domain {domain} contains '+all'",
                                "Allows sending from ANY server without rejection - "
                                "a critical SPF misconfiguration.")
                elif "?all" in rec:
                    posture["spf"] = "weak (?all)"
                    report.add("DNS", "MEDIUM", f"SPF of domain {domain} contains '?all' (neutral)",
                                "Weak SPF policy - does not clearly state what to do with "
                                "unauthorized sources.")
        else:
            posture["spf"] = "missing"
            report.add("DNS", "HIGH", f"No SPF record for domain {domain}",
                        "The domain does not publish an SPF policy - makes sender address spoofing easier.")
    except Exception as e:
        report.add("DNS", "INFO", f"Could not fetch SPF for {domain}", str(e))

    # DMARC (_dmarc.<domain> TXT) - full tag parse: p/sp/pct/adkim/aspf/rua/ruf
    try:
        answers = resolver.resolve(f"_dmarc.{domain}", "TXT")
        dmarc_records = [r.to_text() for r in answers if "v=dmarc1" in r.to_text().lower()]
        if dmarc_records:
            rec = dmarc_records[0].strip('"')
            tags = dict((k.lower(), v) for k, v in re.findall(r'(\w+)\s*=\s*([^;]+);?', rec))
            report.dmarc_dns_policy = tags
            p = tags.get("p", "").strip().lower()
            pct = tags.get("pct", "100").strip()
            posture["dmarc"] = f"p={p}" if p else "found"

            report.add("DNS", "INFO", f"DMARC record found for domain {domain}", rec)
            if p == "none":
                report.add("DNS", "MEDIUM", f"DMARC policy of domain {domain} is set to p=none",
                            "Messages failing SPF/DKIM are neither rejected nor quarantined "
                            "- monitoring only. Makes spoofing easier.")
            try:
                pct_val = int(pct)
                if pct_val < 100:
                    report.add("DNS", "MEDIUM", f"DMARC of domain {domain} is enforced for only {pct_val}% of messages (pct={pct_val})",
                                "Partial DMARC rollout - the remaining non-compliant messages "
                                "bypass the enforced policy (p=). Typical during a gradual rollout, "
                                "but it means a real protection gap until pct=100.")
            except ValueError:
                pass
            if not tags.get("rua") and not tags.get("ruf"):
                report.add("DNS", "LOW", f"Domain {domain} has no DMARC reporting configured (rua/ruf)",
                            "No addresses for aggregate (rua) and forensic (ruf) reports - "
                            "the domain owner gets no visibility into abuse/spoofing attempts "
                            "against their domain, even if the p= policy is set correctly.")
        else:
            posture["dmarc"] = "missing"
            report.add("DNS", "HIGH", f"No DMARC record for domain {domain}",
                        "No DMARC policy - the domain does not protect itself against spoofing at "
                        "the receiving-policy level.")
    except Exception as e:
        posture["dmarc"] = "missing/error"
        report.add("DNS", "HIGH", f"No DMARC record / error for {domain}", str(e))

    # MX records - basic infra info
    try:
        mx_answers = resolver.resolve(domain, "MX")
        mx_hosts = sorted([str(r.exchange).rstrip('.') for r in mx_answers])
        report.mx_hosts = mx_hosts
        posture["mx"] = ", ".join(mx_hosts) if mx_hosts else None
        report.add("DNS", "INFO", f"MX records of domain {domain}", ", ".join(mx_hosts))
    except Exception:
        pass

    # BIMI (Brand Indicators for Message Identification) - presence indicates
    # extra investment in mail-brand security; absence is informational only.
    try:
        bimi_answers = resolver.resolve(f"default._bimi.{domain}", "TXT")
        bimi_records = [r.to_text() for r in bimi_answers if "v=bimi1" in r.to_text().lower()]
        if bimi_records:
            report.add("DNS", "INFO", f"BIMI record found for domain {domain}", bimi_records[0])
    except Exception:
        pass

    # MTA-STS (enforces TLS for inbound mail at the policy level)
    try:
        resolver.resolve(f"_mta-sts.{domain}", "TXT")
        posture["mta_sts"] = "found"
        report.add("DNS", "GOOD", f"Domain {domain} publishes an MTA-STS record",
                    "Indicates policy-level enforcement of TLS encryption for inbound mail - "
                    "makes downgrade/STARTTLS-stripping attacks harder.")
    except Exception:
        posture["mta_sts"] = "missing"
        report.add("DNS", "LOW", f"No MTA-STS record for domain {domain}",
                    "The domain does not publish an MTA-STS policy - inbound mail may be "
                    "vulnerable to an encryption downgrade attack (STARTTLS stripping) if "
                    "the sending server allows it.")

    # TLS-RPT (SMTP TLS Reporting) - complements MTA-STS by giving the domain
    # owner visibility into failed TLS negotiations reported by other MTAs.
    try:
        resolver.resolve(f"_smtp._tls.{domain}", "TXT")
        posture["tls_rpt"] = "found"
        report.add("DNS", "GOOD", f"Domain {domain} publishes a TLS-RPT record",
                    "The domain receives reports on failed TLS encryption attempts from other "
                    "MTAs - useful for detecting downgrade/stripping in practice.")
    except Exception:
        posture["tls_rpt"] = "missing"
        report.add("DNS", "LOW", f"No TLS-RPT record for domain {domain}",
                    "The domain has no visibility into TLS negotiation problems reported by "
                    "other servers - makes detecting downgrade attacks in practice harder.")

    report.posture = posture


def cymru_asn_lookup(ip, resolver):
    """Lightweight ASN/organization lookup via Team Cymru's public DNS
    service - no extra dependency beyond dnspython (already optional)."""
    try:
        ip_obj = ipaddress.ip_address(ip)
        if not isinstance(ip_obj, ipaddress.IPv4Address):
            return None  # IPv6 uses a different (nibble) query format - skipped for simplicity
        octets = ip.split(".")
        query = ".".join(reversed(octets)) + ".origin.asn.cymru.com"
        answers = resolver.resolve(query, "TXT")
        txt = answers[0].to_text().strip('"')
        parts = [p.strip() for p in txt.split("|")]
        if not parts or not parts[0]:
            return None
        asn = parts[0].split()[0]  # can list multiple ASNs space-separated; take first
        country = parts[2] if len(parts) > 2 else None

        org = None
        try:
            name_answers = resolver.resolve(f"AS{asn}.asn.cymru.com", "TXT")
            name_txt = name_answers[0].to_text().strip('"')
            name_parts = [p.strip() for p in name_txt.split("|")]
            org = name_parts[-1] if name_parts else None
        except Exception:
            pass

        return {"asn": asn, "country": country, "org": org}
    except Exception:
        return None


def analyze_dkim_key_strength(msg, report):
    """Fetches the DKIM public key(s) referenced by DKIM-Signature headers
    directly from DNS (<selector>._domainkey.<domain>) and estimates RSA key
    size. Short keys (<=1024 bit) are a genuine, actionable weakness -
    factoring them is within reach of modern compute."""
    if not HAS_DNS:
        return
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 5

    dkim_headers = get_all(msg, "DKIM-Signature")
    seen_selectors = set()

    for dk in dkim_headers:
        tags = dict((k.lower(), v.strip()) for k, v in DKIM_TAG_RE.findall(dk))
        d_domain = tags.get("d")
        selector = tags.get("s")
        if not d_domain or not selector or (selector, d_domain) in seen_selectors:
            continue
        seen_selectors.add((selector, d_domain))
        query = f"{selector}._domainkey.{d_domain}"

        try:
            answers = resolver.resolve(query, "TXT")
            raw_txt = b"".join(answers[0].strings).decode(errors="replace")
        except Exception as e:
            report.add("DNS", "LOW", f"Could not fetch the DKIM key for {query}",
                        f"The DNS TXT query failed ({e}) - the selector may have been "
                        "removed/rotated, or the domain uses a different key location.")
            continue

        dns_tags = dict((k.lower(), v.strip()) for k, v in DKIM_TAG_RE.findall(raw_txt))
        p_value = dns_tags.get("p", "")
        if not p_value:
            report.add("DNS", "MEDIUM", f"DKIM record {query} contains no active public key",
                        "An empty p= tag means a revoked/retired selector (key revocation) - "
                        "messages signed with this selector will no longer pass DKIM verification.")
            continue

        try:
            key_bytes = base64.b64decode(p_value + "=" * (-len(p_value) % 4))
            n = len(key_bytes)
            # Rough size buckets based on typical DER-encoded RSA SubjectPublicKeyInfo length.
            if n < 100:
                approx_bits = 512
            elif n < 180:
                approx_bits = 1024
            elif n < 300:
                approx_bits = 2048
            elif n < 500:
                approx_bits = 3072
            else:
                approx_bits = 4096

            if approx_bits <= 1024:
                sev = "HIGH"
            elif approx_bits < 2048:
                sev = "MEDIUM"
            else:
                sev = "GOOD"

            report.add(
                "DNS", sev,
                f"DKIM public key {query}: estimated ~{approx_bits}-bit RSA",
                f"Estimated from the decoded key length ({n} bytes) - "
                f"approximate value, does not parse the full ASN.1 structure. Keys <=1024 bit "
                f"are considered cryptographically weak (factoring is within reach of modern "
                f"computing resources) and should be rotated to >=2048 bit."
            )
        except Exception:
            pass


def analyze_asn(report):
    """OSINT / infra-mapping helper: resolve ASN + organization + country for
    every unique public IP seen in the Received chain (requires --dns)."""
    if not HAS_DNS:
        return
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 4

    seen_ips = set()
    for hop in report.infra_hops:
        for ip in hop["ips"]:
            if not is_private_ip(ip) and ip not in seen_ips:
                seen_ips.add(ip)

    for ip in sorted(seen_ips):
        info = cymru_asn_lookup(ip, resolver)
        if info and info.get("asn"):
            report.asn_data[ip] = info
            org = info.get("org") or "unknown organization"
            country = f", country: {info['country']}" if info.get("country") else ""
            report.add("DNS", "INFO", f"{ip}: AS{info['asn']} - {org}{country}",
                        "Data useful for infrastructure mapping / OSINT (hosting provider, "
                        "network operator that owns the IP address).")


# ---------------------------------------------------------------------------
# --deep: full SPF mechanism resolution (recursive, RFC 7208 lookup budget)
# ---------------------------------------------------------------------------
def resolve_spf_mechanisms(domain, resolver, budget=10, depth=0, visited=None):
    """Recursively resolves include:/redirect= chains of an SPF record,
    tracking the DNS-lookup budget (RFC 7208 caps this at 10 - exceeding it
    is a PermError that can cause SPF to fail outright, a real and common
    misconfiguration in orgs with many SPF includes)."""
    if visited is None:
        visited = set()
    if domain in visited or depth > 10 or budget <= 0:
        return [], budget
    visited.add(domain)

    try:
        answers = resolver.resolve(domain, "TXT")
        records = [b"".join(r.strings).decode(errors="replace") for r in answers]
    except Exception:
        return [], budget

    spf_recs = [r for r in records if r.lower().startswith("v=spf1")]
    if not spf_recs:
        return [], budget

    mechanisms = []
    tokens = spf_recs[0].split()[1:]
    for tok in tokens:
        qualifier, t = "+", tok
        if t and t[0] in "+-~?":
            qualifier, t = t[0], t[1:]
        mechanisms.append({"domain": domain, "qualifier": qualifier, "token": t})
        low = t.lower()

        if budget <= 0:
            break
        if low.startswith("include:"):
            budget -= 1
            sub, budget = resolve_spf_mechanisms(t.split(":", 1)[1], resolver, budget, depth + 1, visited)
            mechanisms.extend(sub)
        elif low.startswith("redirect="):
            budget -= 1
            sub, budget = resolve_spf_mechanisms(t.split("=", 1)[1], resolver, budget, depth + 1, visited)
            mechanisms.extend(sub)
        elif low in ("a", "mx") or low.startswith(("a:", "mx:", "a/", "mx/", "exists:", "ptr")):
            budget -= 1

    return mechanisms, budget


def analyze_spf_deep(msg, report):
    """Full SPF authorization map: resolves the include:/redirect= chain,
    counts DNS lookups against the RFC 7208 budget of 10, and flags overly
    broad ip4/ip6 ranges. This is the concrete 'what is actually authorized
    to send' picture, not just a pass/fail verdict."""
    if not HAS_DNS:
        return
    from_addr = email.utils.parseaddr(msg.get("From", ""))[1]
    domain = get_domain(from_addr)
    if not domain:
        return

    resolver = dns.resolver.Resolver()
    resolver.lifetime = 5

    mechanisms, remaining = resolve_spf_mechanisms(domain, resolver, budget=10)
    if not mechanisms:
        return

    lookups_used = 10 - remaining
    report.spf_mechanisms = mechanisms

    if lookups_used >= 10:
        report.add("SPF", "HIGH", f"SPF of domain {domain} reaches/exceeds the 10 DNS lookup limit (RFC 7208)",
                    "Once the limit is exceeded, verifiers return PermError and treat SPF as "
                    "failed (fail) regardless of the actual authorization - a real risk of "
                    "rejecting/marking legitimate mail as spam.")
    elif lookups_used >= 8:
        report.add("SPF", "MEDIUM", f"SPF of domain {domain} is close to the DNS lookup limit: {lookups_used}/10",
                    "Small margin - every additional 'include' may lead to a PermError.")
    else:
        report.add("SPF", "INFO", f"SPF of domain {domain}: {lookups_used}/10 DNS lookups used",
                    "Within the RFC 7208 limit.")

    includes = sorted(set(m["domain"] for m in mechanisms if m["domain"] != domain))
    if includes:
        report.add("SPF", "INFO", f"SPF authorization map - domains pulled in via include/redirect ({len(includes)})",
                    ", ".join(includes))

    for m in mechanisms:
        tok = m["token"]
        low = tok.lower()
        if low.startswith("ip4:"):
            cidr = low.split(":", 1)[1]
            try:
                net = ipaddress.ip_network(cidr, strict=False)
                if net.prefixlen <= 20:
                    report.add("SPF", "MEDIUM", f"SPF authorizes a very broad ip4 range: {cidr} ({net.num_addresses} addresses)",
                                f"Comes from the record of domain {m['domain']}. The broader the range, the larger "
                                "the area that could potentially send mail on behalf of the domain.")
            except ValueError:
                pass
        elif low.startswith("ip6:"):
            cidr = low.split(":", 1)[1]
            try:
                net = ipaddress.ip_network(cidr, strict=False)
                if net.prefixlen <= 48:
                    report.add("SPF", "MEDIUM", f"SPF authorizes a very broad ip6 range: {cidr}",
                                f"Comes from the record of domain {m['domain']}.")
            except ValueError:
                pass
        elif low == "all" and m["qualifier"] == "+":
            report.add("SPF", "CRITICAL", f"'+all' mechanism found in the expanded SPF chain (domain {m['domain']})",
                        "Authorizes sending from any server - a critical misconfiguration.")


# ---------------------------------------------------------------------------
# --deep: PTR/A consistency for every public hop + ASN grouping + DNSSEC
# ---------------------------------------------------------------------------
def analyze_hop_consistency(report):
    """For every public hop IP: reverse-resolve to PTR, then forward-resolve
    the PTR hostname back to A/AAAA and check it actually points back to the
    same IP (full round-trip, not just a bare PTR lookup) - this is the
    'PTR <-> A consistent' check from a proper DNS-correlation pass."""
    if not HAS_DNS:
        return
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 4
    socket.setdefaulttimeout(4)

    checked = set()
    for hop in report.infra_hops:
        for ip in hop["ips"]:
            if is_private_ip(ip) or ip in checked:
                continue
            checked.add(ip)
            try:
                ptr_host = strip_dot(socket.gethostbyaddr(ip)[0])
            except (socket.herror, socket.gaierror, socket.timeout, OSError):
                report.add("DNS", "INFO", f"No PTR record (reverse DNS) for {ip}",
                            "Makes verifying the server's identity harder; some providers (e.g. residential "
                            "links) deliberately do not publish it.")
                continue

            try:
                a_answers = resolver.resolve(ptr_host, "A")
                forward_ips = {r.to_text() for r in a_answers}
            except Exception:
                forward_ips = set()

            if ip in forward_ips:
                report.add("DNS", "GOOD", f"{ip} <-> {ptr_host}: PTR and A consistent (forward-confirmed)",
                            "Full PTR/A consistency - typical of properly configured, "
                            "legitimate mail infrastructure.")
            elif forward_ips:
                report.add("DNS", "MEDIUM", f"{ip} -> PTR {ptr_host}, but A({ptr_host}) does not point back to {ip}",
                            f"A({ptr_host}) = {', '.join(sorted(forward_ips))}. A lack of forward-confirmed "
                            "rDNS consistency is often characteristic of unauthorized "
                            "relays/spoofing, though it also happens with sloppy DNS configuration.")
            else:
                report.add("DNS", "LOW", f"{ip} -> PTR {ptr_host}, but no A record for {ptr_host}",
                            "The PTR name does not resolve back to any address - "
                            "incomplete DNS configuration on the host owner's side.")


def analyze_asn_grouping(report):
    """Groups already-resolved ASN data (from analyze_asn) to answer 'do the
    hops in this chain belong to the same network operator as the domain's
    own MX'? A mismatch isn't inherently bad (many orgs use third-party
    relays) but is a useful infra-mapping signal."""
    if not report.asn_data:
        return

    by_asn = {}
    for ip, info in report.asn_data.items():
        by_asn.setdefault(info["asn"], []).append(ip)

    if len(by_asn) > 1:
        lines = [f"AS{asn}: {', '.join(ips)}" for asn, ips in sorted(by_asn.items())]
        report.add("DNS", "INFO", f"IP addresses in the Received chain belong to {len(by_asn)} different ASNs",
                    "; ".join(lines))

    mx_asns = set()
    if report.mx_hosts and HAS_DNS:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 4
        for mx_host in report.mx_hosts:
            try:
                a_answers = resolver.resolve(mx_host, "A")
                for r in a_answers:
                    info = cymru_asn_lookup(r.to_text(), resolver)
                    if info and info.get("asn"):
                        mx_asns.add(info["asn"])
            except Exception:
                pass

    if mx_asns:
        origin_asns = set(by_asn.keys())
        if origin_asns and not (origin_asns & mx_asns):
            report.add("DNS", "LOW", "The sender's ASN in the Received chain differs from the ASN of the domain's current MX records",
                        f"Received ASNs: {sorted(origin_asns)}  vs  MX ASNs: {sorted(mx_asns)}. "
                        "May be normal (mail provider migration, external ESP), but it is worth "
                        "verifying whether the sending infrastructure is still the same operator.")


def analyze_dnssec(msg, report):
    """Lightweight DNSSEC presence check: a DNSKEY record at the domain apex
    is a reasonable practical signal that the zone is signed. This doesn't
    validate the full chain of trust to the root - a pragmatic recon-level
    check, not a substitute for `dig +dnssec` / delv."""
    if not HAS_DNS:
        return
    from_addr = email.utils.parseaddr(msg.get("From", ""))[1]
    domain = get_domain(from_addr)
    if not domain:
        return
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 4
    try:
        resolver.resolve(domain, "DNSKEY")
        report.posture["dnssec"] = "enabled"
        report.add("DNS", "GOOD", f"Domain {domain} publishes a DNSKEY record (DNSSEC likely enabled)",
                    "Makes DNS cache poisoning/spoofing attacks against this domain's records harder "
                    "(including SPF/DMARC/MX). This is not a full chain-of-trust validation.")
    except Exception:
        report.posture["dnssec"] = "not detected"
        report.add("DNS", "LOW", f"No DNSKEY record for domain {domain} (DNSSEC likely disabled)",
                    "Without DNSSEC, the domain's records (including SPF/DMARC) are theoretically vulnerable to "
                    "DNS cache poisoning attacks on unprotected resolution paths.")


def build_recon_hypotheses(report):
    """Synthesizes a short list of confidence-labelled hypotheses from the
    correlated data gathered above. Deliberately kept separate from
    'findings' - these are inferences for further verification, not facts,
    and should never be presented as if they were."""
    hyps = []

    if report.providers:
        top = report.providers[0]
        hyps.append(("HIGH", f"{top['name']} likely handles mail for this domain",
                     f"based on host '{top['example_host']}' in the Received chain."))

    if report.asn_data:
        orgs = sorted(set(i.get("org") for i in report.asn_data.values() if i.get("org")))
        if orgs:
            hyps.append(("MEDIUM", f"Sending infrastructure likely hosted at: {', '.join(orgs[:3])}",
                         "based on ASN data of the IP addresses in the Received chain."))

    posture = report.posture
    if posture.get("dmarc", "").startswith("p=reject"):
        hyps.append(("HIGH", "The domain actively enforces anti-spoofing protection (DMARC p=reject)",
                     "this makes spoofing this domain in phishing/BEC attacks harder."))
    elif posture.get("dmarc") == "missing":
        hyps.append(("MEDIUM", "The domain may be vulnerable to spoofing in phishing attacks",
                     "no DMARC policy at all - worth verifying as a potential vector for a social engineering test."))

    for host in report.hostnames:
        if INTERNAL_DOMAIN_SUFFIX_RE.search(host) or INFRA_ROLE_HOSTNAME_RE.match(host):
            hyps.append(("LOW", f"'{host}' may reveal part of the internal network topology",
                         "the name suggests internal infrastructure - to be verified, not confirmed."))
            break

    report.hypotheses = hyps


# ---------------------------------------------------------------------------
# Report rendering
# ---------------------------------------------------------------------------
def print_section(title):
    print(f"\n{C.BOLD}{C.BLUE}== {title} =={C.RESET}")


def print_finding(f):
    color = SEV_COLOR.get(f.severity, C.RESET)
    print(f"  {color}[{f.severity:^8}]{C.RESET} {f.title}")
    if f.detail:
        print(f"             {C.DIM}{f.detail}{C.RESET}")


def render_console(report, msg_meta):
    title = "SMTP Header Security Analyzer"
    width = max(len(title) + 4, 44)
    rule = "─" * width
    print(f"{C.CYAN}{rule}{C.RESET}")
    print(f"{C.BOLD}  {title}{C.RESET}")
    print(f"{C.CYAN}{rule}{C.RESET}")
    print(f"  {C.DIM}File   {C.RESET} {msg_meta.get('file')}")
    print(f"  {C.DIM}From   {C.RESET} {msg_meta.get('from')}")
    print(f"  {C.DIM}Subject{C.RESET} {msg_meta.get('subject')}")
    print(f"  {C.DIM}Date   {C.RESET} {msg_meta.get('date')}")

    if report.infra_hops:
        print_section("Infrastructure mapping (Received chain)")
        for hop in report.infra_hops:
            ip_str = ", ".join(hop["ips"]) if hop["ips"] else "-"
            tag = f" {C.DIM}[internal/loopback]{C.RESET}" if hop["is_loopback_hop"] else ""
            if not hop.get("has_from", True):
                tag += f" {C.DIM}[no from clause]{C.RESET}"
            delta = hop.get("delta_seconds")
            delta_str = ""
            if delta is not None:
                delta_str = f" {C.DIM}(+{delta:.1f}s){C.RESET}" if delta < 60 else f" {C.DIM}(+{delta/60:.1f}min){C.RESET}"
            print(f"  Hop {hop['index']}: from={hop['from_host']} -> by={hop['by_host']} "
                  f"[{hop['protocol'] or '?'}]  IP: {ip_str}{tag}{delta_str}")
            if hop["tls"]:
                t = hop["tls"]
                bits = f", {t['bits']} bits" if t["bits"] else ""
                print(f"           {C.CYAN}TLS: {t['version']} / {t['cipher']}{bits}{C.RESET}")
            for sc in hop["scanners"]:
                port = f" (port {sc['port']})" if sc["port"] else ""
                print(f"           {C.DIM}Scanner: {sc['name']}{port}{C.RESET}")

    if report.hostnames:
        print_section(f"Detected hosts / domains ({len(report.hostnames)})")
        print("  " + ", ".join(report.hostnames))

    if report.providers:
        print_section("Detected mail providers / ESPs")
        for p in report.providers:
            print(f"  - {p['name']}  (host: {p['example_host']})")

    if report.software:
        print_section("Detected software")
        for s in report.software:
            v = f" v{s['version']}" if s["version"] else ""
            print(f"  - {s['software']}{v}  (header: {s['header']})")

    if report.posture:
        p = report.posture
        print_section(f"Domain security posture: {p.get('domain', '')}")
        rows = [
            ("SPF", p.get("spf")),
            ("DMARC", p.get("dmarc")),
            ("MX", p.get("mx")),
            ("MTA-STS", p.get("mta_sts")),
            ("TLS-RPT", p.get("tls_rpt")),
            ("DNSSEC", p.get("dnssec")),
        ]
        for label, val in rows:
            if val is None:
                continue
            print(f"  {label:<8} {val}")

    if report.findings:
        print_section("All findings")
        ordered = sorted(report.findings, key=lambda f: SEV_ORDER.get(f.severity, 9))
        by_cat = {}
        for f in ordered:
            by_cat.setdefault(f.category, []).append(f)
        for cat, items in by_cat.items():
            print(f"\n {C.BOLD}{cat}{C.RESET}")
            for f in items:
                print_finding(f)

    if report.hypotheses:
        print_section("Recon hypotheses (NOT facts - require verification)")
        for confidence, title, evidence in report.hypotheses:
            print(f"  {C.MAGENTA}[{confidence:^6}]{C.RESET} {title}")
            print(f"             {C.DIM}{evidence}{C.RESET}")

    if any(report.iocs.get(k) for k in report.iocs):
        print_section("IOCs / indicators (for further use)")
        labels = {"ipv4": "IPv4", "ipv6": "IPv6", "domains": "Domains", "emails": "E-mail",
                  "urls": "URL", "dkim_selectors": "DKIM selectors", "message_ids": "Message-ID"}
        for key, label in labels.items():
            vals = report.iocs.get(key) or []
            if vals:
                print(f"  {label}: {', '.join(vals)}")

    # Summary
    print_section("Summary")
    counts = {}
    for f in report.findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "GOOD"]:
        if sev in counts:
            print(f"  {SEV_COLOR[sev]}{sev:<9}{C.RESET}: {counts[sev]}")
    print()


def build_json_report(report, msg_meta):
    return {
        "meta": msg_meta,
        "infrastructure_hops": report.infra_hops,
        "hostnames_detected": report.hostnames,
        "providers_detected": report.providers,
        "software_detected": report.software,
        "security_posture": report.posture,
        "spf_mechanisms": report.spf_mechanisms,
        "asn_data": report.asn_data,
        "recon_hypotheses": [
            {"confidence": c, "title": t, "evidence": e} for c, t, e in report.hypotheses
        ],
        "iocs": report.iocs,
        "findings": [f.to_dict() for f in report.findings],
        "summary": {
            sev: sum(1 for f in report.findings if f.severity == sev)
            for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "GOOD"]
        },
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="SMTP header security analysis (pentest / recon)."
    )
    parser.add_argument("--headers", required=True, help="File with headers/message (.txt/.eml)")
    parser.add_argument("--json", help="Also save the report to a JSON file")
    parser.add_argument("--dns", action="store_true",
                         help="Run live DNS queries (SPF/DMARC/MX/BIMI/MTA-STS/TLS-RPT, ASN, "
                              "DKIM key strength) for the sender domain (requires dnspython and network access)")
    parser.add_argument("--deep", action="store_true",
                         help="Extends --dns with a full configuration check: recursive "
                              "SPF expansion (include/redirect + 10-lookup limit), PTR<->A consistency "
                              "for every public hop, ASN grouping, DNSSEC, plus "
                              "a domain security posture summary and recon hypotheses. "
                              "Implies --dns. More DNS queries = slower execution.")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")
    args = parser.parse_args()

    if args.deep:
        args.dns = True

    if args.no_color:
        C.disable()

    try:
        with open(args.headers, "rb") as fh:
            raw = fh.read()
    except OSError as e:
        print(f"Error reading file {args.headers}: {e}", file=sys.stderr)
        sys.exit(1)

    parse_bytes, was_repaired = repair_unfolded_headers(raw)
    msg = email.message_from_bytes(parse_bytes, policy=email.policy.default)

    report = Report()
    msg_meta = {
        "file": args.headers,
        "from": msg.get("From", ""),
        "to": msg.get("To", ""),
        "subject": msg.get("Subject", ""),
        "date": msg.get("Date", ""),
    }
    report.meta = msg_meta

    if was_repaired:
        pass  # headers repaired silently - this adds nothing to the security analysis

    analyze_infrastructure(msg, report)
    analyze_software(msg, report)
    analyze_encryption(report)
    analyze_auth(msg, report)
    analyze_interesting(msg, report)
    analyze_internal_disclosure(report)
    analyze_injection(msg, raw, report)
    analyze_relay_heuristics(msg, report, use_dns=args.dns)
    analyze_timing(msg, report)
    analyze_message_id(msg, report)
    analyze_arc_chain(msg, report)

    if args.dns:
        analyze_dns(msg, report)
        analyze_asn(report)
        analyze_dkim_key_strength(msg, report)

    analyze_dmarc_alignment(msg, report)

    if args.deep:
        analyze_spf_deep(msg, report)
        analyze_hop_consistency(report)
        analyze_asn_grouping(report)
        analyze_dnssec(msg, report)
        build_recon_hypotheses(report)

    build_iocs(msg, report)

    render_console(report, msg_meta)

    if args.json:
        data = build_json_report(report, msg_meta)
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        print(f"{C.GREEN}JSON report saved to: {args.json}{C.RESET}")


if __name__ == "__main__":
    main()
