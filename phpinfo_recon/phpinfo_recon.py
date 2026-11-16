#!/usr/bin/env python3
"""
phpinfo_recon.py
================
Tool for analysing phpinfo() pages (info.php, phpinfo.php, test.php, etc.)
encountered during penetration tests.

Features:
  - Fetches phpinfo from a URL or loads a locally saved HTML file.
  - Parses the full phpinfo() structure into a dict (section -> directive -> value).
  - Prints a summary of the most interesting information (stack, paths, user, etc.).
  - Scans for potential data leaks (passwords, keys, tokens).
  - Checks for common php.ini security misconfigurations.
  - Optionally (--check-vulns) checks component freshness through external
    APIs (endoflife.date + NVD) instead of shipping a local CVE database.

Usage:
    python3 phpinfo_recon.py --url https://target.tld/info.php
    python3 phpinfo_recon.py --file saved_phpinfo.html
    python3 phpinfo_recon.py --url https://target.tld/info.php --check-vulns
    python3 phpinfo_recon.py --url https://target.tld/info.php --json out.json

Requirements:
    pip install requests beautifulsoup4

Author: tool for internal pentesting use. Use only as part of authorised
security testing.
"""

import argparse
import json
import re
import sys
import time
import warnings
from datetime import date, datetime
from pathlib import Path
from urllib.parse import urlparse

try:
    import requests
except ImportError:
    sys.exit("[!] Missing module 'requests'. Install it with: pip install requests beautifulsoup4")

try:
    from bs4 import BeautifulSoup
except ImportError:
    sys.exit("[!] Missing module 'beautifulsoup4'. Install it with: pip install requests beautifulsoup4")

warnings.filterwarnings("ignore", message="Unverified HTTPS request")

# --------------------------------------------------------------------------
# Colours (optional, degrade gracefully if the terminal does not support them)
# --------------------------------------------------------------------------

class C:
    RED = "\033[91m"
    YEL = "\033[93m"
    GRN = "\033[92m"
    CYA = "\033[96m"
    BLD = "\033[1m"
    END = "\033[0m"
    # Palette for categories/sections (e.g. "[PHP Variables]", "[Apache Environment]").
    # Kept separate from the severity colours (RED/YEL/GRN/CYA) so that you can see
    # at a glance which phpinfo section a finding comes from, regardless of its severity.
    SECTION_PALETTE = [
        "\033[95m",  # magenta
        "\033[94m",  # blue
        "\033[35m",  # dark magenta
        "\033[34m",  # dark blue
        "\033[36m",  # dark cyan
        "\033[33m",  # dark yellow
        "\033[92m",  # bright green (also used for severity=INFO, but fine in this context)
        "\033[97m",  # bright white
    ]


def colorize(text, color):
    if not sys.stdout.isatty():
        return text
    return f"{color}{text}{C.END}"


SEV_COLOR = {"HIGH": C.RED, "MEDIUM": C.YEL, "LOW": C.CYA, "INFO": C.GRN}

_section_color_cache = {}


def section_color(section_name):
    """Assigns a stable colour (deterministic within a single run) to a given
    phpinfo section/category, so that e.g. all findings from 'PHP Variables'
    share one colour and 'Apache Environment' gets another."""
    if section_name not in _section_color_cache:
        idx = len(_section_color_cache) % len(C.SECTION_PALETTE)
        _section_color_cache[section_name] = C.SECTION_PALETTE[idx]
    return _section_color_cache[section_name]



# --------------------------------------------------------------------------
# 1. Fetching / loading phpinfo
# --------------------------------------------------------------------------

# --------------------------------------------------------------------------
# 1b. Hardening against malicious phpinfo content (see: security audit)
# --------------------------------------------------------------------------
#
# KEY SECURITY ASSUMPTION OF THIS TOOL: the entire phpinfo() content comes
# from the TARGET server and is effectively 100% controlled by the attacking
# side (or by a defender who deliberately plants a crafted file for the
# pentester). We treat it exactly like any other fully untrusted input --
# never as trusted content that can be displayed directly.

# Maximum phpinfo size we agree to process (from a URL or a local file). A real
# phpinfo() is usually < 500 KB even with long extension lists -- 20 MB is a very
# generous margin that still acts as a hard limit protecting against:
#   - "decompression bombs" (a tiny gzip -> gigabytes after requests decompresses it),
#   - a server streaming data endlessly (the requests timeout applies to gaps
#     BETWEEN packets, not to total transfer size/time),
#   - simply downloading the wrong thing by accident (e.g. a large binary file).
MAX_HTML_BYTES = 20 * 1024 * 1024  # 20 MB

# C0 control characters (0x00-0x1F, including ESC=0x1B), DEL (0x7F) and C1
# (0x80-0x9F) are stripped from EVERY key/value extracted from phpinfo BEFORE
# anything goes into further processing. This is the one safe sanitisation
# point -- we do it once, at the trust boundary (right after parsing the HTML),
# so every later print()/json.dumps()/regex comparison already operates on clean
# text, with no need to remember it in dozens of places in the code.
#
# Without this, an attacker controlling phpinfo (i.e. EVERY tested target)
# could embed ANSI/VT100 sequences in any value (e.g. $_SERVER['anything']) and:
#   - replace/hide the pentester's real output (e.g. clear the screen and print
#     a fake "no vulnerabilities" above the genuine findings),
#   - in some terminals (iTerm2, kitty, WezTerm, newer GNOME Terminal) silently
#     overwrite the SYSTEM CLIPBOARD via the OSC 52 sequence -- if the pentester
#     later pastes something from history/the clipboard into a shell, they may
#     paste (and execute) a payload planted by the attacker,
#   - change the terminal window title, hide text, etc.
_CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]")


def sanitize_text(s):
    if s is None:
        return s
    return _CONTROL_CHARS_RE.sub("", s)


def _read_capped(response, max_bytes):
    """Reads a requests response in streaming mode, aborting hard once
    max_bytes is exceeded -- this also works for gzip/deflate content, because
    urllib3/requests decompresses incrementally during iter_content, so the
    limit protects the real size AFTER decompression, not just on the wire."""
    total = 0
    chunks = []
    for chunk in response.iter_content(chunk_size=65536):
        total += len(chunk)
        if total > max_bytes:
            response.close()
            sys.exit(f"[!] Response exceeded the {max_bytes // (1024*1024)} MB limit -- aborting. "
                      "This may be a decompression bomb or simply a mistake (non-HTML URL). "
                      "If this is intentional, increase MAX_HTML_BYTES in the code.")
        chunks.append(chunk)
    raw = b"".join(chunks)
    encoding = response.encoding or "utf-8"
    return raw.decode(encoding, errors="replace")


def fetch_url(url, headers=None, cookies=None, auth=None, insecure=False, timeout=15, proxy=None):
    hdrs = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                      "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
    }
    if headers:
        hdrs.update(headers)

    proxies = {"http": proxy, "https": proxy} if proxy else None

    resp = requests.get(
        url,
        headers=hdrs,
        cookies=cookies,
        auth=auth,
        verify=not insecure,
        timeout=timeout,
        proxies=proxies,
        stream=True,  # so that _read_capped can abort the stream before we pull everything into memory
    )
    resp.raise_for_status()
    return _read_capped(resp, MAX_HTML_BYTES)


def load_local(path):
    p = Path(path)
    if not p.exists():
        sys.exit(f"[!] File does not exist: {path}")
    size = p.stat().st_size
    if size > MAX_HTML_BYTES:
        sys.exit(f"[!] File is {size // (1024*1024)} MB, which exceeds the limit of "
                  f"{MAX_HTML_BYTES // (1024*1024)} MB -- this is probably not a phpinfo page. "
                  "Increase MAX_HTML_BYTES in the code if this is intentional.")
    return p.read_text(encoding="utf-8", errors="replace")


# --------------------------------------------------------------------------
# 2. Parsing phpinfo() HTML into the structure: {section: {directive: value}}
# --------------------------------------------------------------------------

def parse_phpinfo(html):
    """
    Standard phpinfo() layout:
      <h1>PHP Version X.Y.Z</h1>
      <table> ... System / Build Date / Server API / ... (no h2 header) </table>
      <h2>core</h2><table>...</table>
      <h2>openssl</h2><table>...</table>
      ...
    Table rows have 2 columns (module name + value) or 3
    (directive / Local Value / Master Value).

    SECURITY NOTE: `html` comes from the target server and is fully untrusted.
    Two things are deliberately done differently here than in a "naive"
    implementation:
      1. Parser: we use Python's built-in 'html.parser' instead of 'lxml'.
         It is pure Python (no C-based libxml2) -- a smaller attack surface when
         parsing a fully untrusted document, at the cost of a little performance
         that is irrelevant at typical phpinfo sizes (see also MAX_HTML_BYTES,
         which bounds the input size anyway).
      2. We determine sections in ONE pass over the document, in order
         (h1/h2/table at the same level), instead of calling
         table.find_previous() separately for every table. The latter is
         O(n) per call (it scans backwards through the whole DOM so far), so for
         a crafted file with thousands of <table> and a handful of <h2> the
         whole thing becomes O(n^2) -- an easy, cheap DoS against the tool
         itself. A single pass makes parsing linear regardless of input shape.
    """
    soup = BeautifulSoup(html, "html.parser")

    data = {"_meta": {}, "sections": {}}

    # PHP Version from <h1>
    h1 = soup.find("h1")
    if h1:
        h1_text = sanitize_text(h1.get_text())
        m = re.search(r"PHP Version\s*([\d.]+(?:-\w+)?)", h1_text)
        if m:
            data["_meta"]["php_version"] = m.group(1)

    elements = soup.find_all(["h1", "h2", "table"])
    if not any(el.name == "table" for el in elements):
        sys.exit("[!] No table found in the HTML -- this does not look like standard "
                  "phpinfo() output. Check the file/URL.")

    current_section = "General"
    for el in elements:
        if el.name in ("h1", "h2"):
            if el.name == "h1":
                current_section = "General"
            else:
                name = sanitize_text(el.get_text(strip=True))
                current_section = re.sub(r"\s+", " ", name) or "General"
            continue

        # el.name == "table"
        bucket = data["sections"].setdefault(current_section, {})

        for row in el.find_all("tr"):
            cells = row.find_all(["td", "th"])
            texts = [sanitize_text(c.get_text(" ", strip=True)) for c in cells]
            if len(texts) == 0:
                continue
            if len(texts) == 1:
                # e.g. a header inside the table (extension name as a single cell)
                bucket[texts[0]] = ""
            elif len(texts) == 2:
                key, val = texts
                bucket[key] = val
            elif len(texts) >= 3:
                key, local, master = texts[0], texts[1], texts[2]
                bucket[key] = {"local": local, "master": master}

    return data


# --------------------------------------------------------------------------
# 3. "Summary" extraction -- the most interesting things for a pentester
# --------------------------------------------------------------------------

def get_val(v):
    """Reduces a value (str or {'local':..,'master':..}) to a string (the local value)."""
    if isinstance(v, dict):
        return v.get("local", "")
    return v


def find_key(sections, section_hint, key_regex):
    """Looks for a key matching the regex in the given section (case-insensitive)."""
    sec = sections.get(section_hint, {})
    for k, v in sec.items():
        if re.search(key_regex, k, re.I):
            return k, get_val(v)
    return None, None


def find_anywhere(sections, key_regex, section_regex=None):
    """Looks for a key matching the regex in any section."""
    results = []
    for sname, sec in sections.items():
        if section_regex and not re.search(section_regex, sname, re.I):
            continue
        for k, v in sec.items():
            if re.search(key_regex, k, re.I):
                results.append((sname, k, get_val(v)))
    return results


def build_summary(data):
    sections = data["sections"]
    s = {}

    s["php_version"] = data["_meta"].get("php_version") or get_val(
        sections.get("General", {}).get("PHP Version", "")
    )

    _, s["system"] = find_key(sections, "General", r"^System$")
    _, s["server_api"] = find_key(sections, "General", r"^Server API$")
    _, s["build_date"] = find_key(sections, "General", r"^Build Date$")
    _, s["config_file"] = find_key(sections, "General", r"Loaded Configuration File")
    _, s["extension_dir"] = find_key(sections, "core", r"^extension_dir$")
    _, s["document_root"] = find_key(sections, "PHP Variables", r"DOCUMENT_ROOT")
    if not s["document_root"]:
        _, s["document_root"] = find_key(sections, "core", r"^doc_root$")
    _, s["script_filename"] = find_key(sections, "PHP Variables", r"SCRIPT_FILENAME")
    _, s["server_software"] = find_key(sections, "PHP Variables", r"SERVER_SOFTWARE")
    _, s["server_addr"] = find_key(sections, "PHP Variables", r"SERVER_ADDR")
    # User/Group appears in different places depending on the SAPI: most often in
    # the apache2handler section, sometimes in General, sometimes only indirectly
    # through APACHE_RUN_USER/APACHE_RUN_GROUP in Environment.
    s["user_group"] = None
    _, val = find_key(sections, "apache2handler", r"^User/Group$")
    if val:
        s["user_group"] = val
    if not s["user_group"]:
        _, val = find_key(sections, "General", r"^User/Group$")
        if val:
            s["user_group"] = val
    if not s["user_group"]:
        matches = find_anywhere(sections, r"^User/Group$")
        if matches:
            s["user_group"] = matches[0][2]
    if not s["user_group"]:
        run_user_matches = find_anywhere(sections, r"^APACHE_RUN_USER$", section_regex=r"Environment")
        run_group_matches = find_anywhere(sections, r"^APACHE_RUN_GROUP$", section_regex=r"Environment")
        run_user = run_user_matches[0][2] if run_user_matches else None
        run_group = run_group_matches[0][2] if run_group_matches else None
        if run_user or run_group:
            s["user_group"] = f"{run_user or '?'} / {run_group or '?'} (from APACHE_RUN_USER/GROUP)"
    _, s["open_basedir"] = find_key(sections, "core", r"^open_basedir$")
    _, s["disable_functions"] = find_key(sections, "core", r"^disable_functions$")
    _, s["disable_classes"] = find_key(sections, "core", r"^disable_classes$")
    _, s["session_save_path"] = find_key(sections, "session", r"^session\.save_path$")
    _, s["upload_tmp_dir"] = find_key(sections, "core", r"^upload_tmp_dir$")

    # Component stack with versions.
    # For each extension we check SEVERAL possible key names in priority order,
    # but we always pick the first value that CONTAINS A DIGIT (e.g. "7.68.0"),
    # not a generic "enabled"/"disabled" -- otherwise for curl we would pick up
    # "cURL Information: enabled" instead of the real version from the "Version" key.
    stack = {}
    stack["php"] = s["php_version"]

    STACK_KEY_CANDIDATES = {
        "openssl": [r"^OpenSSL Library Version$", r"^OpenSSL Header Version$", r"^OpenSSL Version$"],
        "curl": [r"^Version$", r"^cURL Information$"],
        "zlib": [r"^Compiled Version$", r"^Linked Version$", r"^ZLib Compiled Version$"],
        "libxml": [r"^libXML Compiled Version$", r"^libXML Version$"],
        "gd": [r"^GD Version$"],
        "mysqli": [r"^Client API library version$", r"^Client API version$"],
        "pdo_mysql": [r"^Client API library version$"],
        "imagick": [r"^ImageMagick version$"],
        "apache2handler": [r"^Apache Version$"],
    }

    for extname, keyregexes in STACK_KEY_CANDIDATES.items():
        sec = sections.get(extname, {})
        if not sec:
            continue
        fallback = None
        found = None
        for keyregex in keyregexes:
            for k, v in sec.items():
                if re.search(keyregex, k, re.I):
                    val = get_val(v)
                    if re.search(r"\d", val):
                        found = val
                        break
                    if fallback is None:
                        fallback = val
            if found:
                break
        if found or fallback:
            stack[extname] = found or fallback

    s["stack"] = stack

    # database extensions present in general
    db_exts = [name for name in sections.keys()
               if re.search(r"mysqli|pdo_mysql|pgsql|pdo_pgsql|sqlite|mongodb|oci8|sqlsrv|pdo_sqlsrv", name, re.I)]
    s["database_extensions"] = db_exts

    return s


# --------------------------------------------------------------------------
# 4. Detecting potential data leaks
# --------------------------------------------------------------------------

# --- Detection by key NAME: whole-token matching, not substrings. ---
# This eliminates false positives such as "tokenizer" (contains "token" as a
# substring but is a different word), "Authors", "Tokenizer Support", etc.
#
# The key is split into alphanumeric tokens (e.g. "$_SERVER['DB_PASSWORD']"
# -> ["server", "db", "password"]) and checked:
#   1) whether any SINGLE token is in SENSITIVE_KEY_TOKENS, or
#   2) whether any ADJACENT PAIR of tokens is in SENSITIVE_KEY_TOKEN_PAIRS
#      (to catch e.g. "db_pass", "api_key", "connection_string").

SENSITIVE_KEY_TOKENS = {
    "password", "passwd", "pwd", "pw", "secret", "token", "credential",
    "credentials", "dsn", "jwt", "apikey", "privkey", "keystore", "keypair",
}

SENSITIVE_KEY_TOKEN_PAIRS = {
    ("api", "key"), ("access", "key"), ("private", "key"), ("secret", "key"),
    ("auth", "key"), ("encryption", "key"), ("session", "key"), ("public", "key"),
    ("db", "pass"), ("db", "password"), ("db", "pwd"), ("database", "pass"),
    ("database", "password"), ("database", "pwd"), ("connection", "string"),
    ("client", "secret"), ("auth", "token"), ("access", "token"),
    ("refresh", "token"), ("bearer", "token"), ("session", "token"),
}

# Keys that look suspicious by name but in practice are almost never a secret
# (a classic false positive) -- we skip them explicitly.
KEY_FALSE_POSITIVE_EXACT = {"pwd", "oldpwd"}  # PWD = the shell's current working directory, not a password


def key_looks_sensitive(key):
    k_clean = key.strip()
    if k_clean.upper() in {"PWD", "OLDPWD"}:
        return False
    tokens = [t.lower() for t in re.findall(r"[A-Za-z0-9]+", k_clean)]
    if not tokens:
        return False
    if len(tokens) == 1 and tokens[0] in KEY_FALSE_POSITIVE_EXACT:
        return False
    for t in tokens:
        if t in SENSITIVE_KEY_TOKENS:
            return True
    for i in range(len(tokens) - 1):
        if (tokens[i], tokens[i + 1]) in SENSITIVE_KEY_TOKEN_PAIRS:
            return True
    return False


# --- Detection by VALUE: specific, high-confidence patterns (HIGH). ---
SENSITIVE_VALUE_PATTERNS = [
    ("AWS Access Key ID", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("Connection string with password", re.compile(r"(mysql|postgres|postgresql|mongodb|redis)://[^:\s]+:[^@\s]+@")),
    ("Private key block", re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("Slack token", re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,}")),
    ("Google API key", re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    ("Generic bearer token in value", re.compile(r"Bearer\s+[A-Za-z0-9\-._~+/]{20,}=*")),
    ("JWT", re.compile(r"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+")),
]

# Keys that are almost always identifiers/hashes/serial numbers and NOT
# secrets -- we exclude them from the entropy heuristic so that we do not flag
# things like SSL_SERVER_M_SERIAL, ETag, request_id, session_id, checksums, etc.
IDENTIFIER_KEY_RE = re.compile(
    r"serial|fingerprint|thumbprint|checksum|\bhash\b|md5|sha1|sha256|etag|"
    r"session_?id|request_?id|trace_?id|build_?id|uuid|guid|\bid\b",
    re.I,
)

_HEX_ONLY_RE = re.compile(r"^[0-9A-Fa-f]{32,64}$")


_BASE64_STRICT_RE = re.compile(r"^[A-Za-z0-9+/_-]+={0,2}$")


def looks_like_random_secret(val):
    """
    Entropy heuristic for values whose key NAME suggests nothing, but whose
    value looks like a random secret (e.g. a hard-coded key in a custom ini
    directive). Deliberately conservative, so that it does not flag hashes/serial
    numbers or ordinary configuration strings:
      - the value MUST consist ONLY of characters from the base64/base64url
        alphabet (A-Za-z0-9+/_- plus optional "=" padding). This is the key
        filter: HTTP headers such as "Accept: text/html,application/xhtml+xml;q=0.9,*/*"
        or system paths ("/sys/fs/cgroup/.../memory.pressure") contain
        commas/semicolons/dots/asterisks outside this alphabet and are rejected
        immediately, instead of relying only on "no spaces",
      - rejects pure hex (typical for MD5/SHA1/SHA256/serial numbers),
      - requires a mix of character classes (lowercase/uppercase/digit/+/=),
      - length within the typical range for base64 secrets (32-88 characters).
    """
    v = val.strip()
    if not (32 <= len(v) <= 88):
        return False
    if not _BASE64_STRICT_RE.fullmatch(v):
        return False
    if _HEX_ONLY_RE.fullmatch(v):
        return False
    classes = sum([
        bool(re.search(r"[a-z]", v)),
        bool(re.search(r"[A-Z]", v)),
        bool(re.search(r"[0-9]", v)),
        bool(re.search(r"[+/=_-]", v)),
    ])
    return classes >= 3


# Sections where leaks are most likely and most "juicy"
# (no needless ^$ anchors -- real sections are e.g. "Environment", "Apache Environment",
# "PHP Variables", module names such as apache2handler, etc.)
HIGH_VALUE_SECTIONS_RE = r"Environment|PHP Variables|\$_SERVER|\$_ENV|apache2handler"

EMPTY_LIKE = {"", "no value", "none", "n/a", "0", "off"}


def is_empty_like(val):
    return (val or "").strip().lower() in EMPTY_LIKE


# Key names that sound like "token/secret" but by definition are NOT
# confidential -- CSRF/XSRF tokens are deliberately readable by client-side JS
# (double-submit cookie pattern), so their presence in $_COOKIE / $_SERVER is
# perfectly normal and not a data leak.
NOT_ACTUALLY_SECRET_KEYS = {
    "xsrf-token", "xsrftoken", "csrf-token", "csrftoken", "x-csrf-token",
    "_csrf", "_token", "anti-csrf-token", "csrf_token",
}


def _normalize_key_for_exclusion(key):
    # "$_COOKIE['XSRF-TOKEN']" -> "xsrf-token"
    m = re.search(r"\[['\"]?([^'\"\]]+)['\"]?\]\s*$", key)
    core = m.group(1) if m else key
    return core.strip().lower()


def scan_sensitive_data(data):
    findings = []
    sections = data["sections"]

    for sname, sec in sections.items():
        is_high_value_section = bool(re.search(HIGH_VALUE_SECTIONS_RE, sname, re.I))
        for k, v in sec.items():
            val = get_val(v) or ""
            if is_empty_like(val):
                continue

            if _normalize_key_for_exclusion(k) in NOT_ACTUALLY_SECRET_KEYS:
                continue

            if key_looks_sensitive(k):
                findings.append({
                    "severity": "HIGH",
                    "section": sname,
                    "key": k,
                    "value": val,
                    "reason": "Key name suggests sensitive data (password/token/secret) and the field is not empty"
                             + (" [high-risk section: env/server vars]" if is_high_value_section else ""),
                })
                continue  # do not duplicate with the remaining checks for the same field

            value_pattern_hit = False
            for label, pattern in SENSITIVE_VALUE_PATTERNS:
                if pattern.search(val):
                    findings.append({
                        "severity": "HIGH",
                        "section": sname,
                        "key": k,
                        "value": val,
                        "reason": f"Value matches pattern: {label}",
                    })
                    value_pattern_hit = True
                    break
            if value_pattern_hit:
                continue

            # entropy heuristic -- only when the key is NOT a known identifier
            if not IDENTIFIER_KEY_RE.search(k) and looks_like_random_secret(val):
                findings.append({
                    "severity": "MEDIUM",
                    "section": sname,
                    "key": k,
                    "value": val,
                    "reason": "Value has high entropy and looks like a random secret (base64-like) -- "
                              "verify manually, this is a heuristic and may produce false positives.",
                })

    return findings


# --------------------------------------------------------------------------
# 5. Security misconfigurations (php.ini)
# --------------------------------------------------------------------------

# (section, directive, "bad" value regex, severity, description)
# The description in square brackets is a rough reference to OWASP Top 10 2021 /
# OWASP ASVS 4.0, to make it easier to map findings into a test report.
MISCONFIG_CHECKS = [
    ("core", "display_errors", r"^(on|1|stdout|stderr)$", "MEDIUM",
     "display_errors enabled -- PHP errors (with paths, SQL queries, stack traces) may be visible to an attacker. "
     "[OWASP A05:2021 Security Misconfiguration]"),
    ("core", "expose_php", r"^on$", "LOW",
     "expose_php enabled -- makes fingerprinting easier (although the phpinfo page itself already gives it away). [OWASP A05:2021]"),
    ("core", "allow_url_include", r"^on$", "HIGH",
     "allow_url_include=On -- combined with LFI it gives direct RCE (remote file inclusion). "
     "[OWASP A03:2021 Injection]"),
    ("core", "allow_url_fopen", r"^on$", "LOW",
     "allow_url_fopen=On -- On by default, but it widens the attack surface for SSRF/LFI (include() of remote URLs if allow_url_include is also On)."),
    ("core", "register_globals", r"^on$", "HIGH",
     "register_globals enabled (very old/dangerous, removed in PHP 5.4+) -- mass variable-injection vulnerabilities. "
     "[OWASP A03:2021 Injection]"),
    ("core", "magic_quotes_gpc", r"^on$", "LOW",
     "magic_quotes_gpc -- deprecated, removed in PHP 5.4; if visible, this is a very old PHP."),
    ("core", "open_basedir", r"^(no value|none|)$", "MEDIUM",
     "open_basedir not set -- no restriction on filesystem access from PHP (relevant for LFI/RCE). "
     "[OWASP ASVS V12.5, A01:2021 Broken Access Control]"),
    ("core", "disable_functions", r"^(no value|none|)$", "MEDIUM",
     "disable_functions is empty -- dangerous functions (exec, system, shell_exec, passthru...) may be available after RCE. "
     "[OWASP ASVS V14.4, A05:2021]"),
    ("core", "short_open_tag", r"^on$", "LOW",
     "short_open_tag enabled -- raises risk when uploading files with an extension other than .php (e.g. .phtml, .html in some configurations)."),
    ("core", "file_uploads", r"^on$", "INFO",
     "file_uploads enabled -- check whether the application validates file type/extension. "
     "[OWASP ASVS V12.1-V12.2 File Upload]"),
    ("core", "session.cookie_httponly", r"^(off|0|no value)$", "MEDIUM",
     "session.cookie_httponly disabled -- the session cookie is accessible from JS (risk in case of XSS). [OWASP ASVS V3.4.1]"),
    ("session", "session.cookie_httponly", r"^(off|0|no value)$", "MEDIUM",
     "session.cookie_httponly disabled -- the session cookie is accessible from JS (risk in case of XSS). [OWASP ASVS V3.4.1]"),
    ("session", "session.cookie_secure", r"^(off|0|no value)$", "MEDIUM",
     "session.cookie_secure disabled -- the session cookie may leak over HTTP (HTTPS not enforced). [OWASP ASVS V3.4.2]"),
    ("session", "session.cookie_samesite", r"^(no value|none|)$", "MEDIUM",
     "session.cookie_samesite not set -- weaker CSRF protection in modern browsers. "
     "[OWASP A01:2021, ASVS V3.4.3]"),
    ("session", "session.use_strict_mode", r"^(off|0|no value)$", "MEDIUM",
     "session.use_strict_mode disabled -- the server accepts uninitialised/arbitrary session IDs supplied by the client "
     "= session fixation. [OWASP ASVS V3.2.2]"),
    ("session", "session.use_trans_sid", r"^(on|1)$", "HIGH",
     "session.use_trans_sid enabled -- the session ID can be injected into URLs, causing it to leak via "
     "server logs, browser history and the Referer header sent to external sites. [OWASP ASVS V3.3.1, A07:2021]"),
    ("session", "session.use_only_cookies", r"^(off|0|no value)$", "HIGH",
     "session.use_only_cookies disabled -- the server accepts a session ID passed in the URL/GET, making session "
     "fixation easier and leaking sessions via logs/Referer. [OWASP ASVS V3.3.1]"),
    ("core", "cgi.fix_pathinfo", r"^(on|1)$", "MEDIUM",
     "cgi.fix_pathinfo=On with PHP-FPM/nginx and no proper configuration can lead to path traversal / RCE "
     "(CVE-2012-1823 and derivatives). [OWASP A03:2021]"),
    ("core", "assert.active", r"^(on|1)$", "HIGH",
     "assert.active enabled (PHP < 8) -- assert() with a string argument executes it as PHP code; a classic "
     "RCE primitive if user input reaches assert(). [OWASP A03:2021 Injection]"),
    ("core", "enable_dl", r"^(on|1)$", "MEDIUM",
     "enable_dl enabled -- allows dynamically loading arbitrary .so extensions at runtime, which widens "
     "the attack surface if the extension directory is writable. [OWASP A05:2021]"),
    ("core", "phar.readonly", r"^(off|0)$", "MEDIUM",
     "phar.readonly disabled -- creating/writing .phar archives is possible, which combined with file upload and "
     "a vulnerable unserialize()/gadget chain opens the way to PHP Object Injection via the phar:// stream wrapper. "
     "[OWASP A08:2021 Software and Data Integrity Failures]"),
    ("core", "zend.exception_ignore_args", r"^(off|0|no value)$", "MEDIUM",
     "zend.exception_ignore_args disabled while display_errors=On (PHP 7.4+) -- the stack trace in the error message "
     "contains function call argument values (potentially passwords/tokens passed as parameters). "
     "[OWASP A05:2021, A02:2021 Cryptographic Failures when secrets appear in arguments]"),
    ("core", "html_errors", r"^(on|1)$", "LOW",
     "html_errors enabled together with display_errors -- error messages rendered as HTML sometimes reflect "
     "user input (e.g. key names from GET/POST), which can be a reflected XSS vector. [OWASP A03:2021]"),
    ("core", "max_execution_time", r"^0$", "LOW",
     "max_execution_time=0 (no limit) -- no protection against long-running requests, makes DoS through "
     "resource exhaustion easier. [OWASP ASVS V13.4, A04:2021 Insecure Design]"),
    ("core", "memory_limit", r"^-1$", "LOW",
     "memory_limit=-1 (no limit) -- a single request can consume all available memory = DoS through resource "
     "exhaustion. [OWASP A04:2021]"),
    ("core", "log_errors", r"^(off|0)$", "LOW",
     "log_errors disabled -- PHP errors are not logged server-side, which makes attack detection and incident "
     "response harder. [OWASP ASVS V7.1 Log Content]"),
    ("core", "mysql.default_password", r".+", "INFO",
     "A value was found in mysql.default_password -- check manually, potential leak."),
    ("core", "sql.safe_mode", r"^on$", "INFO",
     "sql.safe_mode -- deprecated directive, its presence indicates a very old PHP."),
]


def check_misconfigs(data):
    sections = data["sections"]
    findings = []
    for section, key, bad_pattern, sev, desc in MISCONFIG_CHECKS:
        sec = sections.get(section, {})
        matched_key, val = None, None
        for k, v in sec.items():
            if k.lower() == key.lower():
                matched_key, val = k, get_val(v)
                break
        if matched_key is None:
            continue
        val_norm = (val or "").strip()
        if re.search(bad_pattern, val_norm, re.I):
            findings.append({
                "severity": sev,
                "section": section,
                "directive": matched_key,
                "value": val_norm,
                "description": desc,
            })

    findings.extend(check_xdebug_in_prod(sections))
    findings.extend(check_paths_inside_docroot(sections, summary_document_root(sections)))
    findings.extend(check_disable_functions_gaps(sections))
    attack_surface_findings, _backend_services = check_attack_surface(sections)
    findings.extend(attack_surface_findings)

    return findings


def check_xdebug_in_prod(sections):
    """
    Xdebug in an environment that looks like production (and phpinfo() tends to be
    forgotten precisely on production) is a very common and high-value
    finding: it exposes extra data in error messages, can significantly
    degrade performance, and with xdebug.mode containing "debug"/"trace" and
    a reachable port 9003/9000 it can be abused for remote debugging
    (effectively remote code execution by attaching a debugger).
    [OWASP A05:2021 Security Misconfiguration]
    """
    findings = []
    xdebug_section = None
    for sname in sections:
        if sname.lower() == "xdebug":
            xdebug_section = sname
            break
    if not xdebug_section:
        return findings

    sec = sections[xdebug_section]
    mode_val = None
    for k, v in sec.items():
        if k.lower() in ("xdebug.mode", "xdebug.remote_enable"):
            mode_val = get_val(v)
            break

    mode_norm = (mode_val or "").strip().lower()
    if re.search(r"debug|trace|on|1", mode_norm):
        findings.append({
            "severity": "HIGH",
            "section": xdebug_section,
            "directive": "xdebug (loaded + debug/trace/remote mode)",
            "value": mode_val or "enabled",
            "description": "Xdebug loaded with an active debug/trace/remote mode -- if the debugger port is "
                            "reachable from the attacker's network, this is effectively a remote code execution primitive. "
                            "Xdebug should not be present in production. [OWASP A05:2021]",
        })
    else:
        findings.append({
            "severity": "MEDIUM",
            "section": xdebug_section,
            "directive": "xdebug (loaded)",
            "value": "enabled",
            "description": "Xdebug is loaded. Its mere presence on an externally reachable environment "
                            "is a code smell -- performance overhead and extra attack surface. Verify "
                            "xdebug.mode/xdebug.remote_enable and whether the debugger port is reachable. [OWASP A05:2021]",
        })
    return findings


def summary_document_root(sections):
    _, val = find_key(sections, "PHP Variables", r"DOCUMENT_ROOT")
    return val


def check_paths_inside_docroot(sections, document_root):
    """
    Directories/files pointed to by session.save_path, upload_tmp_dir or
    error_log, if they lie INSIDE the document root, are potentially reachable
    directly over HTTP. This opens the way to:
      - reading other users' session files (session hijacking),
      - log poisoning -> RCE (injecting a PHP payload into the log via User-Agent
        or a malformed request, then requesting the log as a PHP file),
      - reading temporary upload files within a race-condition window.
    [OWASP A01:2021 Broken Access Control, ASVS V12.3]
    """
    findings = []
    if not document_root:
        return findings
    docroot_norm = document_root.strip().rstrip("/")
    if not docroot_norm:
        return findings

    PATH_DIRECTIVES = [
        ("session", "session.save_path", "Session files directory", "HIGH"),
        ("core", "upload_tmp_dir", "Temporary file upload directory", "MEDIUM"),
        ("core", "error_log", "PHP error log file", "HIGH"),
    ]
    for section, key, label, sev in PATH_DIRECTIVES:
        sec = sections.get(section, {})
        val = None
        for k, v in sec.items():
            if k.lower() == key.lower():
                val = get_val(v)
                break
        if not val or is_empty_like(val):
            continue
        val_norm = val.strip()
        if val_norm.startswith(docroot_norm):
            findings.append({
                "severity": sev,
                "section": section,
                "directive": key,
                "value": val_norm,
                "description": f"{label} ({key}) is located INSIDE the document root ({docroot_norm}) -- "
                                "probably reachable directly over HTTP. Verify whether the file/directory "
                                "is actually accessible from outside (e.g. curl against the computed URL path).",
            })
    return findings


# --------------------------------------------------------------------------
# 5b. disable_functions "with holes" -- illusory/partial hardening
# --------------------------------------------------------------------------

# Functions with obvious RCE/lateral-movement potential that administrators
# most often TRY to disable through disable_functions. If disable_functions
# is NOT empty (so someone did actually deal with it) but one of these entries
# is missing, that is a concrete, actionable finding -- "hardening is there,
# but leaky" -- instead of just a binary "empty/non-empty".
DANGEROUS_FUNCTIONS = [
    "exec", "shell_exec", "system", "passthru", "popen", "proc_open",
    "proc_close", "pcntl_exec", "show_source", "putenv",
]


def check_disable_functions_gaps(sections):
    _, val = find_key(sections, "core", r"^disable_functions$")
    if not val or is_empty_like(val):
        return []  # an empty disable_functions is already reported separately in MISCONFIG_CHECKS

    disabled = {f.strip().lower() for f in val.split(",") if f.strip()}
    missing = [f for f in DANGEROUS_FUNCTIONS if f.lower() not in disabled]
    if not missing:
        return []
    return [{
        "severity": "MEDIUM",
        "section": "core",
        "directive": "disable_functions (incomplete)",
        "value": val,
        "description": "disable_functions is set (so hardening was attempted), but still allows calling: "
                        f"{', '.join(missing)}. Partial hardening is often illusory after RCE -- "
                        "check whether the application actually needs these functions. [OWASP ASVS V14.4]",
    }]


# --------------------------------------------------------------------------
# 5c. Attack surface: risky extensions and registered stream wrappers
# --------------------------------------------------------------------------

# Extensions whose mere PRESENCE is a signal worth noting during pentest
# recon -- from "this is almost always a mistake on production" (expect)
# to "check a specific vector" (soap/xmlrpc -> XXE, ldap -> LDAP injection).
RISKY_EXTENSION_NOTES = {
    "expect": ("CRITICAL: the 'expect' extension is loaded -- it exposes the expect:// stream wrapper, which "
               "allows direct execution of system commands (e.g. include('expect://id')) without "
               "any additional primitive. Merely loading this extension on production is practically "
               "always a configuration mistake. [OWASP A05:2021]", "HIGH"),
    "mcrypt": ("The 'mcrypt' extension -- removed from PHP core in 7.2 (moved to PECL, the libmcrypt library "
               "has long been unmaintained). Its presence usually means a very old PHP or a manually installed, "
               "outdated cryptographic library.", "LOW"),
    "imap": ("The 'imap' extension (c-client library) -- historically many CVEs, including RCE (e.g. buffer "
             "overflows when parsing IMAP/POP3/NNTP responses). If the application does not use it, consider "
             "removing it from the production image.", "LOW"),
    "soap": ("The SOAP extension parses XML -- check SOAP endpoints for XXE (XML External Entity), "
             "especially if libxml_disable_entity_loader() is not called explicitly in older PHP.", "INFO"),
    "xmlrpc": ("The XML-RPC extension -- historically vulnerable to XXE and other XML parser attacks; check whether "
               "the XML-RPC endpoint is still active and reachable.", "INFO"),
    "ldap": ("The LDAP extension is loaded -- check whether the application properly escapes user input when "
             "building LDAP filters (LDAP injection).", "INFO"),
}

# Stream wrappers whose presence in "Registered PHP Streams" matters
# offensively -- primarily expect:// (RCE) and phar:// (deserialisation/PHP
# Object Injection, already partly covered by the phar.readonly check).
INTERESTING_STREAM_WRAPPERS = {
    "expect": ("The 'expect://' stream wrapper is registered -- confirms the ability to execute system commands "
               "through any function that accepts a URL/stream (include, file_get_contents, fopen...). [OWASP A05:2021]", "HIGH"),
    "phar": ("The 'phar://' stream wrapper is registered -- a potential PHP Object Injection vector when deserialising "
             ".phar archive metadata, if the attacker controls the path passed to file functions.", "INFO"),
}

# Extensions hinting at specific backend services in the stack --
# useful as a pointer for further network recon (are Redis/
# Memcached/Mongo reachable directly from the network, without auth, on the default port).
BACKEND_SERVICE_EXTENSIONS = {
    "redis": "Redis", "memcached": "Memcached", "memcache": "Memcache",
    "mongodb": "MongoDB", "pdo_pgsql": "PostgreSQL", "pgsql": "PostgreSQL",
    "oci8": "Oracle", "sqlsrv": "MSSQL", "pdo_sqlsrv": "MSSQL",
    "mysqli": "MySQL/MariaDB", "pdo_mysql": "MySQL/MariaDB", "cassandra": "Cassandra",
    "pdo_sqlite": "SQLite", "sqlite3": "SQLite",
}


def check_attack_surface(sections):
    """
    Returns (findings, backend_services):
      - findings: list of dicts like in check_misconfigs, for the [SECURITY MISCONFIGURATIONS] section
        (risky extensions + stream wrappers -- real security findings, not just info).
      - backend_services: set of backend service names suggested by loaded extensions
        (for a separate, informational summary line -- not every pentester looks for "misconfiguration"
        here, but it is a great hint about what else to scan in the internal network).
    """
    findings = []
    backend_services = set()

    for sname in sections:
        key_lower = sname.strip().lower()
        if key_lower in RISKY_EXTENSION_NOTES:
            desc, sev = RISKY_EXTENSION_NOTES[key_lower]
            findings.append({
                "severity": sev,
                "section": sname,
                "directive": f"extension: {sname}",
                "value": "loaded",
                "description": desc,
            })
        if key_lower in BACKEND_SERVICE_EXTENSIONS:
            backend_services.add(BACKEND_SERVICE_EXTENSIONS[key_lower])

    _, streams_val = find_key(sections, "General", r"^Registered PHP Streams$")
    if streams_val:
        wrappers = {w.strip().lower() for w in streams_val.split(",")}
        for wrapper, (desc, sev) in INTERESTING_STREAM_WRAPPERS.items():
            if wrapper in wrappers:
                findings.append({
                    "severity": sev,
                    "section": "General",
                    "directive": f"stream wrapper: {wrapper}://",
                    "value": streams_val,
                    "description": desc,
                })

    return findings, backend_services


# --------------------------------------------------------------------------
# 5d. Infrastructure fingerprinting: private IPs, internal hosts, cloud/
#     container markers -- useful for further recon and pivoting
# --------------------------------------------------------------------------

PRIVATE_IPV4_RE = re.compile(
    r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3})\b"
)
INTERNAL_HOSTNAME_RE = re.compile(
    r"\b[a-zA-Z0-9][a-zA-Z0-9.-]*\.(?:internal|local|corp|intra|lan)\b", re.I
)

# Keys whose mere PRESENCE (regardless of value) gives away the hosting
# platform/container orchestration -- a great infrastructure fingerprint.
PLATFORM_MARKER_KEYS = {
    "kubernetes_service_host": "Kubernetes",
    "kubernetes_port": "Kubernetes",
    "docker_container": "Docker",
    "ecs_container_metadata_uri": "AWS ECS",
    "ecs_container_metadata_uri_v4": "AWS ECS",
    "aws_execution_env": "AWS Lambda/other AWS compute",
    "aws_region": "AWS",
    "google_cloud_project": "Google Cloud",
    "gcp_project": "Google Cloud",
    "website_instance_id": "Azure App Service",
    "website_site_name": "Azure App Service",
    "dyno": "Heroku",
    "fly_app_name": "Fly.io",
}


def collect_infra_hints(data):
    """
    Scans ALL phpinfo values (not only 'high-risk' sections)
    for traces of internal infrastructure -- useful for further
    network recon / pivoting once a foothold is gained.
    Returns a dict: {"private_ips": set, "internal_hostnames": set, "platform_markers": [(platform, section, key, value)]}
    """
    sections = data["sections"]
    private_ips = set()
    internal_hostnames = set()
    platform_markers = []

    for sname, sec in sections.items():
        for k, v in sec.items():
            val = get_val(v) or ""
            if is_empty_like(val):
                continue

            for m in PRIVATE_IPV4_RE.findall(val):
                private_ips.add(m)
            for m in INTERNAL_HOSTNAME_RE.findall(val):
                internal_hostnames.add(m)

            norm_key = _normalize_key_for_exclusion(k)
            if norm_key in PLATFORM_MARKER_KEYS:
                platform_markers.append((PLATFORM_MARKER_KEYS[norm_key], sname, k, val))

    return {
        "private_ips": private_ips,
        "internal_hostnames": internal_hostnames,
        "platform_markers": platform_markers,
    }


# --------------------------------------------------------------------------
# 6. Full list of stack versions (for manual verification, default mode)
# --------------------------------------------------------------------------

VERSION_KEY_RE = re.compile(
    r"version|release|revision|Build Date|libxml|zlib|openssl|api|client", re.I
)

# Keys that are clearly a list of names / credits in the "General" section
# (e.g. "Extension Module API", "Server API (SAPI) Abstraction Layer") -- those
# values never contain digits, so the requirement that the value contain a
# digit (below) already filters them out. This list is an extra safeguard
# for edge cases (e.g. "Version 2" in a name).
CREDITS_KEY_RE = re.compile(r"^(Thanks to|Authors?|Contribution by)", re.I)


def collect_all_versions(data):
    """
    Collects ALL key/value pairs that look like real version numbers,
    per section/module. The key must match VERSION_KEY_RE, and in addition
    the value MUST contain at least one digit -- this filters out
    fields such as "Extension Module API: Andi Gutmans, Zeev Suraski..." (the list
    of authors/credits from the General section), which used to be picked up only
    because the key name contained the word "API"/"libxml"/"openssl", etc.
    """
    sections = data["sections"]
    out = {}
    for sname, sec in sections.items():
        hits = {}
        for k, v in sec.items():
            if CREDITS_KEY_RE.search(k):
                continue
            if VERSION_KEY_RE.search(k):
                val = get_val(v)
                if val and not is_empty_like(val) and re.search(r"\d", val):
                    hits[k] = val
        if hits:
            out[sname] = hits
    return out


# --------------------------------------------------------------------------
# 7. --check-vulns : EOL + CVE through public APIs (no local database)
# --------------------------------------------------------------------------

EOL_API = "https://endoflife.date/api/{product}.json"
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# heuristic map: what from phpinfo -> which product on endoflife.date
EOL_PRODUCT_MAP = {
    "php": "php",
}

OS_DETECT_PATTERNS = [
    (r"ubuntu", "ubuntu"),
    (r"debian", "debian"),
    (r"centos", "centos"),
    (r"red ?hat|rhel", "red-hat"),
    (r"alpine", "alpine"),
    (r"fedora", "fedora"),
    (r"amazon linux", "amazon-linux"),
    (r"win(dows|nt)", "windows-server"),  # approximate, endoflife.date has several windows products
]


def check_eol(product, version):
    """Returns EOL info for the given product+version from endoflife.date."""
    try:
        resp = requests.get(EOL_API.format(product=product), timeout=10)
        if resp.status_code != 200:
            return None
        cycles = resp.json()
    except Exception as e:
        return {"error": str(e)}

    # match by cycle (e.g. "8.1" for version "8.1.27")
    ver_major_minor = ".".join(version.split(".")[:2]) if version else ""
    for cycle in cycles:
        if str(cycle.get("cycle")) == ver_major_minor or str(cycle.get("cycle")) == version:
            return cycle
    return {"note": f"No exact match for cycle '{ver_major_minor}' in endoflife.date"}


# How many days ahead we treat an approaching EOL as "worth showing" --
# an EOL in 5 years is not a pentest finding, an EOL in 3 months is.
UPCOMING_EOL_HORIZON_DAYS = 180


def classify_eol_status(eol_field):
    """
    In the "eol" field endoflife.date returns:
      - False              -> end of support was never announced
      - True                -> EOL "since forever"/immediate (rare)
      - "YYYY-MM-DD" string -> a SPECIFIC end-of-support date -- it may lie
                                in the PAST (already EOL) or in the FUTURE
                                (planned end of support, the version is still alive).

    Returns a tuple (status, eol_date_or_None) where status is one of:
      "not_eol"   -- no announced EOL, nothing to report
      "past_eol"  -- the EOL date has passed, the version is actually unsupported
      "upcoming"  -- the EOL date is in the future, but within UPCOMING_EOL_HORIZON_DAYS
      "future_ok" -- the EOL date is far in the future, nothing alarming right now
    """
    if eol_field is False:
        return "not_eol", None
    if eol_field is True:
        return "past_eol", None
    if isinstance(eol_field, str):
        try:
            eol_date = datetime.strptime(eol_field, "%Y-%m-%d").date()
        except ValueError:
            # Unusual date format from the API -- we do not guess, we treat it as "nothing certain".
            return "not_eol", None
        today = date.today()
        if eol_date <= today:
            return "past_eol", eol_date
        elif (eol_date - today).days <= UPCOMING_EOL_HORIZON_DAYS:
            return "upcoming", eol_date
        else:
            return "future_ok", eol_date
    return "not_eol", None


def guess_os_product(system_string):
    if not system_string:
        return None
    for pattern, product in OS_DETECT_PATTERNS:
        if re.search(pattern, system_string, re.I):
            return product
    return None


def check_nvd(component, version, api_key=None, max_results=5):
    """Simple keyword search against NVD. Without an API key: limit of 5 req/30s -- we handle the sleep ourselves."""
    params = {
        "keywordSearch": f"{component} {version}",
        "resultsPerPage": max_results,
    }
    headers = {}
    if api_key:
        headers["apiKey"] = api_key
    try:
        resp = requests.get(NVD_API, params=params, headers=headers, timeout=15)
        if resp.status_code != 200:
            return {"error": f"HTTP {resp.status_code}"}
        js = resp.json()
        cves = []
        for item in js.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cid = cve.get("id")
            desc = ""
            for d in cve.get("descriptions", []):
                if d.get("lang") == "en":
                    desc = d.get("value", "")
                    break
            metrics = cve.get("metrics", {})
            score = None
            for mkey in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if mkey in metrics:
                    score = metrics[mkey][0]["cvssData"].get("baseScore")
                    break
            cves.append({"id": cid, "score": score, "summary": desc[:180]})
        return {"total_results": js.get("totalResults", 0), "cves": cves}
    except Exception as e:
        return {"error": str(e)}


def run_vuln_checks(summary, nvd_api_key=None, use_nvd=True):
    results = {"eol": {}, "cve": {}}

    # PHP EOL
    php_ver = summary.get("php_version")
    if php_ver:
        results["eol"]["php"] = check_eol("php", php_ver)

    # OS EOL (heuristic)
    os_product = guess_os_product(summary.get("system", ""))
    if os_product:
        # try to extract the version number from the system string, e.g. "Ubuntu ... 22.04"
        m = re.search(r"(\d+\.\d+(\.\d+)?)", summary.get("system", ""))
        os_ver = m.group(1) if m else None
        if os_ver:
            results["eol"][os_product] = check_eol(os_product, os_ver)
        else:
            results["eol"][os_product] = {"note": "Could not extract the OS version number from the System string -- verify manually."}

    if use_nvd:
        print(colorize("[*] Querying NVD (rate limit: pausing between requests)...", C.CYA))
        stack = summary.get("stack", {})
        for i, (comp, ver) in enumerate(stack.items()):
            if not ver:
                continue
            if i > 0:
                time.sleep(6 if not nvd_api_key else 0.6)  # without a key: max ~5 req/30s
            results["cve"][comp] = check_nvd(comp, ver, api_key=nvd_api_key)

    return results


# --------------------------------------------------------------------------
# 8. Output
# --------------------------------------------------------------------------

def print_report(url_or_file, summary, sensitive, misconfigs, all_versions, vulns=None,
                  show_full_versions=True, infra_hints=None):
    line = "=" * 78
    print(colorize(line, C.BLD))
    print(colorize(f" phpinfo() RECON REPORT — {url_or_file}", C.BLD))
    print(colorize(line, C.BLD))

    def field(label, value):
        # Skip the field entirely if the value is empty/"no value"/"none" --
        # instead of printing "?" or "(empty!)", which only clutters the report.
        if value is None or is_empty_like(str(value)):
            return
        print(f"  {label:<18}: {value}")

    print(colorize("\n[SUMMARY]", C.BLD))
    field("PHP version", summary.get("php_version"))
    field("System (OS)", summary.get("system"))
    field("Server API", summary.get("server_api"))
    field("Server software", summary.get("server_software"))
    field("User/Group", summary.get("user_group"))
    field("Document root", summary.get("document_root"))
    field("Script filename", summary.get("script_filename"))
    field("Config file (ini)", summary.get("config_file"))
    field("extension_dir", summary.get("extension_dir"))
    field("session.save_path", summary.get("session_save_path"))
    if summary.get("database_extensions"):
        print(f"  {'DB extensions':<18}: {', '.join(summary['database_extensions'])}")
    if summary.get("backend_services_hint"):
        print(f"  {'Backend (hint)':<18}: {', '.join(summary['backend_services_hint'])} "
              f"(from loaded extensions -- worth checking whether reachable directly from the network)")
    # an empty open_basedir / disable_functions is a real security finding --
    # that fact is already reported separately in [SECURITY MISCONFIGURATIONS], so
    # here in the summary we also skip them when empty, like the rest of the fields.
    field("open_basedir", summary.get("open_basedir"))
    field("disable_functions", summary.get("disable_functions"))

    print(colorize("\n[STACK]", C.BLD))
    for comp, ver in summary.get("stack", {}).items():
        if ver and not is_empty_like(ver):
            print(f"  {comp:<16}: {ver}")

    print(colorize(f"\n[POTENTIAL DATA LEAKS] ({len(sensitive)})", C.BLD))
    if not sensitive:
        print("  No obvious leaks found (also check the Environment / $_SERVER sections manually).")
    for f in sorted(sensitive, key=lambda x: {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}[x["severity"]]):
        sc = SEV_COLOR.get(f["severity"], "")
        sec_tag = colorize(f"[{f['section']}]", section_color(f["section"]))
        print(f"  {colorize('['+f['severity']+']', sc)} {sec_tag} {f['key']} = {f['value']}")
        print(f"        -> {f['reason']}")

    print(colorize(f"\n[SECURITY MISCONFIGURATIONS] ({len(misconfigs)})", C.BLD))
    if not misconfigs:
        print("  No classic misconfigurations detected based on signatures.")
    for f in sorted(misconfigs, key=lambda x: {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}[x["severity"]]):
        sc = SEV_COLOR.get(f["severity"], "")
        sec_tag = colorize(f"({f['section']})", section_color(f["section"]))
        print(f"  {colorize('['+f['severity']+']', sc)} {f['directive']} = {f['value']!r}  {sec_tag}")
        print(f"        -> {f['description']}")

    if vulns is not None:
        print(colorize("\n[VULN / EOL CHECK]", C.BLD))
        any_shown = False

        for prod, info in vulns.get("eol", {}).items():
            if not info:
                continue
            if "error" in info:
                print(colorize(f"  [!] EOL {prod}: request error ({info['error']})", C.YEL))
                any_shown = True
                continue
            if "note" in info:
                # No unambiguous cycle match in endoflife.date -- nothing concrete
                # to report, so we skip it, following the "show only findings" rule.
                continue
            eol_field = info.get("eol")
            latest = info.get("latest")
            status, eol_date = classify_eol_status(eol_field)
            if status == "not_eol":
                continue  # no announced EOL -- nothing to report
            if status == "future_ok":
                continue  # EOL far in the future -- not a current problem
            if status == "past_eol":
                label = colorize("EOL / NO LONGER SUPPORTED", C.RED)
                date_str = str(eol_date) if eol_date else str(eol_field)
                print(f"  {prod} cycle {info.get('cycle')}: {label} (since {date_str}) | latest: {latest}")
            elif status == "upcoming":
                days_left = (eol_date - date.today()).days
                label = colorize("SUPPORT ENDING SOON", C.YEL)
                print(f"  {prod} cycle {info.get('cycle')}: {label} — {eol_date} (in {days_left} days) | latest: {latest}")
            any_shown = True

        for comp, info in vulns.get("cve", {}).items():
            if not info:
                continue
            if "error" in info:
                print(colorize(f"  [!] CVE {comp}: request error ({info['error']})", C.YEL))
                any_shown = True
                continue
            total = info.get("total_results", 0)
            cves = info.get("cves", [])
            if total == 0 and not cves:
                continue  # nothing found -- skip
            print(f"  CVE {comp}: ~{total} results in NVD for this phrase (verify manually, keyword search is approximate)")
            for cve in cves[:5]:
                score_s = f" CVSS {cve['score']}" if cve.get("score") else ""
                print(f"      - {cve['id']}{score_s}: {cve['summary']}")
            any_shown = True

        if not any_shown:
            print("  No EOL / CVE issues detected for the checked components (based on the available APIs).")

    if infra_hints and (infra_hints["private_ips"] or infra_hints["internal_hostnames"] or infra_hints["platform_markers"]):
        print(colorize("\n[INFRASTRUCTURE HINTS]", C.BLD))
        print("  (useful for further network recon / pivoting -- not vulnerabilities in themselves)")
        if infra_hints["private_ips"]:
            print(f"  Private IP addresses in content: {', '.join(sorted(infra_hints['private_ips']))}")
        if infra_hints["internal_hostnames"]:
            print(f"  Internal hostnames: {', '.join(sorted(infra_hints['internal_hostnames']))}")
        for platform, sname, k, v in infra_hints["platform_markers"]:
            sec_tag = colorize(f"[{sname}]", section_color(sname))
            print(f"  Platform: {colorize(platform, C.CYA)} — {sec_tag} {k} = {v}")

    if show_full_versions:
        print(colorize("\n[FULL LIST OF VERSIONS / COMPONENTS] (for manual verification)", C.BLD))
        for sname, kv in all_versions.items():
            print(f"  -- {sname} --")
            for k, v in kv.items():
                print(f"     {k}: {v}")

    print(colorize("\n" + line, C.BLD))


def build_json_report(url_or_file, summary, sensitive, misconfigs, all_versions, vulns=None):
    return {
        "source": url_or_file,
        "summary": summary,
        "potential_data_leaks": sensitive,
        "misconfigurations": misconfigs,
        "all_versions": all_versions,
        "vuln_check": vulns,
    }


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(
        description="phpinfo() analysis for pentests: recon, data leaks, misconfigurations, versions/EOL/CVE."
    )
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--url", help="URL of the phpinfo file (e.g. https://target/info.php)")
    src.add_argument("--file", help="Locally saved HTML file with phpinfo() output")

    ap.add_argument("--check-vulns", action="store_true",
                     help="Check EOL (endoflife.date) and indicative CVEs (NVD) for the detected components")
    ap.add_argument("--no-nvd", action="store_true",
                     help="With --check-vulns, skip NVD queries (EOL only) -- faster, fewer rate limits")
    ap.add_argument("--nvd-api-key", help="NVD API key (optional, raises the rate limit)")

    ap.add_argument("--insecure", action="store_true", help="Do not verify the TLS certificate (self-signed, etc.)")
    ap.add_argument("--proxy", help="Proxy for requests, e.g. http://127.0.0.1:8080 (e.g. Burp)")
    ap.add_argument("--cookie", help="Cookie(s) in the format 'a=1; b=2'")
    ap.add_argument("--header", action="append", help="Additional header 'Name: value' (can be repeated)")
    ap.add_argument("--user", help="Basic auth 'user:pass'")
    ap.add_argument("--timeout", type=int, default=15)

    ap.add_argument("--json", metavar="FILE", help="Save the full report as JSON to the given file")
    ap.add_argument("--no-full-versions", action="store_true",
                     help="Do not print the full list of all versions (only summary + leaks + misconfigurations)")
    ap.add_argument("--save-html", metavar="FILE",
                     help="Save the fetched raw phpinfo HTML locally (useful for archiving evidence)")

    args = ap.parse_args()

    # --- fetch/load ---
    if args.url:
        headers = {}
        if args.header:
            for h in args.header:
                if ":" not in h:
                    sys.exit(f"[!] Invalid --header format: {h!r}, expected 'Name: value'")
                k, v = h.split(":", 1)
                headers[k.strip()] = v.strip()

        cookies = None
        if args.cookie:
            cookies = {}
            for part in args.cookie.split(";"):
                if "=" in part:
                    k, v = part.strip().split("=", 1)
                    cookies[k] = v

        auth = None
        if args.user:
            if ":" not in args.user:
                sys.exit("[!] --user must be in the format user:pass")
            u, p = args.user.split(":", 1)
            auth = (u, p)

        print(colorize(f"[*] Fetching {args.url} ...", C.CYA))
        try:
            html = fetch_url(
                args.url, headers=headers, cookies=cookies, auth=auth,
                insecure=args.insecure, timeout=args.timeout, proxy=args.proxy
            )
        except requests.exceptions.SSLError:
            sys.exit("[!] TLS error. If this is a self-signed cert in a test, use --insecure.")
        except requests.exceptions.RequestException as e:
            sys.exit(f"[!] Error fetching URL: {e}")
        source_label = args.url
    else:
        html = load_local(args.file)
        source_label = args.file

    if args.save_html:
        Path(args.save_html).write_text(html, encoding="utf-8")
        print(colorize(f"[*] Raw HTML saved to {args.save_html}", C.CYA))

    # heuristic check that this really is phpinfo
    if "phpinfo()" not in html and "PHP Version" not in html and "PHP Credits" not in html:
        print(colorize("[!] Warning: the HTML does not clearly look like phpinfo() output -- "
                        "continuing, but the results may be incomplete/wrong.", C.YEL))

    # --- parsing ---
    data = parse_phpinfo(html)
    summary = build_summary(data)
    sensitive = scan_sensitive_data(data)
    misconfigs = check_misconfigs(data)
    all_versions = collect_all_versions(data)
    infra_hints = collect_infra_hints(data)
    _attack_surface_findings, backend_services = check_attack_surface(data["sections"])
    summary["backend_services_hint"] = sorted(backend_services)

    vulns = None
    if args.check_vulns:
        vulns = run_vuln_checks(summary, nvd_api_key=args.nvd_api_key, use_nvd=not args.no_nvd)

    # --- output ---
    print_report(source_label, summary, sensitive, misconfigs, all_versions, vulns,
                 show_full_versions=not args.no_full_versions, infra_hints=infra_hints)

    if args.json:
        report = build_json_report(source_label, summary, sensitive, misconfigs, all_versions, vulns)
        report["infrastructure_hints"] = {
            "private_ips": sorted(infra_hints["private_ips"]),
            "internal_hostnames": sorted(infra_hints["internal_hostnames"]),
            "platform_markers": [
                {"platform": p, "section": s, "key": k, "value": v}
                for (p, s, k, v) in infra_hints["platform_markers"]
            ],
        }
        Path(args.json).write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
        print(colorize(f"\n[*] Full JSON report saved to {args.json}", C.CYA))

    # exit code signalling "found something interesting" -- useful in scripts/CI
    if sensitive or any(m["severity"] == "HIGH" for m in misconfigs):
        sys.exit(2)


if __name__ == "__main__":
    main()
