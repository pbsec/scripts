#!/usr/bin/env python3
"""
phpinfo_recon.py
================
Narzędzie do analizy stron phpinfo() (info.php, phpinfo.php, test.php itp.)
napotkanych podczas testów penetracyjnych.

Funkcje:
  - Pobiera phpinfo z URL-a albo wczytuje lokalny zapisany HTML.
  - Parsuje pełną strukturę phpinfo() do słownika (sekcja -> dyrektywa -> wartość).
  - Wypisuje "summary" najciekawszych informacji (stack, ścieżki, user, itd.).
  - Skanuje pod kątem potencjalnych wycieków danych (hasła, klucze, tokeny).
  - Sprawdza typowe security misconfiguration w php.ini.
  - Opcjonalnie (--check-vulns) sprawdza aktualność komponentów przez
    zewnętrzne API (endoflife.date + NVD) zamiast trzymać lokalną bazę CVE.

Użycie:
    python3 phpinfo_recon.py --url https://target.tld/info.php
    python3 phpinfo_recon.py --file saved_phpinfo.html
    python3 phpinfo_recon.py --url https://target.tld/info.php --check-vulns
    python3 phpinfo_recon.py --url https://target.tld/info.php --json out.json

Wymagania:
    pip install requests beautifulsoup4 lxml

Autor: tool dla wewnętrznego użytku pentesterskiego. Używać wyłącznie
w ramach autoryzowanych testów bezpieczeństwa.
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
    sys.exit("[!] Brak modułu 'requests'. Zainstaluj: pip install requests beautifulsoup4 lxml")

try:
    from bs4 import BeautifulSoup
except ImportError:
    sys.exit("[!] Brak modułu 'beautifulsoup4'. Zainstaluj: pip install requests beautifulsoup4 lxml")

warnings.filterwarnings("ignore", message="Unverified HTTPS request")

# --------------------------------------------------------------------------
# Kolory (opcjonalne, degradują się ładnie jeśli terminal nie wspiera)
# --------------------------------------------------------------------------

class C:
    RED = "\033[91m"
    YEL = "\033[93m"
    GRN = "\033[92m"
    CYA = "\033[96m"
    BLD = "\033[1m"
    END = "\033[0m"
    # Paleta dla kategorii/sekcji (np. "[PHP Variables]", "[Apache Environment]") —
    # osobna od kolorów severity (RED/YEL/GRN/CYA), żeby dało się jednym rzutem oka
    # odróżnić "z jakiej sekcji phpinfo pochodzi finding" niezależnie od jego wagi.
    SECTION_PALETTE = [
        "\033[95m",  # magenta
        "\033[94m",  # blue
        "\033[35m",  # dark magenta
        "\033[34m",  # dark blue
        "\033[36m",  # dark cyan
        "\033[33m",  # dark yellow
        "\033[92m",  # bright green (rzadziej używany jako severity=INFO, ale ok w innym kontekście)
        "\033[97m",  # bright white
    ]


def colorize(text, color):
    if not sys.stdout.isatty():
        return text
    return f"{color}{text}{C.END}"


SEV_COLOR = {"HIGH": C.RED, "MEDIUM": C.YEL, "LOW": C.CYA, "INFO": C.GRN}

_section_color_cache = {}


def section_color(section_name):
    """Przypisuje stały (deterministyczny w ramach jednego uruchomienia) kolor
    danej sekcji/kategorii phpinfo, żeby np. wszystkie findingi z 'PHP Variables'
    miały ten sam kolor, a 'Apache Environment' inny."""
    if section_name not in _section_color_cache:
        idx = len(_section_color_cache) % len(C.SECTION_PALETTE)
        _section_color_cache[section_name] = C.SECTION_PALETTE[idx]
    return _section_color_cache[section_name]



# --------------------------------------------------------------------------
# 1. Pobieranie / wczytywanie phpinfo
# --------------------------------------------------------------------------

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
    )
    resp.raise_for_status()
    return resp.text


def load_local(path):
    p = Path(path)
    if not p.exists():
        sys.exit(f"[!] Plik nie istnieje: {path}")
    return p.read_text(encoding="utf-8", errors="replace")


# --------------------------------------------------------------------------
# 2. Parsowanie HTML phpinfo() do struktury: {sekcja: {dyrektywa: wartość}}
# --------------------------------------------------------------------------

def parse_phpinfo(html):
    """
    Standardowy layout phpinfo():
      <h1>PHP Version X.Y.Z</h1>
      <table> ... System / Build Date / Server API / ... (bez nagłówka h2) </table>
      <h2>core</h2><table>...</table>
      <h2>openssl</h2><table>...</table>
      ...
    Wiersze tabel mają 2 kolumny (nazwa modułu + wartość) albo 3
    (dyrektywa / Local Value / Master Value).
    """
    soup = BeautifulSoup(html, "lxml")

    data = {"_meta": {}, "sections": {}}

    # PHP Version z <h1>
    h1 = soup.find("h1")
    if h1:
        m = re.search(r"PHP Version\s*([\d.]+(?:-\w+)?)", h1.get_text())
        if m:
            data["_meta"]["php_version"] = m.group(1)

    tables = soup.find_all("table")
    if not tables:
        sys.exit("[!] Nie znaleziono żadnej tabeli w HTML — to nie wygląda na "
                  "standardowe wyjście phpinfo(). Sprawdź plik/URL.")

    for table in tables:
        # nazwa sekcji = najbliższy poprzedzający h2 (albo h1 dla 1. tabeli "General")
        section_tag = table.find_previous(["h2", "h1"])
        if section_tag is None or section_tag.name == "h1":
            # Tabela przed pierwszym <h2> (albo brak nagłówków w ogóle) to zawsze
            # sekcja ogólna "System / Build Date / Server API / ..." w phpinfo().
            section_name = "General"
        else:
            section_name = section_tag.get_text(strip=True)
        section_name = re.sub(r"\s+", " ", section_name)

        bucket = data["sections"].setdefault(section_name, {})

        for row in table.find_all("tr"):
            cells = row.find_all(["td", "th"])
            texts = [c.get_text(" ", strip=True) for c in cells]
            texts = [t for t in texts]
            if len(texts) == 0:
                continue
            if len(texts) == 1:
                # np. nagłówek wewnątrz tabeli (nazwa rozszerzenia jako pojedyncza komórka)
                bucket[texts[0]] = ""
            elif len(texts) == 2:
                key, val = texts
                bucket[key] = val
            elif len(texts) >= 3:
                key, local, master = texts[0], texts[1], texts[2]
                bucket[key] = {"local": local, "master": master}

    return data


# --------------------------------------------------------------------------
# 3. Ekstrakcja "summary" — najciekawsze rzeczy dla pentestera
# --------------------------------------------------------------------------

def get_val(v):
    """Sprowadza wartość (str albo {'local':..,'master':..}) do stringa (local)."""
    if isinstance(v, dict):
        return v.get("local", "")
    return v


def find_key(sections, section_hint, key_regex):
    """Szuka klucza pasującego do regexu w danej sekcji (case-insensitive)."""
    sec = sections.get(section_hint, {})
    for k, v in sec.items():
        if re.search(key_regex, k, re.I):
            return k, get_val(v)
    return None, None


def find_anywhere(sections, key_regex, section_regex=None):
    """Szuka klucza pasującego do regexu w dowolnej sekcji."""
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
    # User/Group bywa w różnych miejscach zależnie od SAPI: najczęściej w sekcji
    # apache2handler, czasem w General, czasem tylko pośrednio przez
    # APACHE_RUN_USER/APACHE_RUN_GROUP w Environment.
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
            s["user_group"] = f"{run_user or '?'} / {run_group or '?'} (z APACHE_RUN_USER/GROUP)"
    _, s["open_basedir"] = find_key(sections, "core", r"^open_basedir$")
    _, s["disable_functions"] = find_key(sections, "core", r"^disable_functions$")
    _, s["disable_classes"] = find_key(sections, "core", r"^disable_classes$")
    _, s["session_save_path"] = find_key(sections, "session", r"^session\.save_path$")
    _, s["upload_tmp_dir"] = find_key(sections, "core", r"^upload_tmp_dir$")

    # Stack komponentów z wersjami.
    # Dla każdego rozszerzenia sprawdzamy KILKA możliwych nazw kluczy w kolejności
    # priorytetu, ale i tak zawsze wybieramy pierwszą wartość ZAWIERAJĄCĄ CYFRĘ
    # (np. "7.68.0"), a nie ogólnikowe "enabled"/"disabled" — inaczej dla curl
    # łapało się "cURL Information: enabled" zamiast realnej wersji z klucza "Version".
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

    # database extensions ogólnie obecne
    db_exts = [name for name in sections.keys()
               if re.search(r"mysqli|pdo_mysql|pgsql|pdo_pgsql|sqlite|mongodb|oci8|sqlsrv|pdo_sqlsrv", name, re.I)]
    s["database_extensions"] = db_exts

    return s


# --------------------------------------------------------------------------
# 4. Wykrywanie potencjalnych wycieków danych
# --------------------------------------------------------------------------

# --- Detekcja po NAZWIE klucza: dopasowanie całych tokenów, nie podciągów. ---
# To eliminuje false-positives typu "tokenizer" (zawiera "token" jako substring,
# ale to inne słowo), "Authors", "Tokenizer Support" itp.
#
# Klucz jest dzielony na tokeny alfanumeryczne (np. "$_SERVER['DB_PASSWORD']"
# -> ["server", "db", "password"]) i sprawdzany:
#   1) czy jakikolwiek POJEDYNCZY token jest w SENSITIVE_KEY_TOKENS, albo
#   2) czy jakaś SĄSIADUJĄCA PARA tokenów jest w SENSITIVE_KEY_TOKEN_PAIRS
#      (żeby złapać np. "db_pass", "api_key", "connection_string").

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

# Klucze, które z nazwy wyglądają podejrzanie, ale w praktyce prawie zawsze
# nie są sekretem (klasyczny false positive) — pomijamy je jawnie.
KEY_FALSE_POSITIVE_EXACT = {"pwd", "oldpwd"}  # PWD = bieżący katalog roboczy shella, nie hasło


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


# --- Detekcja po WARTOŚCI: konkretne, wysoko-pewne wzorce (HIGH). ---
SENSITIVE_VALUE_PATTERNS = [
    ("AWS Access Key ID", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("Connection string z hasłem", re.compile(r"(mysql|postgres|postgresql|mongodb|redis)://[^:\s]+:[^@\s]+@")),
    ("Private key block", re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("Slack token", re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,}")),
    ("Google API key", re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    ("Generic bearer token w wartości", re.compile(r"Bearer\s+[A-Za-z0-9\-._~+/]{20,}=*")),
    ("JWT", re.compile(r"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+")),
]

# Klucze, które prawie zawsze są identyfikatorami/hashami/numerami seryjnymi,
# a NIE sekretami — wykluczamy je z heurystyki entropii, żeby nie łapać rzeczy
# typu SSL_SERVER_M_SERIAL, ETag, request_id, session_id, checksumy itp.
IDENTIFIER_KEY_RE = re.compile(
    r"serial|fingerprint|thumbprint|checksum|\bhash\b|md5|sha1|sha256|etag|"
    r"session_?id|request_?id|trace_?id|build_?id|uuid|guid|\bid\b",
    re.I,
)

_HEX_ONLY_RE = re.compile(r"^[0-9A-Fa-f]{32,64}$")


_BASE64_STRICT_RE = re.compile(r"^[A-Za-z0-9+/_-]+={0,2}$")


def looks_like_random_secret(val):
    """
    Heurystyka entropii dla wartości, których NAZWA klucza nic nie sugeruje,
    ale wartość wygląda jak losowy sekret (np. hardkodowany klucz w custom
    dyrektywie ini). Świadomie ostrożna, żeby nie łapać hashy/serial numbers
    ani zwykłych stringów konfiguracyjnych:
      - wartość MUSI składać się WYŁĄCZNIE ze znaków alfabetu base64/base64url
        (A-Za-z0-9+/_- oraz ewentualny padding "="). To jest kluczowy filtr:
        nagłówki HTTP typu "Accept: text/html,application/xhtml+xml;q=0.9,*/*"
        czy ścieżki systemowe ("/sys/fs/cgroup/.../memory.pressure") zawierają
        przecinki/średniki/kropki/gwiazdki spoza tego alfabetu i są od razu
        odrzucane, zamiast polegać tylko na "brak spacji",
      - odrzuca czysty hex (typowe dla MD5/SHA1/SHA256/numerów seryjnych),
      - wymaga zróżnicowania klas znaków (mała/wielka litera/cyfra/+/=),
      - długość w typowym zakresie dla base64 sekretów (32-88 znaków).
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


# Sekcje, w których wycieki są najbardziej prawdopodobne i "soczyste"
# (bez zbędnych kotwic ^$ — realne sekcje to np. "Environment", "Apache Environment",
# "PHP Variables", nazwy modułów typu apache2handler itp.)
HIGH_VALUE_SECTIONS_RE = r"Environment|PHP Variables|\$_SERVER|\$_ENV|apache2handler"

EMPTY_LIKE = {"", "no value", "none", "n/a", "0", "off"}


def is_empty_like(val):
    return (val or "").strip().lower() in EMPTY_LIKE


# Nazwy kluczy, które z brzmienia wyglądają jak "token/secret", ale z definicji
# NIE są poufne — CSRF/XSRF tokeny są celowo czytelne dla JS po stronie klienta
# (double-submit cookie pattern), więc ich obecność w $_COOKIE / $_SERVER to
# normalny stan rzeczy, a nie wyciek danych.
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
                    "reason": "Nazwa klucza sugeruje wrażliwe dane (hasło/token/secret) i pole nie jest puste"
                             + (" [sekcja wysokiego ryzyka: env/server vars]" if is_high_value_section else ""),
                })
                continue  # nie dubluj z kolejnymi checkami dla tego samego pola

            value_pattern_hit = False
            for label, pattern in SENSITIVE_VALUE_PATTERNS:
                if pattern.search(val):
                    findings.append({
                        "severity": "HIGH",
                        "section": sname,
                        "key": k,
                        "value": val,
                        "reason": f"Wartość pasuje do wzorca: {label}",
                    })
                    value_pattern_hit = True
                    break
            if value_pattern_hit:
                continue

            # heurystyka entropii — tylko gdy klucz NIE jest znanym identyfikatorem
            if not IDENTIFIER_KEY_RE.search(k) and looks_like_random_secret(val):
                findings.append({
                    "severity": "MEDIUM",
                    "section": sname,
                    "key": k,
                    "value": val,
                    "reason": "Wartość ma wysoką entropię i wygląda jak losowy sekret (base64-podobny) — "
                              "zweryfikuj ręcznie, to heurystyka i może dawać false-positive.",
                })

    return findings


# --------------------------------------------------------------------------
# 5. Security misconfigurations (php.ini)
# --------------------------------------------------------------------------

# (sekcja, dyrektywa, "zła" wartość regex, severity, opis)
# Opis w nawiasach kwadratowych to zgrubne odniesienie do OWASP Top 10 2021 /
# OWASP ASVS 4.0, żeby łatwiej było to wpiąć do raportu z testów.
MISCONFIG_CHECKS = [
    ("core", "display_errors", r"^(on|1|stdout|stderr)$", "MEDIUM",
     "display_errors włączone — błędy PHP (ze ścieżkami, zapytaniami SQL, stack trace) mogą być widoczne dla atakującego. "
     "[OWASP A05:2021 Security Misconfiguration]"),
    ("core", "expose_php", r"^on$", "LOW",
     "expose_php włączone — ułatwia fingerprinting (choć sam plik phpinfo już to zdradza). [OWASP A05:2021]"),
    ("core", "allow_url_include", r"^on$", "HIGH",
     "allow_url_include=On — w połączeniu z LFI daje bezpośrednie RCE (remote file inclusion). "
     "[OWASP A03:2021 Injection]"),
    ("core", "allow_url_fopen", r"^on$", "LOW",
     "allow_url_fopen=On — standardowo On, ale zwiększa powierzchnię ataku przy SSRF/LFI (include() zdalnych URLi jeśli allow_url_include też On)."),
    ("core", "register_globals", r"^on$", "HIGH",
     "register_globals włączone (bardzo stare/niebezpieczne, usunięte w PHP 5.4+) — masowe podatności na injection zmiennych. "
     "[OWASP A03:2021 Injection]"),
    ("core", "magic_quotes_gpc", r"^on$", "LOW",
     "magic_quotes_gpc — przestarzała, usunięta w PHP 5.4, jeśli widoczna to bardzo stary PHP."),
    ("core", "open_basedir", r"^(no value|none|)$", "MEDIUM",
     "open_basedir nieustawiony — brak ograniczenia dostępu do filesystemu z poziomu PHP (istotne przy LFI/RCE). "
     "[OWASP ASVS V12.5, A01:2021 Broken Access Control]"),
    ("core", "disable_functions", r"^(no value|none|)$", "MEDIUM",
     "disable_functions puste — niebezpieczne funkcje (exec, system, shell_exec, passthru...) mogą być dostępne przy RCE. "
     "[OWASP ASVS V14.4, A05:2021]"),
    ("core", "short_open_tag", r"^on$", "LOW",
     "short_open_tag włączone — zwiększa ryzyko przy uploadzie plików z rozszerzeniem innym niż .php (np. .phtml, .html w niektórych konfiguracjach)."),
    ("core", "file_uploads", r"^on$", "INFO",
     "file_uploads włączone — sprawdź czy jest walidacja typu/rozszerzenia po stronie aplikacji. "
     "[OWASP ASVS V12.1-V12.2 File Upload]"),
    ("core", "session.cookie_httponly", r"^(off|0|no value)$", "MEDIUM",
     "session.cookie_httponly wyłączone — ciasteczko sesji dostępne z JS (ryzyko przy XSS). [OWASP ASVS V3.4.1]"),
    ("session", "session.cookie_httponly", r"^(off|0|no value)$", "MEDIUM",
     "session.cookie_httponly wyłączone — ciasteczko sesji dostępne z JS (ryzyko przy XSS). [OWASP ASVS V3.4.1]"),
    ("session", "session.cookie_secure", r"^(off|0|no value)$", "MEDIUM",
     "session.cookie_secure wyłączone — ciasteczko sesji może wyciec przez HTTP (brak wymogu HTTPS). [OWASP ASVS V3.4.2]"),
    ("session", "session.cookie_samesite", r"^(no value|none|)$", "MEDIUM",
     "session.cookie_samesite nieustawione — słabsza ochrona przed CSRF na nowoczesnych przeglądarkach. "
     "[OWASP A01:2021, ASVS V3.4.3]"),
    ("session", "session.use_strict_mode", r"^(off|0|no value)$", "MEDIUM",
     "session.use_strict_mode wyłączone — serwer akceptuje niezainicjowane/dowolne ID sesji podane przez klienta "
     "= session fixation. [OWASP ASVS V3.2.2]"),
    ("session", "session.use_trans_sid", r"^(on|1)$", "HIGH",
     "session.use_trans_sid włączone — ID sesji może być wstrzykiwane w URL, co powoduje jego wyciek przez "
     "logi serwera, historię przeglądarki i nagłówek Referer u zewnętrznych stron. [OWASP ASVS V3.3.1, A07:2021]"),
    ("session", "session.use_only_cookies", r"^(off|0|no value)$", "HIGH",
     "session.use_only_cookies wyłączone — serwer akceptuje ID sesji przekazane w URL/GET, ułatwiając session "
     "fixation i wyciek sesji przez logi/Referer. [OWASP ASVS V3.3.1]"),
    ("core", "cgi.fix_pathinfo", r"^(on|1)$", "MEDIUM",
     "cgi.fix_pathinfo=On z PHP-FPM/nginx bez odpowiedniej konfiguracji może prowadzić do path traversal / RCE "
     "(CVE-2012-1823 i pochodne). [OWASP A03:2021]"),
    ("core", "assert.active", r"^(on|1)$", "HIGH",
     "assert.active włączone (PHP < 8) — assert() z argumentem string wykonuje go jako kod PHP; klasyczny "
     "prymityw RCE jeśli dane wejściowe trafiają do assert(). [OWASP A03:2021 Injection]"),
    ("core", "enable_dl", r"^(on|1)$", "MEDIUM",
     "enable_dl włączone — pozwala na dynamiczne ładowanie dowolnych rozszerzeń .so w runtime, co zwiększa "
     "powierzchnię ataku przy zapisywalnym katalogu rozszerzeń. [OWASP A05:2021]"),
    ("core", "phar.readonly", r"^(off|0)$", "MEDIUM",
     "phar.readonly wyłączone — możliwe tworzenie/zapis archiwów .phar, co w połączeniu z uploadem plików i "
     "podatnym unserialize()/gadget chainem otwiera drogę do PHP Object Injection przez phar:// stream wrapper. "
     "[OWASP A08:2021 Software and Data Integrity Failures]"),
    ("core", "zend.exception_ignore_args", r"^(off|0|no value)$", "MEDIUM",
     "zend.exception_ignore_args wyłączone przy display_errors=On (PHP 7.4+) — stack trace w komunikacie błędu "
     "zawiera wartości argumentów wywołań funkcji (potencjalnie hasła/tokeny przekazane jako parametry). "
     "[OWASP A05:2021, A02:2021 Cryptographic Failures gdy w argumentach są sekrety]"),
    ("core", "html_errors", r"^(on|1)$", "LOW",
     "html_errors włączone razem z display_errors — komunikaty błędów renderowane jako HTML czasem odzwierciedlają "
     "dane wejściowe (np. nazwy kluczy z GET/POST), co bywa wektorem reflected XSS. [OWASP A03:2021]"),
    ("core", "max_execution_time", r"^0$", "LOW",
     "max_execution_time=0 (bez limitu) — brak ochrony przed długo działającymi requestami, ułatwia DoS przez "
     "wyczerpanie zasobów. [OWASP ASVS V13.4, A04:2021 Insecure Design]"),
    ("core", "memory_limit", r"^-1$", "LOW",
     "memory_limit=-1 (bez limitu) — pojedynczy request może zużyć całą dostępną pamięć = DoS przez wyczerpanie "
     "zasobów. [OWASP A04:2021]"),
    ("core", "log_errors", r"^(off|0)$", "LOW",
     "log_errors wyłączone — błędy PHP nie są logowane po stronie serwera, co utrudnia wykrycie ataku i incident "
     "response. [OWASP ASVS V7.1 Log Content]"),
    ("core", "mysql.default_password", r".+", "INFO",
     "Znaleziono wartość w mysql.default_password — sprawdź ręcznie, potencjalny leak."),
    ("core", "sql.safe_mode", r"^on$", "INFO",
     "sql.safe_mode — przestarzała dyrektywa, jej obecność wskazuje na bardzo stary PHP."),
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
    Xdebug w środowisku, które wygląda na produkcyjne (a phpinfo() bywa
    zapominane właśnie na produkcji), to bardzo częsty i wysoko-wartościowy
    finding: ujawnia dodatkowe dane w komunikatach błędów, potrafi znacząco
    obniżyć wydajność, a przy xdebug.mode zawierającym "debug"/"trace" i
    dostępnym porcie 9003/9000 bywa wykorzystywane do zdalnego debugowania
    (efektywnie zdalne wykonanie kodu przez podłączenie debuggera).
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
            "description": "Xdebug załadowany z aktywnym trybem debug/trace/remote — jeśli port debuggera jest "
                            "osiągalny z sieci atakującego, to efektywnie prymityw zdalnego wykonania kodu. "
                            "Xdebug nie powinien być obecny na produkcji. [OWASP A05:2021]",
        })
    else:
        findings.append({
            "severity": "MEDIUM",
            "section": xdebug_section,
            "directive": "xdebug (loaded)",
            "value": "enabled",
            "description": "Xdebug jest załadowany. Sam fakt jego obecności na środowisku dostępnym z zewnątrz "
                            "to code smell — narzut wydajnościowy i dodatkowa powierzchnia ataku. Zweryfikuj "
                            "xdebug.mode/xdebug.remote_enable i czy port debuggera jest osiągalny. [OWASP A05:2021]",
        })
    return findings


def summary_document_root(sections):
    _, val = find_key(sections, "PHP Variables", r"DOCUMENT_ROOT")
    return val


def check_paths_inside_docroot(sections, document_root):
    """
    Katalogi/pliki wskazywane przez session.save_path, upload_tmp_dir czy
    error_log, jeśli leżą WEWNĄTRZ document root, są potencjalnie osiągalne
    bezpośrednio przez HTTP. To otwiera drogę do:
      - odczytu plików sesji innych userów (session hijacking),
      - log poisoning -> RCE (wstrzyknięcie PHP payloadu do logu przez User-Agent
        czy błędny request, a potem wywołanie logu jako pliku PHP),
      - odczytu tymczasowych plików uploadu w oknie race condition.
    [OWASP A01:2021 Broken Access Control, ASVS V12.3]
    """
    findings = []
    if not document_root:
        return findings
    docroot_norm = document_root.strip().rstrip("/")
    if not docroot_norm:
        return findings

    PATH_DIRECTIVES = [
        ("session", "session.save_path", "Katalog plików sesji", "HIGH"),
        ("core", "upload_tmp_dir", "Katalog tymczasowy uploadu plików", "MEDIUM"),
        ("core", "error_log", "Plik logu błędów PHP", "HIGH"),
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
                "description": f"{label} ({key}) znajduje się WEWNĄTRZ document root ({docroot_norm}) — "
                                "prawdopodobnie osiągalny bezpośrednio przez HTTP. Zweryfikuj, czy plik/katalog "
                                "faktycznie jest dostępny z zewnątrz (np. curl na wyliczoną ścieżkę URL).",
            })
    return findings


# --------------------------------------------------------------------------
# 5b. disable_functions "z dziurami" — hardening iluzoryczny/częściowy
# --------------------------------------------------------------------------

# Funkcje o oczywistym potencjale RCE/lateral movement, które administratorzy
# najczęściej PRÓBUJĄ wyłączać przez disable_functions. Jeśli disable_functions
# NIE jest puste (czyli ktoś faktycznie się tym zajął), ale brakuje w nim
# którejś z tych pozycji, to konkretny, actionable finding — "hardening jest,
# ale nieszczelny" — zamiast tylko binarnego "puste/niepuste".
DANGEROUS_FUNCTIONS = [
    "exec", "shell_exec", "system", "passthru", "popen", "proc_open",
    "proc_close", "pcntl_exec", "show_source", "putenv",
]


def check_disable_functions_gaps(sections):
    _, val = find_key(sections, "core", r"^disable_functions$")
    if not val or is_empty_like(val):
        return []  # puste disable_functions jest już zgłaszane osobno w MISCONFIG_CHECKS

    disabled = {f.strip().lower() for f in val.split(",") if f.strip()}
    missing = [f for f in DANGEROUS_FUNCTIONS if f.lower() not in disabled]
    if not missing:
        return []
    return [{
        "severity": "MEDIUM",
        "section": "core",
        "directive": "disable_functions (niekompletne)",
        "value": val,
        "description": "disable_functions jest ustawione (czyli hardening był próbowany), ale wciąż pozwala "
                        f"wywołać: {', '.join(missing)}. Częściowe hardenowanie bywa iluzoryczne przy RCE — "
                        "sprawdź, czy te funkcje są faktycznie potrzebne aplikacji. [OWASP ASVS V14.4]",
    }]


# --------------------------------------------------------------------------
# 5c. Attack surface: ryzykowne rozszerzenia i zarejestrowane stream wrappery
# --------------------------------------------------------------------------

# Rozszerzenia, których sama OBECNOŚĆ jest sygnałem wartym odnotowania w
# rekonesansie pentestowym — od "to niemal zawsze błąd na produkcji" (expect)
# po "sprawdź konkretny wektor" (soap/xmlrpc -> XXE, ldap -> LDAP injection).
RISKY_EXTENSION_NOTES = {
    "expect": ("KRYTYCZNE: rozszerzenie 'expect' załadowane — udostępnia stream wrapper expect://, który "
               "pozwala na bezpośrednie wykonanie poleceń systemowych (np. include('expect://id')) bez "
               "żadnego dodatkowego prymitywu. Samo załadowanie tego rozszerzenia na produkcji to praktycznie "
               "zawsze błąd konfiguracyjny. [OWASP A05:2021]", "HIGH"),
    "mcrypt": ("Rozszerzenie 'mcrypt' — usunięte z coreu PHP w 7.2 (przeniesione do PECL, biblioteka libmcrypt "
               "od dawna nieutrzymywana). Jego obecność zwykle oznacza bardzo stary PHP lub ręcznie doinstalowaną, "
               "nieaktualną bibliotekę kryptograficzną.", "LOW"),
    "imap": ("Rozszerzenie 'imap' (biblioteka c-client) — historycznie sporo CVE w tym RCE (np. przepełnienia "
             "bufora w parsowaniu odpowiedzi IMAP/POP3/NNTP). Jeśli aplikacja z niego nie korzysta, warto "
             "rozważyć usunięcie z obrazu produkcyjnego.", "LOW"),
    "soap": ("Rozszerzenie SOAP parsuje XML — sprawdź endpointy SOAP pod kątem XXE (XML External Entity), "
             "zwłaszcza jeśli libxml_disable_entity_loader() nie jest wywoływane jawnie w starszym PHP.", "INFO"),
    "xmlrpc": ("Rozszerzenie XML-RPC — historycznie podatne na XXE i inne ataki na parser XML; sprawdź, czy "
               "endpoint XML-RPC jest nadal aktywny i osiągalny.", "INFO"),
    "ldap": ("Rozszerzenie LDAP załadowane — sprawdź, czy aplikacja poprawnie escapuje dane wejściowe przy "
             "budowaniu filtrów LDAP (LDAP injection).", "INFO"),
}

# Wrappery strumieni, których obecność w "Registered PHP Streams" jest istotna
# ofensywnie — przede wszystkim expect:// (RCE) i phar:// (deserializacja/PHP
# Object Injection, już częściowo pokryte przez check phar.readonly).
INTERESTING_STREAM_WRAPPERS = {
    "expect": ("Stream wrapper 'expect://' zarejestrowany — potwierdza możliwość wykonania poleceń systemowych "
               "przez dowolną funkcję przyjmującą URL/stream (include, file_get_contents, fopen...). [OWASP A05:2021]", "HIGH"),
    "phar": ("Stream wrapper 'phar://' zarejestrowany — potencjalny wektor PHP Object Injection przy deserializacji "
             "metadanych archiwum .phar, jeśli atakujący kontroluje ścieżkę przekazywaną do funkcji plikowych.", "INFO"),
}

# Rozszerzenia sugerujące obecność konkretnych usług backendowych w stacku —
# przydatne jako podpowiedź do dalszego rekonesansu sieciowego (czy Redis/
# Memcached/Mongo są dostępne bezpośrednio z sieci, bez auth, na domyślnym porcie).
BACKEND_SERVICE_EXTENSIONS = {
    "redis": "Redis", "memcached": "Memcached", "memcache": "Memcache",
    "mongodb": "MongoDB", "pdo_pgsql": "PostgreSQL", "pgsql": "PostgreSQL",
    "oci8": "Oracle", "sqlsrv": "MSSQL", "pdo_sqlsrv": "MSSQL",
    "mysqli": "MySQL/MariaDB", "pdo_mysql": "MySQL/MariaDB", "cassandra": "Cassandra",
    "pdo_sqlite": "SQLite", "sqlite3": "SQLite",
}


def check_attack_surface(sections):
    """
    Zwraca (findings, backend_services):
      - findings: lista dictów jak w check_misconfigs, do sekcji [SECURITY MISCONFIGURATIONS]
        (ryzykowne rozszerzenia + stream wrappery — to realne security findings, nie tylko info).
      - backend_services: set nazw usług backendowych sugerowanych przez załadowane rozszerzenia
        (do osobnej, informacyjnej linii w summary — nie każdy pentester szuka tu "misconfiguration",
        ale to świetna podpowiedź co jeszcze poskanować w sieci wewnętrznej).
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
# 5d. Infrastructure fingerprinting: prywatne IP, wewnętrzne hosty, markery
#     chmury/kontenerów — przydatne do dalszego rekonesansu i pivotowania
# --------------------------------------------------------------------------

PRIVATE_IPV4_RE = re.compile(
    r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3})\b"
)
INTERNAL_HOSTNAME_RE = re.compile(
    r"\b[a-zA-Z0-9][a-zA-Z0-9.-]*\.(?:internal|local|corp|intra|lan)\b", re.I
)

# Klucze, których sama OBECNOŚĆ (niezależnie od wartości) zdradza platformę
# hostingową/orkiestrację kontenerów — świetny fingerprint infrastruktury.
PLATFORM_MARKER_KEYS = {
    "kubernetes_service_host": "Kubernetes",
    "kubernetes_port": "Kubernetes",
    "docker_container": "Docker",
    "ecs_container_metadata_uri": "AWS ECS",
    "ecs_container_metadata_uri_v4": "AWS ECS",
    "aws_execution_env": "AWS Lambda/inne AWS compute",
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
    Skanuje WSZYSTKIE wartości phpinfo (nie tylko sekcje 'wysokiego ryzyka')
    pod kątem śladów infrastruktury wewnętrznej — przydatne przy dalszym
    rekonesansie sieciowym / pivotowaniu po uzyskaniu punktu zaczepienia.
    Zwraca dict: {"private_ips": set, "internal_hostnames": set, "platform_markers": [(key, section, value)]}
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
# 6. Lista pełnego stacku wersji (do ręcznej weryfikacji, tryb domyślny)
# --------------------------------------------------------------------------

VERSION_KEY_RE = re.compile(
    r"version|release|revision|Build Date|libxml|zlib|openssl|api|client", re.I
)

# Klucze będące ewidentnie listą nazwisk / creditsów w sekcji "General"
# (np. "Extension Module API", "Server API (SAPI) Abstraction Layer") — te
# wartości nigdy nie zawierają cyfr, więc odfiltrowuje je już sam wymóg
# obecności cyfry w wartości poniżej. Ta lista to dodatkowe zabezpieczenie
# na wypadek edge case'ów (np. "Version 2" w nazwisku).
CREDITS_KEY_RE = re.compile(r"^(Thanks to|Authors?|Contribution by)", re.I)


def collect_all_versions(data):
    """
    Zbiera WSZYSTKIE pary klucz/wartość, które wyglądają jak realne numery
    wersji, per sekcja/moduł. Klucz musi pasować do VERSION_KEY_RE, ale
    dodatkowo wartość MUSI zawierać przynajmniej jedną cyfrę — to odsiewa
    pola typu "Extension Module API: Andi Gutmans, Zeev Suraski..." (lista
    autorów/credits z sekcji General), które łapały się wcześniej tylko
    dlatego, że nazwa klucza zawierała słowo "API"/"libxml"/"openssl" itp.
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
# 7. --check-vulns : EOL + CVE przez publiczne API (bez lokalnej bazy)
# --------------------------------------------------------------------------

EOL_API = "https://endoflife.date/api/{product}.json"
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# heurystyczna mapa: co z phpinfo -> jaki produkt w endoflife.date
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
    (r"win(dows|nt)", "windows-server"),  # przybliżone, endoflife.date ma różne produkty windows
]


def check_eol(product, version):
    """Zwraca info o EOL dla danego produktu+wersji z endoflife.date."""
    try:
        resp = requests.get(EOL_API.format(product=product), timeout=10)
        if resp.status_code != 200:
            return None
        cycles = resp.json()
    except Exception as e:
        return {"error": str(e)}

    # dopasuj po cyklu (np. "8.1" dla wersji "8.1.27")
    ver_major_minor = ".".join(version.split(".")[:2]) if version else ""
    for cycle in cycles:
        if str(cycle.get("cycle")) == ver_major_minor or str(cycle.get("cycle")) == version:
            return cycle
    return {"note": f"Brak dokładnego dopasowania cyklu '{ver_major_minor}' w endoflife.date"}


# Ile dni do przodu traktujemy zbliżający się EOL jako "warty pokazania" —
# EOL za 5 lat to nie finding pentestowy, EOL za 3 miesiące już tak.
UPCOMING_EOL_HORIZON_DAYS = 180


def classify_eol_status(eol_field):
    """
    endoflife.date w polu "eol" zwraca:
      - False              -> nigdy nie ogłoszono końca wsparcia
      - True                -> EOL "od zawsze"/natychmiastowe (rzadkie)
      - "YYYY-MM-DD" string -> KONKRETNA DATA końca wsparcia — może być
                                w PRZESZŁOŚCI (już EOL) albo w PRZYSZŁOŚCI
                                (zaplanowany koniec wsparcia, wersja nadal żyje).

    Zwraca krotkę (status, eol_date_or_None) gdzie status to jedno z:
      "not_eol"   — brak ogłoszonego EOL, nic do zgłoszenia
      "past_eol"  — data EOL już minęła, wersja faktycznie bez wsparcia
      "upcoming"  — data EOL w przyszłości, ale w horyzoncie UPCOMING_EOL_HORIZON_DAYS
      "future_ok" — data EOL daleko w przyszłości, nic alarmującego teraz
    """
    if eol_field is False:
        return "not_eol", None
    if eol_field is True:
        return "past_eol", None
    if isinstance(eol_field, str):
        try:
            eol_date = datetime.strptime(eol_field, "%Y-%m-%d").date()
        except ValueError:
            # Nietypowy format daty z API — nie zgadujemy, traktujemy jako "nic pewnego".
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
    """Proste keyword-search po NVD. Bez klucza API: limit 5 req/30s — sami pilnujemy sleep."""
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

    # OS EOL (heurystyka)
    os_product = guess_os_product(summary.get("system", ""))
    if os_product:
        # spróbuj wyciągnąć numer wersji z system string, np "Ubuntu ... 22.04"
        m = re.search(r"(\d+\.\d+(\.\d+)?)", summary.get("system", ""))
        os_ver = m.group(1) if m else None
        if os_ver:
            results["eol"][os_product] = check_eol(os_product, os_ver)
        else:
            results["eol"][os_product] = {"note": "Nie udało się wyciągnąć numeru wersji OS ze stringa System — zweryfikuj ręcznie."}

    if use_nvd:
        print(colorize("[*] Odpytuję NVD (rate-limit: pauza między zapytaniami)...", C.CYA))
        stack = summary.get("stack", {})
        for i, (comp, ver) in enumerate(stack.items()):
            if not ver:
                continue
            if i > 0:
                time.sleep(6 if not nvd_api_key else 0.6)  # bez klucza: max ~5 req/30s
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
        # Pomijamy pole całkowicie, jeśli wartość jest pusta/"no value"/"none" —
        # zamiast wypisywać "?" albo "(puste!)", co tylko zaśmieca raport.
        if value is None or is_empty_like(str(value)):
            return
        print(f"  {label:<18}: {value}")

    print(colorize("\n[SUMMARY]", C.BLD))
    field("PHP wersja", summary.get("php_version"))
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
              f"(z załadowanych rozszerzeń — warto sprawdzić czy dostępne bezpośrednio z sieci)")
    # open_basedir / disable_functions puste to realny finding bezpieczeństwa —
    # ten fakt jest już zgłaszany osobno w [SECURITY MISCONFIGURATIONS], więc
    # tutaj w summary też je pomijamy, gdy puste, zgodnie z resztą pól.
    field("open_basedir", summary.get("open_basedir"))
    field("disable_functions", summary.get("disable_functions"))

    print(colorize("\n[STACK]", C.BLD))
    for comp, ver in summary.get("stack", {}).items():
        if ver and not is_empty_like(ver):
            print(f"  {comp:<16}: {ver}")

    print(colorize(f"\n[POTENTIAL DATA LEAKS] ({len(sensitive)})", C.BLD))
    if not sensitive:
        print("  Nie znaleziono oczywistych wycieków (sprawdź też ręcznie sekcje Environment / $_SERVER).")
    for f in sorted(sensitive, key=lambda x: {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}[x["severity"]]):
        sc = SEV_COLOR.get(f["severity"], "")
        sec_tag = colorize(f"[{f['section']}]", section_color(f["section"]))
        print(f"  {colorize('['+f['severity']+']', sc)} {sec_tag} {f['key']} = {f['value']}")
        print(f"        -> {f['reason']}")

    print(colorize(f"\n[SECURITY MISCONFIGURATIONS] ({len(misconfigs)})", C.BLD))
    if not misconfigs:
        print("  Brak wykrytych klasycznych misconfiguration na podstawie sygnatur.")
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
                print(colorize(f"  [!] EOL {prod}: błąd zapytania ({info['error']})", C.YEL))
                any_shown = True
                continue
            if "note" in info:
                # Brak jednoznacznego dopasowania cyklu w endoflife.date — nic konkretnego
                # do zaraportowania, więc pomijamy zgodnie z zasadą "pokazuj tylko znaleziska".
                continue
            eol_field = info.get("eol")
            latest = info.get("latest")
            status, eol_date = classify_eol_status(eol_field)
            if status == "not_eol":
                continue  # brak ogłoszonego EOL — nic do zgłoszenia
            if status == "future_ok":
                continue  # EOL daleko w przyszłości — nie jest to aktualny problem
            if status == "past_eol":
                label = colorize("EOL / BRAK WSPARCIA", C.RED)
                date_str = str(eol_date) if eol_date else str(eol_field)
                print(f"  {prod} cycle {info.get('cycle')}: {label} (od {date_str}) | najnowsza: {latest}")
            elif status == "upcoming":
                days_left = (eol_date - date.today()).days
                label = colorize("WSPARCIE KOŃCZY SIĘ WKRÓTCE", C.YEL)
                print(f"  {prod} cycle {info.get('cycle')}: {label} — {eol_date} (za {days_left} dni) | najnowsza: {latest}")
            any_shown = True

        for comp, info in vulns.get("cve", {}).items():
            if not info:
                continue
            if "error" in info:
                print(colorize(f"  [!] CVE {comp}: błąd zapytania ({info['error']})", C.YEL))
                any_shown = True
                continue
            total = info.get("total_results", 0)
            cves = info.get("cves", [])
            if total == 0 and not cves:
                continue  # nic nie znaleziono — pomijamy
            print(f"  CVE {comp}: ~{total} wyników w NVD dla tej frazy (weryfikuj ręcznie, keyword search jest przybliżony)")
            for cve in cves[:5]:
                score_s = f" CVSS {cve['score']}" if cve.get("score") else ""
                print(f"      - {cve['id']}{score_s}: {cve['summary']}")
            any_shown = True

        if not any_shown:
            print("  Brak wykrytych problemów EOL / CVE dla sprawdzonych komponentów (na podstawie dostępnych API).")

    if infra_hints and (infra_hints["private_ips"] or infra_hints["internal_hostnames"] or infra_hints["platform_markers"]):
        print(colorize("\n[INFRASTRUCTURE HINTS]", C.BLD))
        print("  (przydatne do dalszego rekonesansu sieciowego / pivotowania — nie są to same w sobie podatności)")
        if infra_hints["private_ips"]:
            print(f"  Prywatne adresy IP w treści: {', '.join(sorted(infra_hints['private_ips']))}")
        if infra_hints["internal_hostnames"]:
            print(f"  Wewnętrzne hostname'y: {', '.join(sorted(infra_hints['internal_hostnames']))}")
        for platform, sname, k, v in infra_hints["platform_markers"]:
            sec_tag = colorize(f"[{sname}]", section_color(sname))
            print(f"  Platforma: {colorize(platform, C.CYA)} — {sec_tag} {k} = {v}")

    if show_full_versions:
        print(colorize("\n[PEŁNA LISTA WERSJI / KOMPONENTÓW] (do ręcznej weryfikacji)", C.BLD))
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
        description="Analiza phpinfo() pod kątem pentestów: recon, data leaks, misconfig, wersje/EOL/CVE."
    )
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--url", help="URL do pliku phpinfo (np. https://target/info.php)")
    src.add_argument("--file", help="Lokalny zapisany plik HTML z wyjściem phpinfo()")

    ap.add_argument("--check-vulns", action="store_true",
                     help="Sprawdź EOL (endoflife.date) i orientacyjne CVE (NVD) dla wykrytych komponentów")
    ap.add_argument("--no-nvd", action="store_true",
                     help="Przy --check-vulns pomiń zapytania do NVD (tylko EOL) — szybciej, mniej rate-limitów")
    ap.add_argument("--nvd-api-key", help="Klucz API do NVD (opcjonalnie, podnosi rate limit)")

    ap.add_argument("--insecure", action="store_true", help="Nie weryfikuj certyfikatu TLS (self-signed itp.)")
    ap.add_argument("--proxy", help="Proxy dla requestów, np. http://127.0.0.1:8080 (np. Burp)")
    ap.add_argument("--cookie", help="Ciasteczko(a) w formacie 'a=1; b=2'")
    ap.add_argument("--header", action="append", help="Dodatkowy nagłówek 'Nazwa: wartość' (można wielokrotnie)")
    ap.add_argument("--user", help="Basic auth 'user:pass'")
    ap.add_argument("--timeout", type=int, default=15)

    ap.add_argument("--json", metavar="PLIK", help="Zapisz pełny raport jako JSON do wskazanego pliku")
    ap.add_argument("--no-full-versions", action="store_true",
                     help="Nie wypisuj pełnej listy wszystkich wersji (tylko summary + leaks + misconfig)")
    ap.add_argument("--save-html", metavar="PLIK",
                     help="Zapisz pobrany surowy HTML phpinfo lokalnie (przydatne do archiwizacji dowodu)")

    args = ap.parse_args()

    # --- pobranie/wczytanie ---
    if args.url:
        headers = {}
        if args.header:
            for h in args.header:
                if ":" not in h:
                    sys.exit(f"[!] Zły format --header: {h!r}, oczekiwano 'Nazwa: wartość'")
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
                sys.exit("[!] --user musi być w formacie user:pass")
            u, p = args.user.split(":", 1)
            auth = (u, p)

        print(colorize(f"[*] Pobieram {args.url} ...", C.CYA))
        try:
            html = fetch_url(
                args.url, headers=headers, cookies=cookies, auth=auth,
                insecure=args.insecure, timeout=args.timeout, proxy=args.proxy
            )
        except requests.exceptions.SSLError:
            sys.exit("[!] Błąd TLS. Jeśli to self-signed cert w teście, użyj --insecure.")
        except requests.exceptions.RequestException as e:
            sys.exit(f"[!] Błąd pobierania URL: {e}")
        source_label = args.url
    else:
        html = load_local(args.file)
        source_label = args.file

    if args.save_html:
        Path(args.save_html).write_text(html, encoding="utf-8")
        print(colorize(f"[*] Zapisano surowy HTML do {args.save_html}", C.CYA))

    # heurystyczna walidacja że to na pewno phpinfo
    if "phpinfo()" not in html and "PHP Version" not in html and "PHP Credits" not in html:
        print(colorize("[!] Uwaga: HTML nie wygląda jednoznacznie na wyjście phpinfo() — "
                        "kontynuuję, ale wyniki mogą być niepełne/błędne.", C.YEL))

    # --- parsowanie ---
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
        print(colorize(f"\n[*] Pełny raport JSON zapisany do {args.json}", C.CYA))

    # exit code sygnalizujący "znaleziono coś ciekawego" — przydatne w skryptach/CI
    if sensitive or any(m["severity"] == "HIGH" for m in misconfigs):
        sys.exit(2)


if __name__ == "__main__":
    main()
