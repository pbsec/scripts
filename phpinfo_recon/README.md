###### phpinfo_recon.py (v1.0)

## About

Skrypt do analizy bezpieczeństwa środowiska/aplikacji w oparciu o udostępniony plik `phpinfo()` (`info.php` / `phpinfo.php` / etc). Program przyjmuje adres URL lub lokalny HTML w oparciu o który dokonuje rekonesans. Output zwracany jest do terminala w przystępnej formie.

## Features

  - Pobiera phpinfo z URL-a albo wczytuje lokalny zapisany HTML.
  - Parsuje pełną strukturę phpinfo() do słownika (sekcja -> dyrektywa -> wartość).
  - Wypisuje "summary" najciekawszych informacji (stack, ścieżki, user, itd.).
  - Skanuje pod kątem potencjalnych wycieków danych (hasła, klucze, tokeny).
  - Sprawdza typowe security misconfiguration w php.ini.
  - Opcjonalnie (--check-vulns) sprawdza aktualność komponentów przez
    zewnętrzne API (endoflife.date + NVD) zamiast trzymać lokalną bazę CVE.

## Usage

```
$ python3 phpinfo_recon.py --help

usage: phpinfo_recon.py [-h] (--url URL | --file FILE) [--check-vulns] [--no-nvd] [--nvd-api-key NVD_API_KEY] [--insecure] [--proxy PROXY] [--cookie COOKIE] [--header HEADER]
                        [--user USER] [--timeout TIMEOUT] [--json PLIK] [--no-full-versions] [--save-html PLIK]

Analiza phpinfo() pod kątem pentestów: recon, data leaks, misconfig, wersje/EOL/CVE.

optional arguments:
  -h, --help            show this help message and exit
  --url URL             URL do pliku phpinfo (np. https://target/info.php)
  --file FILE           Lokalny zapisany plik HTML z wyjściem phpinfo()
  --check-vulns         Sprawdź EOL (endoflife.date) i orientacyjne CVE (NVD) dla wykrytych komponentów
  --no-nvd              Przy --check-vulns pomiń zapytania do NVD (tylko EOL) — szybciej, mniej rate-limitów
  --nvd-api-key NVD_API_KEY
                        Klucz API do NVD (opcjonalnie, podnosi rate limit)
  --insecure            Nie weryfikuj certyfikatu TLS (self-signed itp.)
  --proxy PROXY         Proxy dla requestów, np. http://127.0.0.1:8080 (np. Burp)
  --cookie COOKIE       Ciasteczko(a) w formacie 'a=1; b=2'
  --header HEADER       Dodatkowy nagłówek 'Nazwa: wartość' (można wielokrotnie)
  --user USER           Basic auth 'user:pass'
  --timeout TIMEOUT
  --json PLIK           Zapisz pełny raport jako JSON do wskazanego pliku
  --no-full-versions    Nie wypisuj pełnej listy wszystkich wersji (tylko summary + leaks + misconfig)
  --save-html PLIK      Zapisz pobrany surowy HTML phpinfo lokalnie (przydatne do archiwizacji dowodu)
```

## Examples

```
python3 phpinfo_recon.py --url https://woot.xyz/info.php
python3 phpinfo_recon.py --url https://woot.xyz/info.php --insecure --check-vulns
python3 phpinfo_recon.py --file woot_phpinfo.html --json wootwoot_report.json
```

