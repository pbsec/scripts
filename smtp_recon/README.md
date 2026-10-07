###### smtp_recon.py (v1.0)

## About

Skrypt do analizy bezpieczeństwa oraz mapowania infrastruktury w oparciu o nagłówki wiadomości SMTP. 
Use case: Realizowanie projektu (np. aplikacja www) gdzie przychodzi mail na skrzynkę, surowe nagłówki wrzucane są do programu który analizuję bezpieczeństwo konfiguracji oraz mapuje wykorzystywaną infrastrukturę.


## Features

  - Mapowanie infrastruktury (Received: chain -> IP, hostnames, hops, IPs)
  - Fingerprinting oprogramowania (MTA, mailery, AV, klienty pocztowe + wersje, itp.)
  - Bezpieczeństwo SPF / DKIM / DMARC / ARC / TLS / itp.
  - Inne "ciekawe" nagłówki (X-Originating-IP, mismatch From/Reply-To/Return-Path,
    X-Spam-*, wewnętrzne IP w nagłówkach, custom X- headers, itp.)

## Usage

```
$ python3 smtp_recon.py --help
usage: smtp_recon.py [-h] --headers HEADERS [--json JSON] [--dns] [--deep] [--no-color]

Analiza bezpieczeństwa nagłówków SMTP (pentest / recon).

optional arguments:
  -h, --help         show this help message and exit
  --headers HEADERS  Plik z nagłówkami/wiadomością (.txt/.eml)
  --json JSON        Zapisz raport również do pliku JSON
  --dns              Wykonaj zapytania DNS (SPF/DMARC/MX/BIMI/MTA-STS/TLS-RPT, ASN, siła klucza DKIM) dla domeny nadawcy (wymaga dnspython i dostępu do sieci)
  --deep             Rozszerza --dns o pełną weryfikację konfiguracji: rekurencyjne rozwinięcie SPF (include/redirect + limit 10 lookupów), spójność PTR<->A dla każdego
                     publicznego hopa, grupowanie ASN, DNSSEC oraz podsumowanie postawy bezpieczeństwa domeny i hipotezy rekonesansu. Implikuje --dns. Więcej zapytań DNS =
                     wolniejsze wykonanie.
  --no-color         Wyłącz kolorowanie output
```

Flaga `--headers` jako mus, jedynie pasywna analiza.
Flaga `--dns` jako dodatkowe active checks.
Flaga `--deep` jako kompletna analiza, inkluduje `--dns`.

## Examples

```
python3 smtp_recon.py --headers msg.txt
python3 smtp_recon.py --headers msg.txt --dns
python3 smtp_recon.py --headers msg.eml --deep --json msg_check.json
```



