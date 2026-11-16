###### smtp_recon.py (v1.0)

## About

A script for security analysis and infrastructure mapping based on SMTP message headers.
Use case: Implementing a project (e.g., a web application) where an incoming email is received in a mailbox, and the raw headers are fed into a program that analyzes the configuration's security and maps the infrastructure being used.


## Features

- Infrastructure mapping (Received: chain -> IP, hostnames, hops, IPs)
- Software fingerprinting (MTA, mailers, AV, email clients + versions, etc.)
- Security: SPF / DKIM / DMARC / ARC / TLS / etc.
- Other "interesting" headers (X-Originating-IP, mismatches between From/Reply-To/Return-Path,
X-Spam-*, internal IPs in headers, custom X- headers, etc.)

## Usage

```
$ python3 smtp_recon.py --help
usage: smtp_header_analyzer.py [-h] --headers HEADERS [--json JSON] [--dns] [--deep] [--no-color]

SMTP header security analysis (pentest / recon).

optional arguments:
  -h, --help         show this help message and exit
  --headers HEADERS  File with headers/message (.txt/.eml)
  --json JSON        Also save the report to a JSON file
  --dns              Run live DNS queries (SPF/DMARC/MX/BIMI/MTA-STS/TLS-RPT, ASN, DKIM key strength) for the sender domain (requires dnspython and network access)
  --deep             Extends --dns with a full configuration check: recursive SPF expansion (include/redirect + 10-lookup limit), PTR<->A consistency for every public hop, ASN grouping, DNSSEC, plus a
                     domain security posture summary and recon hypotheses. Implies --dns. More DNS queries = slower execution.
  --no-color         Disable colored output
```

The `--headers` flag is mandatory; it performs only passive analysis.
The `--dns` flag enables additional active checks.
The `--deep` flag triggers a comprehensive analysis, which includes `--dns`.

## Examples

```
python3 smtp_recon.py --headers msg.txt
python3 smtp_recon.py --headers msg.txt --dns
python3 smtp_recon.py --headers msg.eml --deep --json msg_check.json
```



