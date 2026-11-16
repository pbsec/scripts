###### phpinfo_recon.py (v1.0)

## About

A script for analyzing the security of an environment or application based on a provided `phpinfo()` file (e.g., `info.php`, `phpinfo.php`, etc.). The program accepts either a URL or a local HTML file and uses it to perform reconnaissance. The results are output to the terminal in an easy-to-read format.

## Features

- Fetches `phpinfo` from a URL or loads a locally saved HTML file.
- Parses the complete `phpinfo()` structure into a dictionary (section -> directive -> value).
- Outputs a summary of the most relevant information (stack, paths, user, etc.).
- Scans for potential data leaks (passwords, keys, tokens).
- Checks for common security misconfigurations in `php.ini`.
- Optionally (via the `--check-vulns` flag), verifies the currency of components using external APIs (endoflife.date + NVD) instead of maintaining a local CVE database.

## Usage

```
$ python3 phpinfo_recon.py --help

usage: phpinfo_recon.py [-h] (--url URL | --file FILE) [--check-vulns]
                        [--no-nvd] [--nvd-api-key NVD_API_KEY] [--insecure]
                        [--proxy PROXY] [--cookie COOKIE] [--header HEADER]
                        [--user USER] [--timeout TIMEOUT] [--json FILE]
                        [--no-full-versions] [--save-html FILE]

phpinfo() analysis for pentests: recon, data leaks, misconfigurations,
versions/EOL/CVE.

options:
  -h, --help            show this help message and exit
  --url URL             URL of the phpinfo file (e.g. https://target/info.php)
  --file FILE           Locally saved HTML file with phpinfo() output
  --check-vulns         Check EOL (endoflife.date) and indicative CVEs (NVD)
                        for the detected components
  --no-nvd              With --check-vulns, skip NVD queries (EOL only) --
                        faster, fewer rate limits
  --nvd-api-key NVD_API_KEY
                        NVD API key (optional, raises the rate limit)
  --insecure            Do not verify the TLS certificate (self-signed, etc.)
  --proxy PROXY         Proxy for requests, e.g. http://127.0.0.1:8080 (e.g.
                        Burp)
  --cookie COOKIE       Cookie(s) in the format 'a=1; b=2'
  --header HEADER       Additional header 'Name: value' (can be repeated)
  --user USER           Basic auth 'user:pass'
  --timeout TIMEOUT
  --json FILE           Save the full report as JSON to the given file
  --no-full-versions    Do not print the full list of all versions (only
                        summary + leaks + misconfigurations)
  --save-html FILE      Save the fetched raw phpinfo HTML locally (useful for
                        archiving evidence)
```

## Examples

```
python3 phpinfo_recon.py --url https://woot.xyz/info.php
python3 phpinfo_recon.py --url https://woot.xyz/info.php --insecure --check-vulns
python3 phpinfo_recon.py --file woot_phpinfo.html --json wootwoot_report.json
```

