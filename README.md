#  Raccoon
![Racoon](raccoon.png)

#### Offensive Security Tool for Reconnaissance and Information Gathering
![Build Status](https://travis-ci.org/evyatarmeged/Raccoon.svg?branch=master)
![license](https://img.shields.io/github/license/mashape/apistatus.svg)
![pythonver](https://img.shields.io/badge/python-3%2B-blue.svg)
![raccoonver](https://img.shields.io/badge/Raccoon%20version-0.0.1-lightgrey.svg)

##### Features
- [x] DNS details
- [x] DNS visual mapping using DNS dumpster
- [x] WHOIS information
- [x] TLS Data - supported ciphers, TLS versions,
certificate details and SANs
- [x] Port Scan
- [x] Services and scripts scan
- [x] URL fuzzing and directory detection
- [x] Subdomain enumeration - uses Google dorking, bruteforce and SAN discovery
- [x] Web application data (CMS, Web Server info, robots & sitemap
extraction)
- [x] Detects known WAFs
- [x] Supports anonymous routing through Tor/Proxies
- [x] Uses asyncio for improved performance
- [x] Saves output to files - separates targets by folders
and modules by files


##### Roadmap and TODOs
- [ ] Support multiple hosts (read from file)
- [ ] CIDR notation support
- [ ] IP ranges support
- [ ] Rate limit evasion
- [ ] OWASP vulnerabilities scan (RFI, RCE, XSS, SQLi etc.)
- [ ] SearchSploit lookup on results
- [ ] More output formats


### About
Raccoon is a tool made for reconnaissance and information gathering with an emphasis on simplicity.<br> It will do everything from
fetching DNS records, retrieving WHOIS information, obtaining TLS data, detecting WAF presence and up to threaded dir busting and
subdomain enumeration. Every scan outputs to a corresponding file.<br>
It utilizes Python's asyncio for running most scans asynchronously.<br>

Raccoon supports Tor/proxy for anonymous routing. It uses default wordlists (for URL fuzzing and subdomain discovery)
from the amazing [SecLists](https://github.com/danielmiessler/SecLists) repository but different lists can be passed as arguments.<br>

For more options - see "Usage".

### Installation
For the latest stable version:<br>
```pip install raccoon-scanner```<br>
Or clone the GitHub repository for the latest features and changes:<br>
```git clone https://github.com/evyatarmeged/Raccoon.git```

##### Prerequisites
Raccoon uses [Nmap](https://github.com/nmap/nmap) to scan ports as well as utilizes some other Nmap scripts
and features. It is mandatory that you have it installed before running Raccoon.


### Usage
```
Usage: raccoon.py [OPTIONS]

Options:
  -t, --target TEXT              Target to scan  [required]
  -d, --dns-records TEXT         Comma separated DNS records to query.
                                 Defaults to: A, MX, NS, CNAME, SOA
  --tor-routing                  Route HTTP traffic through Tor. Slows total
                                 runtime significantly
  --proxy-list TEXT              Path to proxy list file that would be used
                                 for routing HTTP traffic. A proxy from the
                                 list will be chosen at random for each
                                 request. Slows total runtime
  --proxy TEXT                   Proxy address to route HTTP traffic through.
                                 Slows total runtime
  -w, --wordlist TEXT            Path to wordlist that would be used for URL
                                 fuzzing
  -T, --threads INTEGER          Number of threads to use for URL
                                 Fuzzing/Subdomain enumeration. Default: 25
  --ignored-response-codes TEXT  Comma separated list of HTTP status code to
                                 ignore for fuzzing. Defaults to:
                                 301,400,401,403,402,404,504
  --subdomain-list TEXT          Path to subdomain list file that would be
                                 used for enumeration
  -f, --full-scan                Run Nmap scan with both -sV and -sC
  -S, --scripts                  Run Nmap scan with -sC flag
  -s, --services                 Run Nmap scan with -sV flag
  -p, --port TEXT                Use this port range for Nmap scan instead of
                                 the default
  --tls-port INTEGER             Use this port for TLS queries. Default: 443
  --no-health-check              Do not test for target host availability
  -fr, --follow-redirects        Follow redirects when fuzzing. Default: True
  --no-url-fuzzing               Do not fuzz URLs
  --no-sub-enum                  Do not bruteforce subdomains
  -q, --quiet                    Do not output to stdout
  -o, --outdir TEXT              Directory destination for scan output
  --help                         Show this message and exit.
```

### Screenshots
![poc](/screenshots/poc.png)
![poc2](/screenshots/poc2.png)
### Contributing
Any contributions, issues, features and tips are welcome.