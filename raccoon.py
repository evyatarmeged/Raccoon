import os
import asyncio
import threading
from subprocess import PIPE, check_call, CalledProcessError
import requests
import click
from requests.exceptions import ConnectionError
from raccoon.utils.coloring import COLOR
from raccoon.utils.exceptions import RaccoonException
from raccoon.utils.request_handler import RequestHandler
from raccoon.utils.helper_utils import HelperUtilities
from raccoon.lib.fuzzer import URLFuzzer
from raccoon.lib.host import Host
from raccoon.lib.scanner import Scanner, NmapScan
from raccoon.lib.sub_domain import SubDomainEnumerator
from raccoon.lib.waf import WAF
from raccoon.lib.tls import TLSInfoScanner


# TODO: Change all prints to a logger debug/info/warning call for EASY verbosity control

def intro():
    print("""{}
      _____                _____    _____    ____     ____    _   _ 
     |  __ \      /\      / ____|  / ____|  / __ \   / __ \  | \ | |
     | |__) |    /  \    | |      | |      | |  | | | |  | | |  \| |
     |  _  /    / /\ \   | |      | |      | |  | | | |  | | | . ` |
     | | \ \   / ____ \  | |____  | |____  | |__| | | |__| | | |\  |
     |_|  \_\ /_/    \_\  \_____|  \_____|  \____/   \____/  |_| \_|

    {}
    """.format(COLOR.BLUE, COLOR.RESET))


def create_event_loop_tasks(funcs):
    return [asyncio.ensure_future(f()) for f in funcs]


@click.command()
@click.option("-t", "--target", help="Target to scan")
@click.option("-dr", "--dns-records", default="A,MX,NS,CNAME,SOA",
              help="DNS Records to query. Defaults to: A, MX, NS, CNAME, SOA")
@click.option("--tor-routing", is_flag=True, help="Route traffic through TOR")
@click.option("--proxy-list", help="Path to proxy list file that would be used for routing")
@click.option("-w", "--wordlist", default="./raccoon/wordlists/fuzzlist",
              help="Path to wordlist that would be used for URL fuzzing")
@click.option("-T", "--threads", default=25, help="Number of threads to use. Default: 25")
@click.option("--ignored-response-codes", default="400,401,402,404,504",
              help="Comma separated list of HTTP status code to ignore for fuzzing.\n"
                   "Defaults to: 400,401,402,404,504")
@click.option("--subdomain-list", default="./raccoon/wordlists/subdomains",
              help="Path to subdomain list file that would be used for enumeration")
@click.option("-f", "--full-scan", is_flag=True, help="Run Nmap scan both scripts and services scans")
@click.option("-S", "--scripts", is_flag=True, help="Run Nmap scan with scripts scan")
@click.option("-s", "--services", is_flag=True, help="Run Nmap scan with services scan")
@click.option("-pr", "--port-range", help="Use this port range for Nmap scan instead of the default")
@click.option("--tls-port", default=443, help="Use this port for TLS queries. Default: 443")
@click.option("--no-health-check", is_flag=True, help="Do not test for target host availability")
@click.option("-q", "--quiet", is_flag=True, help="Do not output to stdout")
def main(target,
         tor_routing,
         proxy_list,
         dns_records,
         wordlist,
         threads,
         ignored_response_codes,
         subdomain_list,
         full_scan,
         scripts,
         services,
         port_range,
         tls_port,
         no_health_check,
         quiet):

    # Arg validation
    if proxy_list and not os.path.isfile(proxy_list):
        raise FileNotFoundError("Not a valid file path, {}".format(proxy_list))

    if wordlist and not os.path.isfile(wordlist):
        raise FileNotFoundError("Not a valid file path, {}".format(wordlist))

    if subdomain_list and not os.path.isfile(subdomain_list):
        raise FileNotFoundError("Not a valid file path, {}".format(wordlist))

    dns_records = tuple(dns_records.split(","))

    ignored_response_codes = tuple(int(code) for code in ignored_response_codes.split(","))

    if port_range:
        HelperUtilities.validate_port_range(port_range)

    # /Arg validation

    intro()

    # Set Request Handler instance
    request_handler = RequestHandler(proxy_list=proxy_list, tor_routing=tor_routing)

    if not no_health_check:
        HelperUtilities.validate_target_is_up(target)

    main_loop = asyncio.get_event_loop()

    host = Host(target=target, dns_records=dns_records)

    # TODO: Populate array when multiple targets are supported
    # nmap_threads = []

    print("Setting Nmap scans to run in the background")
    nmap_scan = NmapScan(host, full_scan, scripts, services, port_range)
    nmap_thread = threading.Thread(target=Scanner.run, args=(nmap_scan, ))
    # Run Nmap scan in the background. Can take some time
    nmap_thread.start()

    # Run first set of checks - TLS, web application data, WHOIS
    waf = WAF(host)
    tls_info_scanner = TLSInfoScanner(host, tls_port)
    tasks = create_event_loop_tasks((waf.detect, tls_info_scanner.run))
    main_loop.run_until_complete(asyncio.wait(tasks))

    # Second set of checks - URL fuzzing, Subdomain enumeration
    sans = tls_info_scanner.sni_data.get("SANs")
    fuzzer = URLFuzzer(host, ignored_response_codes, threads, wordlist)
    main_loop.run_until_complete(fuzzer.fuzz_all())

    if not host.is_ip:
        subdomain_enumerator = SubDomainEnumerator(
            host,
            domain_list=subdomain_list,
            sans=None,
            ignored_response_codes=ignored_response_codes,
            num_threads=threads
        )
        main_loop.run_until_complete(subdomain_enumerator.run())


# TODO: Change relative paths in default wordlist/subdomain list/etc


main()
