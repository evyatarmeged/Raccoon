import os
import asyncio
import threading
import click
import time
from raccoon.utils.coloring import COLOR
from raccoon.utils.exceptions import RaccoonException
from raccoon.utils.request_handler import RequestHandler
from raccoon.utils.logger import SystemOutLogger
from raccoon.utils.helper_utils import HelperUtilities
from raccoon.lib.fuzzer import URLFuzzer
from raccoon.lib.host import Host
from raccoon.lib.scanner import Scanner, NmapScan
from raccoon.lib.sub_domain import SubDomainEnumerator
from raccoon.lib.dns_handler import DNSHandler
from raccoon.lib.waf import WAF
from raccoon.lib.tls import TLSHandler
from raccoon.lib.web_app import WebApplicationScanner


def intro(logger):
    logger.info("""{}
      _____                _____    _____    ____     ____    _   _ 
     |  __ \      /\      / ____|  / ____|  / __ \   / __ \  | \ | |
     | |__) |    /  \    | |      | |      | |  | | | |  | | |  \| |
     |  _  /    / /\ \   | |      | |      | |  | | | |  | | | . ` |
     | | \ \   / ____ \  | |____  | |____  | |__| | | |__| | | |\  |
     |_|  \_\ /_/    \_\  \_____|  \_____|  \____/   \____/  |_| \_|

    {} By Evyatar Meged\n
    """.format(COLOR.BLUE, COLOR.RESET))


@click.command()
@click.option("-t", "--target", help="Target to scan")
@click.option("-dr", "--dns-records", default="A,MX,NS,CNAME,SOA",
              help="DNS Records to query. Defaults to: A, MX, NS, CNAME, SOA")
@click.option("--tor-routing", is_flag=True, help="Route HTTP traffic through TOR.\n"
                                                  "Slows total runtime significantly")
@click.option("--proxy-list", help="Path to proxy list file that would be used for routing HTTP traffic\n"
                                   "Slows total runtime")
@click.option("--proxy", help="Proxy address to route HTTP traffic through\n"
                              "Slows total runtime")
@click.option("-w", "--wordlist", default="./raccoon/wordlists/fuzzlist",
              help="Path to wordlist that would be used for URL fuzzing")
@click.option("-T", "--threads", default=25, help="Number of threads to use. Default: 25")
@click.option("--ignored-response-codes", default="301,400,401,402,404,504",
              help="Comma separated list of HTTP status code to ignore for fuzzing.\n"
                   "Defaults to: 301,400,401,402,404,504")
@click.option("--subdomain-list", default="./raccoon/wordlists/subdomains",
              help="Path to subdomain list file that would be used for enumeration")
@click.option("-f", "--full-scan", is_flag=True, help="Run Nmap scan with both -sV and -sC")
@click.option("-S", "--scripts", is_flag=True, help="Run Nmap scan with -sC flag")
@click.option("-s", "--services", is_flag=True, help="Run Nmap scan with -sV flag")
@click.option("-pr", "--port-range", help="Use this port range for Nmap scan instead of the default")
@click.option("--tls-port", default=443, help="Use this port for TLS queries. Default: 443")
@click.option("--no-health-check", is_flag=True, help="Do not test for target host availability")
# @click.option("-d", "--delay", default="0.25-1",
#               help="Min and Max number of seconds of delay to be waited between requests\n"
#                    "Defaults to Min: 0.25, Max: 1. Specified in the format of Min-Max")
@click.option("-q", "--quiet", is_flag=True, help="Do not output to stdout")
@click.option("-v", "--verbose", is_flag=True, help="Increase stdout output verbosity")
@click.option("-o", "--outdir", default="Raccoon_scan_results",
              help="Directory destination for scan output")
def main(target,
         tor_routing,
         proxy_list,
         proxy,
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
         # delay,
         outdir,
         quiet,
         verbose):

    # Arg validation

    # Set logging level and Logger instance
    log_level = HelperUtilities.validate_verbosity_args(verbose, quiet)
    logger = SystemOutLogger(log_level)

    if proxy_list and not os.path.isfile(proxy_list):
        raise FileNotFoundError("Not a valid file path, {}".format(proxy_list))

    if wordlist and not os.path.isfile(wordlist):
        raise FileNotFoundError("Not a valid file path, {}".format(wordlist))

    if subdomain_list and not os.path.isfile(subdomain_list):
        raise FileNotFoundError("Not a valid file path, {}".format(wordlist))

    HelperUtilities.create_output_directory(outdir)

    HelperUtilities.validate_proxy_args(tor_routing, proxy, proxy_list)

    if tor_routing:
        logger.info("Routing traffic using TOR service")
    elif proxy_list:
        if proxy_list and not os.path.isfile(proxy_list):
            raise FileNotFoundError("Not a valid file path, {}".format(proxy_list))
        else:
            logger.info("Routing traffic using proxies from list {}".format(proxy_list))
    elif proxy:
        logger.info("Routing traffic through proxy {}".format(proxy))

    # TODO: Sanitize delay argument

    dns_records = tuple(dns_records.split(","))

    ignored_response_codes = tuple(int(code) for code in ignored_response_codes.split(","))

    if port_range:
        HelperUtilities.validate_port_range(port_range)

    # /Arg validation

    # Set Request Handler instance
    request_handler = RequestHandler(proxy_list=proxy_list, tor_routing=tor_routing, single_proxy=proxy)

    intro(logger)

    if not no_health_check:
        HelperUtilities.validate_target_is_up(target)

    main_loop = asyncio.get_event_loop()

    # TODO: Populate array when multiple targets are supported
    # hosts = []
    host = Host(target=target, dns_records=dns_records)

    logger.info("Setting Nmap scan to run in the background")
    nmap_scan = NmapScan(host, full_scan, scripts, services, port_range)
    # TODO: Populate array when multiple targets are supported
    # nmap_threads = []
    nmap_thread = threading.Thread(target=Scanner.run, args=(nmap_scan, ))
    # Run Nmap scan in the background. Can take some time
    nmap_thread.start()

    # Run first set of checks - TLS, Web/WAF Data, WHOIS
    waf = WAF(host)
    tls_info_scanner = TLSHandler(host, tls_port)
    web_app_scanner = WebApplicationScanner(host)
    tasks = (
        asyncio.ensure_future(tls_info_scanner.run()),
        asyncio.ensure_future(waf.detect()),
        asyncio.ensure_future(DNSHandler.grab_whois(host)),
        asyncio.ensure_future(web_app_scanner.run_scan())
    )
    main_loop.run_until_complete(asyncio.wait(tasks))

    # Second set of checks - URL fuzzing, Subdomain enumeration
    sans = tls_info_scanner.sni_data.get("SANs")
    fuzzer = URLFuzzer(host, ignored_response_codes, threads, wordlist)
    main_loop.run_until_complete(fuzzer.fuzz_all())
    if not host.is_ip:
        subdomain_enumerator = SubDomainEnumerator(
            host,
            domain_list=subdomain_list,
            sans=sans,
            ignored_response_codes=ignored_response_codes,
            num_threads=threads
        )
        main_loop.run_until_complete(subdomain_enumerator.run())

    if nmap_thread.is_alive():
        logger.info("All scans done. Waiting for Nmap scan to wrap up.\n"
                    "This may vary depending on parameters and port range")

        while nmap_thread.is_alive():
            time.sleep(15)

    logger.info("\nRaccoon scan finished\n")

# TODO: Change relative paths in default wordlist/subdomain list/etc

main()
