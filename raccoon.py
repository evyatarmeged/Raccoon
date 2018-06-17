import click
from subprocess import PIPE, check_call, CalledProcessError
import requests
from requests.exceptions import ConnectionError
from raccoon.utils import coloring
from raccoon.utils.exceptions import RaccoonBaseException
from raccoon.lib.fuzzer import URLFuzzer
from raccoon.lib.host import Host
from raccoon.lib.scanner import Scanner
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


def validate_target_is_up(host):
    cmd = "ping -c 1 {}".format(host)
    try:
        check_call(cmd.split(), stdout=PIPE, stderr=PIPE)
        return
    except CalledProcessError:
        # Maybe ICMP is blocked. Try web server
        try:
            if "http" not in host:
                host = "http://"+host
            requests.get(host)
            return
        except ConnectionError:
            raise RaccoonBaseException("Target does not seem to be up.\n"
                                       "Run with --no-health-check to ignore hosts considered as down.")


@click.command()
@click.option("-t", "--target", help="Target to scan")
@click.option("--tor-routing", is_flag=True, help="Route traffic through TOR")
@click.option("--proxy-list", help="Path to proxy list file that would be used for routing")
@click.option("-w", "--wordlist", help="Path to wordlist that would be used for URL fuzzing")
@click.option("-T", "--threads", help="Number of threads to use. Default: 25")
@click.option("--ignore-error-codes", help="Comma separated list of HTTP status code to ignore for fuzzing")
@click.option("--subdomain-list", help="Path to subdomain list file that would be used for enumeration")
@click.option("-F", "--full-scan", is_flag=True, help="Run Nmap scan both scripts and services scans")
@click.option("-S", "--scripts", is_flag=True, help="Run Nmap scan with scripts scan")
@click.option("-s", "--services", is_flag=True, help="Run Nmap scan with services scan")
@click.option("-pr", "--port-range", help="Use this port range for Nmap scan instead of the default")
@click.option("--tls-port", help="Use this port for TLS queries. Default: 443")
@click.option("--no-health-check", is_flag=True, help="Do not test for target host availability")
@click.option("-q", "--quiet", is_flag=True, help="Do not output to stdout")
def main(target,
         tor_routing=False,
         proxy_list=None,
         wordlist=None,
         threads=25,
         ignore_error_codes=(),
         subdomain_list=None,
         full_scan=False,
         scripts=False,
         services=False,
         port_range=None,
         tls_port=443,
         no_health_check=False,
         quiet=False):

    # TODO: Validate params (file paths, error codes are comma-sep, port-range is legit)

    if not no_health_check:
        validate_target_is_up(target)

    host = Host(target=target)



main()

# tasks = [
#     asyncio.ensure_future()),
#     asyncio.ensure_future(),
# ]
# run_until_complete(asyncio.wait(tasks))