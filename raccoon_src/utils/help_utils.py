import os
import distutils.spawn
from collections import Counter
from subprocess import PIPE, check_call, CalledProcessError
from requests.exceptions import ConnectionError
from raccoon_src.utils.exceptions import RaccoonException, ScannerException, RequestHandlerException
from raccoon_src.utils.request_handler import RequestHandler


class HelpUtilities:

    PATH = ""

    @classmethod
    def validate_target_is_up(cls, host):
        cmd = "ping -c 1 {}".format(host.target)
        try:
            check_call(cmd.split(), stdout=PIPE, stderr=PIPE)
            return
        except CalledProcessError:
            # Maybe ICMP is blocked. Try web server
            try:
                if host.port == 443 or host.port == 80:
                    url = "{}://{}".format(host.protocol, host.target)
                else:
                    url = "{}://{}:{}".format(host.protocol, host.target, host.port)
                rh = RequestHandler()
                rh.send("GET", url=url, timeout=15)
                return
            except (ConnectionError, RequestHandlerException):
                raise RaccoonException("Target {} seems to be down (no response to ping or from a web server"
                                       " at port {}).\nRun with --skip-health-check to ignore hosts"
                                       " considered as down.".format(host, host.port))

    @classmethod
    def parse_cookie_arg(cls, cookie_arg):
        try:
            cookies = {}
            for c in cookie_arg.split(','):
                c = c.split(":")
                cookies[c[0]] = c[1]
            return cookies
        except (IndexError, TypeError):
            raise RaccoonException("Cookie parsing error occurred, probably due to invalid cookie format.\n"
                                   "Cookie format should be comma separated key:value pairs. Use --help "
                                   "for more info.")

    @classmethod
    def validate_wordlist_args(cls, proxy_list, wordlist, subdomain_list):
        if proxy_list and not os.path.isfile(proxy_list):
            raise FileNotFoundError("Not a valid file path, {}".format(proxy_list))

        if wordlist and not os.path.isfile(wordlist):
            raise FileNotFoundError("Not a valid file path, {}".format(wordlist))

        if subdomain_list and not os.path.isfile(subdomain_list):
            raise FileNotFoundError("Not a valid file path, {}".format(wordlist))

    @classmethod
    def validate_port_range(cls, port_range):
        """Validate port range for Nmap scan"""
        ports = port_range.split("-")
        if all(ports) and int(ports[-1]) <= 65535 and not len(ports) != 2:
            return True
        raise ScannerException("Invalid port range {}".format(port_range))

    @classmethod
    def validate_proxy_args(cls, *args):
        """No more than 1 of the following can be specified: tor_routing, proxy, proxy_list"""
        supplied_proxies = Counter((not arg for arg in (*args,))).get(False)
        if not supplied_proxies:
            return
        elif supplied_proxies > 1:
            raise RaccoonException("Must specify only one of the following:\n"
                                   "--tor-routing, --proxy-list, --proxy")

    @classmethod
    def determine_verbosity(cls, quiet):
        if quiet:
            return "CRITICAL"
        else:
            return "INFO"

    @classmethod
    def find_nmap_executable(cls):
        return distutils.spawn.find_executable("nmap")

    @classmethod
    def find_openssl_executable(cls):
        return distutils.spawn.find_executable("openssl")

    @classmethod
    def validate_executables(cls):
        if not (cls.find_nmap_executable() and cls.find_openssl_executable()):
            raise RaccoonException("Could not find Nmap or OpenSSL "
                                   "installed. Please install them and run Raccoon again.")
        return

    @classmethod
    def create_output_directory(cls, outdir):
        """Tries to create base output directory"""
        cls.PATH = outdir
        try:
            os.mkdir(outdir)
        except FileExistsError:
            pass

    @classmethod
    def get_output_path(cls, module_path):
        return "{}/{}".format(cls.PATH, module_path)

    @classmethod
    def confirm_traffic_routs_through_tor(cls):
        rh = RequestHandler()
        try:
            page = rh.send("GET", url="https://check.torproject.org")
            if "Congratulations. This browser is configured to use Tor." in page.text:
                return
            elif "Sorry. You are not using Tor" in page.text:
                raise RaccoonException("Traffic does not seem to be routed through Tor.\nExiting")
        except RequestHandlerException:
            raise RaccoonException("Tor service seems to be down - not able to connect to 127.0.0.1:9050.\nExiting")

    @classmethod
    def query_dns_dumpster(cls, host):
        # Start DNS Dumpster session for the token
        request_handler = RequestHandler()
        dnsdumpster_session = request_handler.get_new_session()
        url = "https://dnsdumpster.com"
        if host.naked:
            target = host.naked
        else:
            target = host.target
        payload = {
            "targetip": target,
            "csrfmiddlewaretoken": None
        }
        try:
            dnsdumpster_session.get(url, timeout=10)
            jar = dnsdumpster_session.cookies
            for c in jar:
                if not c.__dict__.get("name") == "csrftoken":
                    continue
                payload["csrfmiddlewaretoken"] = c.__dict__.get("value")
                break
            dnsdumpster_session.post(url, data=payload, headers={"Referer": "https://dnsdumpster.com/"})

            return dnsdumpster_session.get("https://dnsdumpster.com/static/map/{}.png".format(target))
        except ConnectionError:
            raise RaccoonException

    @classmethod
    def extract_hosts_from_cidr(cls):
        pass

    @classmethod
    def extract_hosts_from_range(cls):
        pass
