import os
import struct
import socket
import distutils.spawn
from platform import system
from collections import Counter
from subprocess import PIPE, check_call, CalledProcessError
from requests.exceptions import ConnectionError
from raccoon_src.utils.exceptions import RaccoonException, ScannerException, RequestHandlerException
from raccoon_src.utils.request_handler import RequestHandler


class HelpUtilities:

    PATH = ""
    
    @staticmethod
    def ip_to_int(ip_address):
        """

        >>> HelpUtilities.ip_to_int("192.168.0.0")
        3232235520L
        >>> HelpUtilities.ip_to_int("192.168.255.255")
        3232301055L

        :param ip_address: a quad dotted ip address
        :return: an integer (long) representation of that ip address's bits
        """
        return struct.unpack('!I', socket.inet_aton(ip_address))[0]

    @staticmethod
    def int_to_ip(int_value):
        """

        >>> HelpUtilities.int_to_ip(3232235520)
        '192.168.0.0'
        >>> HelpUtilities.int_to_ip(3232301055)
        '192.168.255.255'

        :param int_value: an integer
        :return: string quad dotted ip address
        """

        return socket.inet_ntoa(struct.pack('!I', int_value))

    @staticmethod
    def iter_ip_range(start_address,end_address):
        """

        :param start_address:
        :param end_address:
        :return:
        """
        for i in range(HelpUtilities.ip_to_int(start_address),HelpUtilities.ip_to_int(end_address)+1):
            yield HelpUtilities.int_to_ip(i)

    @staticmethod
    def count_ips_in_range(start_address,end_address):
        """
        >>> HelpUtilities.count_ips_in_range('192.168.1.10','192.168.255.10')
        65024L


        :param start_address: a quad dotted ip address string
        :param end_address: a quad dotted ip address string
        :return:
        """
        return HelpUtilities.ip_to_int(end_address)-HelpUtilities.ip_to_int(start_address)

    @staticmethod
    def iter_ip_blocks(start_address,end_address,num_blocks):
        """
        an iterator that divides an ip_range into num_blocks, it yields tuples of (block_start_address,block_end_address)
        suitable for generating values to pass off to threads or multiprocessing

        >>> list(HelpUtilities.iter_ip_blocks("192.168.0.1","192.168.255.255",3)) # three cores??? o.O
        [('192.168.0.1', '192.168.85.85'), ('192.168.85.86', '192.168.170.170'), ('192.168.170.171', '192.168.255.255')]

        >>> list(HelpUtilities.iter_ip_blocks('192.168.0.1', '192.168.85.86',80))# 80 cores?        # doctest: +ELLIPSIS
        [('192.168.0.1', '192.168.1.18'), ('192.168.1.19', '192.168.2.36'), ('192.168.2.37', '192.168.3.54'),...

        :param start_address:  the first address to scan
        :param end_address: the last address to scan
        :param num_blocks: the number of blocks to subdivide into
        :return:  tuple of (block_start_address,block_end_address)
        """
        ttl_address_count = HelpUtilities.count_ips_in_range(start_address,end_address)
        addresses_per_block = ttl_address_count//num_blocks + 1
        start_address_int =HelpUtilities.ip_to_int(start_address)
        end_address_int =HelpUtilities.ip_to_int(end_address)
        for i in range(start_address_int,end_address_int,addresses_per_block):
            yield (HelpUtilities.int_to_ip(i),HelpUtilities.int_to_ip(i+addresses_per_block-1))
            
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
    def find_mac_gtimeout_executable(cls):
        """To add macOS support, the coreutils package needs to be installed using homebrew"""
        return distutils.spawn.find_executable("gtimeout")

    @classmethod
    def validate_executables(cls):
        if not (cls.find_nmap_executable() and cls.find_openssl_executable()):
            raise RaccoonException("Could not find Nmap or OpenSSL "
                                   "installed. Please install them and run Raccoon again.")
        if system() == "Darwin":
            if not cls.find_mac_gtimeout_executable():
                raise RaccoonException("To support Raccoon with macOS 'gtimeout' must be installed.\n"
                                       "gtimeout can be installed by running 'brew install coreutils'")
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
