import os
import distutils.spawn
import requests
from collections import Counter
from subprocess import PIPE, check_call, CalledProcessError
from requests.exceptions import ConnectionError
from raccoon.utils.exceptions import RaccoonException, ScannerException


class HelpUtilities:

    PATH = ""

    @classmethod
    def validate_target_is_up(cls, host):
        cmd = "ping -c 1 {}".format(host)
        try:
            check_call(cmd.split(), stdout=PIPE, stderr=PIPE)
            return
        except CalledProcessError:
            # Maybe ICMP is blocked. Try web server
            try:
                if "http" not in host:
                    host = "http://" + host
                requests.get(host, timeout=10)
                return
            except ConnectionError:
                raise RaccoonException("Target {} seems to be down.\n"
                                       "Run with --no-health-check to ignore hosts considered as down.".format(host))

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
        if not (HelpUtilities.find_nmap_executable() and HelpUtilities.find_openssl_executable()):
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
    def extract_hosts_from_cidr(cls):
        pass

    @classmethod
    def extract_hosts_from_range(cls):
        pass
