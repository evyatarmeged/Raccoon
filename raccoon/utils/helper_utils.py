import os
import requests
from collections import Counter
from subprocess import PIPE, check_call, CalledProcessError
from raccoon.utils.exceptions import RaccoonException


class HelperUtilities:

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
    def validate_port_range(cls, port_range):
        """Validate port range for Nmap scan"""
        ports = port_range.split("-")
        if all(ports) and int(ports[-1]) <= 65535:
            return True
        raise RaccoonException("Invalid port range supplied: {}".format(port_range))

    @classmethod
    def validate_proxy_arguments(cls, *args):
        """No more than 1 of the following can be specified: tor_routing, proxy, proxy_list"""
        if Counter((not arg for arg in (*args,))).get(False) > 1:
            raise RaccoonException("Must specify only one of the following:\n"
                                   "--tor-routing, --proxy-list, --proxy")
        else:
            if tor_routing:
                print("Routing traffic using TOR service")
            elif proxy_list:
                if proxy_list and not os.path.isfile(proxy_list):
                    raise FileNotFoundError("Not a valid file path, {}".format(proxy_list))
                else:
                    print("Routing traffic using proxies from list {}".format(proxy_list))
            elif proxy:
                print("Routing traffic through proxy {}".format(proxy))

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
