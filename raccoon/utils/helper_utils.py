from subprocess import PIPE, check_call, CalledProcessError
import requests


class HelperUtilities:

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
    def extract_hosts_from_cidr(cls):
        pass

    @classmethod
    def extract_hosts_from_range(cls):
        pass
