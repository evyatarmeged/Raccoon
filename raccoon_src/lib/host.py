import os
from ipaddress import ip_address
from dns.exception import Timeout
from raccoon_src.lib.dns_handler import DNSHandler
from raccoon_src.utils.exceptions import HostHandlerException
from raccoon_src.utils.help_utils import HelpUtilities
from raccoon_src.utils.coloring import COLOR, COLORED_COMBOS
from raccoon_src.utils.logger import Logger, SystemOutLogger


class Host:
    """
    Host parsing, IP to host resolution (and vice verse), etc
    Sets domain/IP, port, protocol. also tries to parse FQDN, naked domain, if possible.
    """
    def __init__(self, target, dns_records):
        self.target = target.strip()
        self.dns_records = dns_records
        self.port = 80
        self.protocol = "http"
        self.is_ip = False
        self.fqdn = None
        self.naked = None
        self.dns_results = {}
        self.logger = SystemOutLogger()

    def __str__(self):
        return self.target

    def __repr__(self):
        return self.__dict__

    @staticmethod
    def _create_host_dir(path):
        try:
            os.makedirs("/".join(path.split("/")[:-1]), exist_ok=True)
        except FileExistsError:
            pass

    def validate_ip(self, addr=None):
        if not addr:
            addr = self.target
        try:
            ip_address(addr.strip())
            return True
        except ValueError:
            return

    def _extract_port(self, addr):
        try:
            self.target, self.port = addr.split(":")
            try:
                self.port = int(self.port)
            except ValueError:
                # Probably has a path after the port, e.g - localhost:3000/home.asp
                raise HostHandlerException("Failed to parse port {}. Is there a path after it ?".format(
                    self.port
                ))
            self.logger.info("{} Port detected: {}".format(COLORED_COMBOS.NOTIFY, self.port))
        except IndexError:
            self.logger.info("{} Did not detect port. Using default port 80".format(COLORED_COMBOS.NOTIFY))
            return
        return

    def _is_proto(self, domain=None):
        if not domain:
            domain = self.target
        if "://" in domain:
            if any(domain.startswith(proto) for proto in ("https", "http")):
                return True
            else:
                raise HostHandlerException("Unknown or unsupported protocol: {}".format(self.target.split("://")[0]))
        return

    def write_up(self):
        self.logger.info("{} Writing DNS query results".format(COLORED_COMBOS.GOOD, self))

        for record in self.dns_results:
            self.logger.debug(record+"\n")
            for value in self.dns_results.get(record):
                self.logger.debug("\t{}".format(value))

    def create_host_dir_and_set_file_logger(self):
        log_file = HelpUtilities.get_output_path("{}/dns_records.txt".format(self.target))
        self._create_host_dir(log_file)
        self.logger = Logger(log_file)

    def parse(self):
        """
        Try to extract domain (full, naked, sub-domain), IP and port.
        """
        if self.target.endswith("/"):
            self.target = self.target[:-1]

        if self._is_proto(self.target):
            try:
                self.protocol, self.target = self.target.split("://")
                self.logger.info("{} Protocol detected: {}".format(COLORED_COMBOS.NOTIFY, self.protocol))
                if self.protocol.lower() == "https" and self.port == 80:
                    self.port = 443
            except ValueError:
                raise HostHandlerException("Could not make domain and protocol from host")

        if ":" in self.target:
            self._extract_port(self.target)

        if self.validate_ip(self.target):
            self.logger.info("{} Detected {} as an IP address.".format(COLORED_COMBOS.NOTIFY, self.target))
            self.is_ip = True
        else:
            domains = []
            if self.target.startswith("www."):
                # Obviously an FQDN
                domains.extend((self.target, self.target.split("www.")[1]))
                self.fqdn = self.target
                self.naked = ".".join(self.fqdn.split('.')[1:])
            else:
                domains.append(self.target)
                domain_levels = self.target.split(".")
                if len(domain_levels) == 2 or (len(domain_levels) == 3 and domain_levels[1] == "co"):
                    self.logger.info("{} Found {} to be a naked domain".format(COLORED_COMBOS.NOTIFY, self.target))
                    self.naked = self.target

            try:
                self.dns_results = DNSHandler.query_dns(domains, self.dns_records)
            except Timeout:
                raise HostHandlerException("DNS Query timed out. Maybe target has DNS protection ?")

            if self.dns_results.get("CNAME"):
                # Naked domains shouldn't hold CNAME records according to RFC regulations
                self.logger.info("{} Found {} to be an FQDN by CNAME presence in DNS records".format(
                    COLORED_COMBOS.NOTIFY, self.target))

                self.fqdn = self.target
                self.naked = ".".join(self.fqdn.split('.')[1:])
        self.create_host_dir_and_set_file_logger()
        self.write_up()
