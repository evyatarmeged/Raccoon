from ipaddress import ip_address
from dns_handler import DNSHandler
from exceptions import HostHandlerException


class Host:
    """
    Host parsing, IP to host resolution (and vice verse), etc
    Sets domain/IP, port, protocol. Also - FQDN, naked domain, if possible.
    """
    def __init__(self, target):
        self.target = target.strip()
        self.port = 80
        self.protocol = "http"
        self.dns_records = []
        self.is_ip = False
        self.fqdn = None
        self.naked = None
        self._parse_host()

    def validate_ip(self, addr=None):
        if not addr:
            addr = self.target
        try:
            ip_address(addr.strip())
            return True
        except ValueError:
            return

    def _extract_port(self, addr):
        if ":" in addr:
            try:
                self.target, self.port = addr.split(":")
                self.port = int(self.port)
                print("Port detected: {}".format(self.port))
            except IndexError:
                print("Did not detect port. Using default port 80")
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

    def _parse_host(self):
        """
        Try to extract domain (full, naked, sub-domain), IP and port.
        """
        if self.target.endswith("/"):
            self.target = self.target[:-1]

        if self._is_proto(self.target):
            try:
                self.protocol, self.target = self.target.split("://")
                print("Protocol detected: {}".format(self.protocol))
            except ValueError:
                raise HostHandlerException("Could not make domain and protocol from host")

        if ":" in self.target:
            self._extract_port(self.target)

        if self.validate_ip(self.target):
            print("Found {} to be an IP address.".format(self.target))
            self.is_ip = True
            return

        domains = []
        if self.target.startswith("www."):
            # Obviously an FQDN
            domains.extend((self.target, self.target.split("www.")[1]))
            print("Found {} to be an FQDN".format(self.target))
            self.fqdn = self.target
            self.naked = ".".join(self.fqdn.split('.')[1:])
        else:
            # Can't be sure if FQDN or just naked domain
            domains.append(self.target)

        self.dns_records = DNSHandler.query_dns(domains)
        if self.dns_records.get("CNAME"):
            # Naked domains shouldn't hold CNAME records according to RFC regulations
            print("Found {} to be an FQDN".format(self.target))
            self.fqdn = self.target
            self.naked = ".".join(self.fqdn.split('.')[1:])
