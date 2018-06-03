from ipaddress import ip_address
from dns_handler import DNSHandler
from exceptions import HostHandlerException


class Host:
    # TODO: Should set domain/IP, port, protocol. Also - FQDN, naked domain, sub-domain if possible.
    """
    Host parsing, IP to host resolution (and vice verse), etc
    """
    def __init__(self, host):
        self.host = host.strip()
        self.port = 80
        self.protocol = "http"
        self.is_ip = False
        self.full = None
        self.naked = None
        self._parse_host()

    def validate_ip(self, addr=None):
        if not addr:
            addr = self.host
        try:
            ip_address(addr.strip())
            return True
        except ValueError:
            return

    def _extract_port(self, addr):
        if ":" in addr:
            try:
                self.host, self.port = addr.split(":")
                print("Port detected: {}".format(self.port))
            except IndexError:
                return
        return

    def _is_subdomain(self, domain=None):
        """
        Naked domains shouldn't have CNAME records according to RFC
        Some hacky DNS providers allow this, but that's super rare
        """
        if not domain:
            domain = self.host
        try:
            result = DNSHandler.query_dns([domain], ["CNAME"])
            if result.get("CNAME"):
                return True
        except TypeError:
            pass
        return

    def _is_proto(self, domain=None):
        if not domain:
            domain = self.host
        if "://" in domain and not any(domain.startswith(proto) for proto in ("https", "http")):
            raise HostHandlerException("Unknown or unsupported protocol: {}".format(self.host.split("://")[0]))

    def _parse_host(self):
        """
        Try to extract domain (full, naked, sub-domain), IP and port.
        """
        if self._is_proto(self.host):
            try:
                self.protocol, self.host = self.host.split("://")
                print("Protocol detected: {}".format(self.protocol))
            except ValueError:
                raise HostHandlerException("Could not make domain and protocol from host")

        if ":" in self.host:
            self._extract_port(self.host)
        if self.validate_ip(self.host):
            print("Found {} to be an IP address.".format(self.host))
            self.is_ip = True
            return
        if self.host.startswith("www"):
            # Extract naked from full and assign
            try:
                self.naked = self.host.split("www.")[1]
                self.full = self.host
            except IndexError:
                # Got sub-domain
                print("Detected {} as a sub-domain".format(self.host))
        else:
            # If we have a sub-domain, naked and full relations are irrelevant
            if not self._is_subdomain(self.host):
                self.full = "www.{}".format(self.host)
                self.naked = self.host
            else:
                print("Detected {} as a sub-domain".format(self.host))