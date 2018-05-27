from ipaddress import ip_address
from dns import reversename, resolver
from .dns_handler import DNSHandler


class HostHandlerException(Exception):
    """Host base exception class"""
    def __init__(self, message='Host Handler Exception'):
        self._message = message

    def __str__(self):
        return self._message


class Host:
    """
    Host parsing, IP to host resolution (and vice verse), etc
    """
    def __init__(self, host):
        self.host = host.strip()
        self.naked = None
        self.full = None
        self._parse_host()

    @staticmethod
    def _is_ip(ip):
        try:
            ip_address(ip.strip())
            return True
        except ValueError:
            return

    @staticmethod
    def _is_subdomain(domain):
        """
        Naked domains shouldn't have CNAME records according to RFC
        Some hacky DNS providers allow this, but that's super rare
        """
        try:
            result = DNSHandler.query_dns(domain, tuple("CNAME"))
            if result.get("CNAME"):
                return True
        except TypeError:
            pass
        return

    @staticmethod
    def _is_proto(domain):
        if any(proto in domain for proto in ("https", "http")):
            return True

    def _parse_host(self):
        """
        Try to extract host from IP, and parse domain for FQDN, naked domain or sub-domain.
        Many IPs don't have reverse lookup zones associated, so PTRs might fail more often than not
        """

        if self._is_ip(self.host):
            try:
                rev_name = reversename.from_address(self.host)
                self.host = str(resolver.query(rev_name, "PTR")[0])
                self._parse_host()
            except resolver.NoNameservers:
                raise HostHandlerException("Could not resolve host from IP. Will not query DNS")

        if self._is_proto(self.host):
            self.host = self.host[self.host.index("://") + 3:]

        # Feels like this part needs tweaking due to sub-domains that have www
        if "www" in self.host:
            # Extract naked from full and assign
            self.naked = self.host.split('www.')[1]
            self.full = self.host
        else:
            if not self._is_subdomain(self.host):
                self.full = "www.{}".format(self.host)
                self.naked = self.host
