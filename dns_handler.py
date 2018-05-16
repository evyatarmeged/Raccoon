from dns import resolver, reversename
from ipaddress import ip_address
from pprint import pprint


class DNSHandlerException(Exception):
    """DNSHandler base exception class"""
    def __init__(self, message='DNS Handler Exception'):
        self._message = message

    def __str__(self):
        return self._message


# noinspection PyUnboundLocalVariable
class DNSHandler(resolver.Resolver):
    """Handles DNS queries and lookups"""
    def __init__(self, host):
        super().__init__()
        self.host = host.strip()

    @staticmethod
    def _is_ip(ip):
        try:
            ip_address(ip.strip())
            return True
        except ValueError:
            return

    def _parse_host(self):
        """
        Try to extract host from IP, or parse domain for FQDN and naked domain.
        Many IPs don't have reverse lookup zones associated, so PTRs might fail more often than not
        """
        host = self.host
        naked_and_full = []

        if self._is_ip(self.host):
            try:
                rev_name = reversename.from_address(self.host)
                self.host = str(resolver.query(rev_name, "PTR")[0])
                self.query_dns()
            except resolver.NoNameservers:
                raise DNSHandlerException("Could not resolve host from IP. Will not query DNS")

        elif any(proto in host for proto in ("https", "http")):
            # Grab URL without protocol
            host = self.host[self.host.index("://") + 3:]

        if "www" in host:
            naked_and_full.append(host.split('www.')[1])
        else:
            naked_and_full.append("www.{}".format(host))

        naked_and_full.append(host) if len(naked_and_full) == 1 else None
        return naked_and_full

    def query_dns(self):
        records = ("A", "MX", "NS", "CNAME", "SOA")
        results = {k: set() for k in records}
        domains = self._parse_host()
        for record in records:
            for domain in domains:
                try:
                    answers = self.query(domain, record)
                    for answer in answers:
                        # Add value to record type
                        results.get(record).add(answer)
                except resolver.NoAnswer:
                    pass
        return {k: None if not v else v for k, v in results.items()}

    def detect_waf(self, cnames):
        """Detects WAF protection by CNAME"""
        pass
