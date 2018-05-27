import aiohttp


class URLFuzzer:
    # TODO: In General, Async/Threaded ?

    def __init__(self, host):
        self.host = host

    def find_subdomains(self, sans):
        """Extracts all sub-domains for TLSVersionChecker SAN list"""

