from fake_useragent import UserAgent
import requests


class WAFApplicationMethods:

    @staticmethod
    def detect_cloudfront(headers):
        service = "cloudfront"
        # TODO: Solve current TypeError
        if service in headers.get('via') or service in headers.get('x-cache')\
                or headers.get("Server") == "CloudFront":
            return True

    @staticmethod
    def detect_incapsula(headers):
        if "x-iinfo" in headers.keys() or headers.get("x-cdn") == "Incapsula":
            return True

    @staticmethod
    def detect_distil( headers):
        if headers.get("x-distil-cs"):
            return True

    @staticmethod
    def detect_cloudflare(headers):
        pass


class WAF:

    WAF_CNAME_MAP = {
        "incapdns": "Incapsula",
        "edgekey": "Akamai",
        "distil": "Distil Networks"
    }

    def __init__(self, host, dns_records):
        self.host = host
        self.cnames = dns_records.get('CNAME')
        self.ua = UserAgent()

    def detect(self):
        self._detect_by_cname()
        self._detect_by_application(self.ua.random)

    def _detect_by_cname(self):
        for waf in self.WAF_CNAME_MAP:
            if any(waf in cname for cname in self.cnames):
                print("Detected WAF presence in CNAME: {}".format(self.WAF_CNAME_MAP.get(waf)))
            else:
                print("No WAF presence detected in CNAME")

    def _detect_by_application(self, ua):
        ua = ua.random
        response = requests.head('http://{}'.format(self.host), headers={'User-Agent': ua})
        for method in WAFApplicationMethods.__dict__:
            if callable(getattr(WAFApplicationMethods, method)):
                print(getattr(WAFApplicationMethods, method)(response.headers))

