from fake_useragent import UserAgent
import requests


SERVER = "Server"


class WAFApplicationMethods:

    @staticmethod
    def detect_cloudfront(headers):
        service = "CloudFront"
        waf_headers = ("Via", "X-cache")
        if any(h in headers.keys() for h in waf_headers) and any(service.lower() in val for val in headers.values()):
            return "CloudFront"

        if headers.get(SERVER) == service:
            return "CloudFront"
        return

    @staticmethod
    def detect_incapsula(headers):
        if "X-Iinfo" in headers.keys() or headers.get("X-CDN") == "Incapsula":
            return "Incapsula"
        return

    @staticmethod
    def detect_distil( headers):
        if headers.get("x-distil-cs"):
            return "Distil Networks"
        return

    @staticmethod
    def detect_cloudflare(headers):
        if "CF-RAY" in headers.keys() or headers.get(SERVER) == "cloudflare":
            return "Cloudflare"
        return

    @staticmethod
    def detect_edgecast(headers):
        if SERVER in headers.keys() and "ECD" in headers[SERVER]:
            return "Edgecast"
        return

    @staticmethod
    def detect_maxcdn(headers):
        if SERVER in headers.keys() and "NetDNA-cache" in headers[SERVER]:
            return "MaxCDN"
        return


class WAF:

    WAF_CNAME_MAP = {
        "incapdns": "Incapsula",
        "edgekey": "Akamai",
        "distil": "Distil Networks",
        "cloudfront": "CloudFront",
        "adn": "EdgeCast",
        "netdna-cdn": "MaxCDN"
    }

    def __init__(self, host, dns_records):
        self.host = host
        self.cnames = dns_records.get('CNAME')
        self.ua = UserAgent()

    @staticmethod
    def waf_detected(name):
        print("Detected {} WAF presence in web application".format(name))

    def detect(self):
        if self.cnames:
            self._detect_by_cname()
        self._detect_by_application(self.ua.random)

    def _detect_by_cname(self):
        for waf in self.WAF_CNAME_MAP:
            if any(waf in cname for cname in self.cnames):
                print("Detected WAF presence in CNAME: {}".format(self.WAF_CNAME_MAP.get(waf)))

    def _detect_by_application(self, ua):
        # TODO: Add HTTP status code sanitation
        response = requests.head('http://{}'.format(self.host), headers={'User-Agent': ua}, allow_redirects=True)
        for method in WAFApplicationMethods.__dict__:
            if callable(getattr(WAFApplicationMethods, method)):
                result = getattr(WAFApplicationMethods, method)(response.headers)
                if result:
                    self.waf_detected(result)
