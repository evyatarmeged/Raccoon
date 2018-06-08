from fake_useragent import UserAgent
import requests
from requests.exceptions import TooManyRedirects, ConnectionError, ConnectTimeout
from exceptions import WAFException


SERVER = "Server"


class WAFApplicationMethods:

    @staticmethod
    def detect_cloudfront(headers):
        service = "CloudFront"
        waf_headers = ("Via", "X-cache")
        if any(h in headers.keys() for h in waf_headers) and any(service.lower() in val for val in headers.values()):
            return True
        if headers.get(SERVER) == service:
            return True
        return

    @staticmethod
    def detect_incapsula(headers):
        if "X-Iinfo" in headers.keys() or headers.get("X-CDN") == "Incapsula":
            return True
        return

    @staticmethod
    def detect_distil( headers):
        if headers.get("x-distil-cs"):
            return True
        return

    @staticmethod
    def detect_cloudflare(headers):
        if "CF-RAY" in headers.keys() or headers.get(SERVER) == "cloudflare":
            return True
        return

    @staticmethod
    def detect_edgecast(headers):
        if SERVER in headers.keys() and "ECD" in headers[SERVER]:
            return True
        return

    @staticmethod
    def detect_maxcdn(headers):
        if SERVER in headers.keys() and "NetDNA-cache" in headers[SERVER]:
            return True
        return


class WAF:

    def __init__(self, host, dns_records):
        self.host = host
        self.cnames = dns_records.get('CNAME')
        self.ua = UserAgent()
        self.waf_cname_map = {
            "incapdns": "Incapsula",
            "edgekey": "Akamai",
            "distil": "Distil Networks",
            "cloudfront": "CloudFront",
            "adn": "EdgeCast",
            "netdna-cdn": "MaxCDN"
        }
        self.waf_app_method_map = {
            "CloudFront": WAFApplicationMethods.detect_cloudfront,
            "Cloudflare": WAFApplicationMethods.detect_cloudflare,
            "Incapsula": WAFApplicationMethods.detect_incapsula,
            "MaxCDN": WAFApplicationMethods.detect_maxcdn,
            "Edgecast": WAFApplicationMethods.detect_edgecast,
            "Distil Networks": WAFApplicationMethods.detect_distil
        }

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
        try:
            response = requests.head(
                'http://{}'.format(self.host),
                headers={'User-Agent': ua},
                allow_redirects=True
            )
            for waf, method in self.waf_app_method_map.keys():
                result = method(response.headers)
                if result:
                    self.waf_detected(waf)

        except (ConnectTimeout, ConnectionError, TooManyRedirects):
            # TODO: throw normal error for each
            return
