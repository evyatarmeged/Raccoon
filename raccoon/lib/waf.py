from requests.exceptions import TooManyRedirects, ConnectionError
from raccoon.utils.exceptions import WAFException
from raccoon.utils.request_handler import RequestHandler
from raccoon.utils.helper_utils import HelperUtilities
from raccoon.utils.logger import Logger


SERVER = "Server"


class WAFApplicationMethods:

    @classmethod
    def detect_cloudfront(cls, headers):
        service = "CloudFront"
        waf_headers = ("Via", "X-cache")
        if any(h in headers.keys() for h in waf_headers) and any(service.lower() in val for val in headers.values()):
            return True
        if headers.get(SERVER) == service:
            return True
        return

    @classmethod
    def detect_incapsula(cls, headers):
        if "X-Iinfo" in headers.keys() or headers.get("X-CDN") == "Incapsula":
            return True
        return

    @classmethod
    def detect_distil(cls, headers):
        if headers.get("x-distil-cs"):
            return True
        return

    @classmethod
    def detect_cloudflare(cls, headers):
        if "CF-RAY" in headers.keys() or headers.get(SERVER) == "cloudflare":
            return True
        return

    @classmethod
    def detect_edgecast(cls, headers):
        if SERVER in headers.keys() and "ECD" in headers[SERVER]:
            return True
        return

    @classmethod
    def detect_maxcdn(cls, headers):
        if SERVER in headers.keys() and "NetDNA-cache" in headers[SERVER]:
            return True
        return


class WAF:

    def __init__(self, host):
        self.host = host
        self.cnames = host.dns_results.get('CNAME')
        self.request_handler = RequestHandler()
        self.waf_cname_map = {
            "incapdns": "Incapsula",
            "edgekey": "Akamai",
            "akamai": "Akamai",
            "edgesuite": "Akamai",
            "distil": "Distil Networks",
            "cloudfront": "CloudFront",
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
        log_file = HelperUtilities.get_output_path("{}/WAF.txt".format(self.host.target))
        self.logger = Logger(log_file)

    def _waf_detected(self, name):
        self.logger.info("Detected {} WAF presence in web application".format(name))

    async def detect(self):
        self.logger.info("Trying to detect WAF presence on {}".format(self.host))
        if self.cnames:
            self._detect_by_cname()
        self._detect_by_application()

    def _detect_by_cname(self):
        for waf in self.waf_cname_map:
            if any(waf in str(cname) for cname in self.cnames):
                self.logger.info(
                    "Detected WAF presence in CNAME: {}".format(self.waf_cname_map.get(waf))
                )

    def _detect_by_application(self):
        try:
            response = self.request_handler.send(
                "HEAD",
                timeout=20,
                url="{}://{}:{}".format(
                    self.host.protocol,
                    self.host.target,
                    self.host.port
                )
            )
            for waf, method in self.waf_app_method_map.items():
                result = method(response.headers)
                if result:
                    self._waf_detected(waf)

        except (ConnectionError, TooManyRedirects) as e:
            raise WAFException("Couldn't get response from server.\n"
                               "Caused due to exception: {}".format(str(e)))
