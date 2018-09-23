from requests.exceptions import TooManyRedirects, ConnectionError
from raccoon_src.utils.web_server_validator import WebServerValidator
from raccoon_src.utils.exceptions import WAFException, WebServerValidatorException
from raccoon_src.utils.request_handler import RequestHandler
from raccoon_src.utils.coloring import COLOR, COLORED_COMBOS
from raccoon_src.utils.help_utils import HelpUtilities
from raccoon_src.utils.logger import Logger


SERVER = "Server"


class WAFApplicationMethods:

    @classmethod
    def detect_cloudfront(cls, res):
        service = "CloudFront"
        waf_headers = ("Via", "X-cache")
        if any(h in res.headers.keys() for h in waf_headers) and any(service.lower() in val for val in res.headers.values()):
            return True
        if res.headers.get(SERVER) == service:
            return True
        return

    @classmethod
    def detect_incapsula(cls, res):
        if "X-Iinfo" in res.headers.keys() or res.headers.get("X-CDN") == "Incapsula":
            return True
        return

    @classmethod
    def detect_distil(cls, res):
        if res.headers.get("x-distil-cs"):
            return True
        return

    @classmethod
    def detect_cloudflare(cls, res):
        if "CF-RAY" in res.headers.keys() or res.headers.get(SERVER) == "cloudflare":
            return True
        return

    @classmethod
    def detect_edgecast(cls, res):
        if SERVER in res.headers.keys() and "ECD" in res.headers[SERVER]:
            return True
        return

    @classmethod
    def detect_maxcdn(cls, res):
        if SERVER in res.headers.keys() and "NetDNA-cache" in res.headers[SERVER]:
            return True
        return

    @classmethod
    def detect_sucuri(cls, res):
        if any((
                res.headers.get(SERVER) == "Sucuri/Cloudproxy",
                "X-Sucuri-ID" in res.headers.keys(),
                "X-Sucuri-Cache"in res.headers.keys(),
                "Access Denied - Sucuri Website Firewall" in res.text)):
            return True
        return

    @classmethod
    def detect_reblaze(cls, res):
        if res.headers.get(SERVER) == "Reblaze Secure Web Gateway" or res.cookies.get("rbzid"):
            return True
        return


class WAF:

    def __init__(self, host):
        self.host = host
        self.cnames = host.dns_results.get('CNAME')
        self.request_handler = RequestHandler()
        self.web_server_validator = WebServerValidator()
        self.waf_present = False
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
            "Distil Networks": WAFApplicationMethods.detect_distil,
            "Sucuri": WAFApplicationMethods.detect_sucuri,
            "Reblaze": WAFApplicationMethods.detect_reblaze
        }
        log_file = HelpUtilities.get_output_path("{}/WAF.txt".format(self.host.target))
        self.logger = Logger(log_file)

    def _waf_detected(self, name, where):
        self.logger.info(
            "{} Detected WAF presence in {}: {}{}{}".format(
                COLORED_COMBOS.BAD, where, COLOR.RED, name, COLOR.RESET))
        self.waf_present = True

    def _detect_by_cname(self):
        for waf in self.waf_cname_map:
            if any(waf in str(cname) for cname in self.cnames):
                self._waf_detected(self.waf_cname_map.get(waf), "CNAME record")

    async def _detect_by_application(self):
        try:
            session = self.request_handler.get_new_session()
            response = session.get(
                timeout=20,
                allow_redirects=True,
                url="{}://{}:{}".format(
                    self.host.protocol,
                    self.host.target,
                    self.host.port
                )
            )
            for waf, method in self.waf_app_method_map.items():
                result = method(response)
                if result:
                    self._waf_detected(waf, "web application")

        except (ConnectionError, TooManyRedirects) as e:
            raise WAFException("Couldn't get response from server.\n"
                               "Caused due to exception: {}".format(str(e)))

    async def detect(self):
        self.logger.info("{} Trying to detect WAF presence in {}".format(COLORED_COMBOS.INFO, self.host))
        if self.cnames:
            self._detect_by_cname()
        try:
            self.web_server_validator.validate_target_webserver(self.host)
            await self._detect_by_application()

            if not self.waf_present:
                self.logger.info("{} Did not detect WAF presence in target".format(COLORED_COMBOS.GOOD))
        except WebServerValidatorException:
            self.logger.info(
                "{} Target does not seem to have an active web server on port {}. "
                "No WAF could be detected on an application level.".format(COLORED_COMBOS.NOTIFY, self.host.port))