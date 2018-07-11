import requests
from bs4 import BeautifulSoup
from requests.exceptions import ConnectionError, TooManyRedirects
from raccoon.utils.web_server_validator import WebServerValidator
from raccoon.utils.request_handler import RequestHandler
from raccoon.utils.helper_utils import HelperUtilities
from raccoon.utils.coloring import COLOR, COLORED_COMBOS
from raccoon.utils.exceptions import WebAppScannerException, WebServerValidatorException
from raccoon.utils.logger import Logger


class WebApplicationScanner:

    def __init__(self, host):
        self.host = host
        self.request_handler = RequestHandler()
        self.web_server_validator = WebServerValidator()
        self.web_scan_results = []
        self.headers = None
        self.robots = None
        log_file = HelperUtilities.get_output_path("{}/web_scan.txt".format(self.host.target))
        self.target_dir = "/".join(log_file.split("/")[:-1])
        self.logger = Logger(log_file)

    def _detect_cms(self, tries=0):
        """
        Detect CMS using whatcms.org.
        Has a re-try mechanism because false negatives may occur
        :param tries: Count of tries for CMS discovery
        """
        page = requests.get("https://whatcms.org/?s={}".format(self.host.target))
        soup = BeautifulSoup(page.text, "lxml")
        found = soup.select(".panel.panel-success")
        if found:
            try:
                cms = [a for a in soup.select("a") if "/c/" in a.get("href")][0]
                self.logger.info("{} CMS detected: target is using {}{}{}".format(
                    COLORED_COMBOS.GOOD, COLOR.GREEN, cms.get("title"), COLOR.RESET))
            except IndexError:
                if tries >= 4:
                    return
                else:
                    self._detect_cms(tries=tries + 1)
        else:
            if tries >= 4:
                return
            else:
                self._detect_cms(tries=tries + 1)

    def _gather_cookie_info(self, jar):
        for cookie in jar:
            key = cookie.__dict__.get("name")
            value = cookie.__dict__.get("value")
            domain = cookie.__dict__.get("domain")
            secure = cookie.__dict__.get("secure")
            try:
                if domain in self.host.target or self.host.target in domain:
                    if not secure:
                        self.logger.info(
                            "%s Found cookie without secure flag: {%s: %s}" % (COLORED_COMBOS.GOOD, key, value)
                        )
            except TypeError:
                continue

    def _gather_server_info(self):
        if self.headers.get("server"):
            self.logger.info("{} Web server detected: {}{}{}".format(
                COLORED_COMBOS.WARNING, COLOR.YELLOW, self.headers.get("server"), COLOR.RESET))

    def _detect_anti_clickjacking(self):
        if not self.headers.get("X-Frame-Options"):
            self.logger.info(
                "{} X-Frame-Options header not detected - target might be vulnerable to clickjacking".format(
                    COLORED_COMBOS.GOOD)
            )

    def _detect_xss_protection(self):
        xss_header = self.headers.get("X-XSS-PROTECTION")
        if xss_header and "1" in xss_header:
            self.logger.info("{} Found X-XSS-PROTECTION header".format(COLORED_COMBOS.BAD))

    def _cors_wildcard(self):
        if self.headers.get("Access-Control-Allow-Origin") == "*":
            self.logger.info("{} CORS wildcard detected".format(COLORED_COMBOS.GOOD))

    def _get_robots_txt(self):
        res = self.request_handler.send(
            "GET",
            url="{}://{}:{}/robots.txt".format(
                self.host.protocol,
                self.host.target,
                self.host.port
            )
        )
        if res.status_code != 404 and res.text and "<!DOCTYPE html>" not in res.text:
            self.logger.info("{} Found robots.txt".format(COLORED_COMBOS.GOOD))
            with open("{}/robots.txt".format(self.target_dir), "w") as file:
                file.write(res.text)

    def _get_sitemap(self):
        res = self.request_handler.send(
            "GET",
            url="{}://{}:{}/sitemap.xml".format(
                self.host.protocol,
                self.host.target,
                self.host.port
            )
        )
        if res.status_code != 404 and res.text and "<!DOCTYPE html>" not in res.text:
            self.logger.info("{} Found sitemap.xml".format(COLORED_COMBOS.GOOD))
            with open("{}/sitemap.xml".format(self.target_dir), "w") as file:
                file.write(res.text)

    def get_web_application_info(self):
        session = self.request_handler.get_new_session()
        try:
            with session:
                # Test if target is serving HTTP requests
                response = session.get(
                    timeout=20,
                    url="{}://{}:{}".format(
                        self.host.protocol,
                        self.host.target,
                        self.host.port
                    )
                )
                self.headers = response.headers
                self._detect_cms()
                self._get_robots_txt()
                self._get_sitemap()
                self._gather_server_info()
                self._cors_wildcard()
                self._detect_xss_protection()
                self._detect_anti_clickjacking()
                self._gather_cookie_info(session.cookies)

        except (ConnectionError, TooManyRedirects) as e:
            raise WebAppScannerException("Couldn't get response from server.\n"
                                         "Caused due to exception: {}".format(str(e)))

    async def run_scan(self):
        self.logger.info("{} Trying to collect {} web application data".format(COLORED_COMBOS.INFO, self.host))
        try:
            self.web_server_validator.validate_target_webserver(self.host)
            self.get_web_application_info()
        except WebServerValidatorException:
            self.logger.info(
                "{} Target does not seem to have an active web server on port: {}\n"
                "No web application data will be gathered.".format(COLORED_COMBOS.WARNING, self.host.port))
            return