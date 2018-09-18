import requests
from bs4 import BeautifulSoup
from requests.exceptions import ConnectionError, TooManyRedirects
from raccoon_src.utils.web_server_validator import WebServerValidator
from raccoon_src.lib.storage_explorer import StorageExplorer
from raccoon_src.utils.request_handler import RequestHandler
from raccoon_src.utils.help_utils import HelpUtilities
from raccoon_src.utils.coloring import COLOR, COLORED_COMBOS
from raccoon_src.utils.exceptions import WebAppScannerException, WebServerValidatorException
from raccoon_src.utils.logger import Logger


class WebApplicationScanner:

    def __init__(self, host):
        self.host = host
        self.request_handler = RequestHandler()
        self.web_server_validator = WebServerValidator()
        self.headers = None
        self.robots = None
        self.forms = None
        self.fuzzable_urls = set()
        self.emails = set()
        log_file = HelpUtilities.get_output_path("{}/web_scan.txt".format(self.host.target))
        self.target_dir = "/".join(log_file.split("/")[:-1])
        self.logger = Logger(log_file)
        self.storage_explorer = StorageExplorer(host, self.logger)

    def _detect_cms(self, tries=0):
        """
        Detect CMS using whatcms.org.
        Has a re-try mechanism because false negatives may occur
        :param tries: Count of tries for CMS discovery
        """
        # WhatCMS is under CloudFlare which detects and blocks proxied/Tor traffic, hence normal request.
        page = requests.get(url="https://whatcms.org/?s={}".format(self.host.target))
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

    def _cookie_info(self, jar):
        for cookie in jar:
            key = cookie.__dict__.get("name")
            domain = cookie.__dict__.get("domain")
            secure = cookie.__dict__.get("secure")
            http_only = cookie.has_nonstandard_attr("HttpOnly")
            try:
                if domain in self.host.target or self.host.target in domain:
                    if not secure or not http_only:
                        current = "%s Cookie: {%s} -" % (COLORED_COMBOS.GOOD, key)
                        if not secure and not http_only:
                            current += " both secure and HttpOnly flags are not set"
                        elif not secure:
                            current += " secure flag not set"
                        else:
                            current += " HttpOnly flag not set"
                        self.logger.info(current)

            except TypeError:
                continue

    def _server_info(self):
        if self.headers.get("server"):
            self.logger.info("{} Web server detected: {}{}{}".format(
                COLORED_COMBOS.GOOD, COLOR.GREEN, self.headers.get("server"), COLOR.RESET))

    def _x_powered_by(self):
        if self.headers.get("X-Powered-By"):
            self.logger.info("{} X-Powered-By header detected: {}{}{}".format(
                COLORED_COMBOS.GOOD, COLOR.GREEN, self.headers.get("X-Powered-By"), COLOR.RESET))

    def _anti_clickjacking(self):
        if not self.headers.get("X-Frame-Options"):
            self.logger.info(
                "{} X-Frame-Options header not detected - target might be vulnerable to clickjacking".format(
                    COLORED_COMBOS.GOOD)
            )

    def _xss_protection(self):
        xss_header = self.headers.get("X-XSS-PROTECTION")
        if xss_header and "1" in xss_header:
            self.logger.info("{} Found X-XSS-PROTECTION header".format(COLORED_COMBOS.BAD))

    def _cors_wildcard(self):
        if self.headers.get("Access-Control-Allow-Origin") == "*":
            self.logger.info("{} CORS wildcard detected".format(COLORED_COMBOS.GOOD))

    def _robots(self):
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

    def _sitemap(self):
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

    def _analyze_hrefs(self, href):
        if all(("?" in href, "=" in href, not href.startswith("mailto:"))):
            if any(((self.host.naked and self.host.naked in href), self.host.target in href, href.startswith("/"))):
                self.fuzzable_urls.add(href)
        elif href.startswith("mailto:"):
            self._add_to_emails(href)

    def _log_fuzzable_urls(self):
        base_target = "{}://{}:{}".format(self.host.protocol, self.host.target, self.host.port)
        for url in self.fuzzable_urls:
            if url.startswith("/"):
                self.logger.debug("\t{}{}".format(base_target, url))
            else:
                self.logger.debug("\t{}".format(url))

    def _log_emails(self):
        for email in self.emails:
            self.logger.debug("\t{}".format(email[7:]))

    def _find_urls(self, soup):
        urls = soup.select("a")
        if urls:
            for url in urls:
                href = url.get("href")
                if href:
                    self._analyze_hrefs(href)

            if self.fuzzable_urls:
                self.logger.info("{} {} fuzzable URLs discovered".format(
                    COLORED_COMBOS.NOTIFY, len(self.fuzzable_urls)))
                self._log_fuzzable_urls()

            if self.emails:
                self.logger.info("{} {} email addresses discovered".format(
                    COLORED_COMBOS.NOTIFY, len(self.emails)))
                self._log_emails()

    def _find_forms(self, soup):
        # TODO: Analyze interesting input names/ids/params
        self.forms = soup.select("form")
        if self.forms:
            self.logger.info("{} {} HTML forms discovered".format(COLORED_COMBOS.NOTIFY, len(self.forms)))
            for form in self.forms:
                form_action = form.get("action")
                if form_action == "#":
                    continue
                form_id = form.get("id")
                form_class = form.get("class")
                form_method = form.get("method")
                self.logger.debug("\tForm details: ID: {}, Class: {}, Method: {}, action: {}".format(
                    form_id, form_class, form_method, form_action
                ))

    def _add_to_emails(self, href):
        self.emails.add(href)

    async def get_web_application_info(self):
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
                self._robots()
                self._sitemap()
                self._server_info()
                self._x_powered_by()
                self._cors_wildcard()
                self._xss_protection()
                self._anti_clickjacking()
                self._cookie_info(session.cookies)

                soup = BeautifulSoup(response.text, "lxml")
                self._find_urls(soup)
                self._find_forms(soup)
                self.storage_explorer.run(soup)

        except (ConnectionError, TooManyRedirects) as e:
            raise WebAppScannerException("Couldn't get response from server.\n"
                                         "Caused due to exception: {}".format(str(e)))

    async def run_scan(self):
        self.logger.info("{} Trying to collect {} web application data".format(COLORED_COMBOS.INFO, self.host))
        try:
            self.web_server_validator.validate_target_webserver(self.host)
            await self.get_web_application_info()
        except WebServerValidatorException:
            self.logger.info(
                "{} Target does not seem to have an active web server on port: {}. "
                "No web application data will be gathered.".format(COLORED_COMBOS.NOTIFY, self.host.port))
            return
