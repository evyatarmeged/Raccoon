import requests
from bs4 import BeautifulSoup


# TODO: Probably load selenium here for more thorough like cookies, whatcms.org
class WebAppVulnDetector:

    def __init__(self, target):
        self.target = target

    def detect_cms(self):
        pass

    def find_login_page(self):
        pass

    def gather_cookie_info(self):
        pass

    def clickjacking_exists(self):
        pass

    def xss_exists(self):
        pass

    def cors_wildcard(self):
        pass

    def get_robots_txt(self):
        pass

