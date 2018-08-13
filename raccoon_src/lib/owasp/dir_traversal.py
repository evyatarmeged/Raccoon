import os
import json
import urllib.parse
from raccoon_src.utils.request_handler import RequestHandler
from raccoon_src.utils.exceptions import RaccoonException, RequestHandlerException
from raccoon_src.utils.coloring import COLORED_COMBOS, COLOR


# Set path for relative access to builtin files.
MY_PATH = os.path.abspath(os.path.dirname(__file__))


class DirectoryTraversal:

    def __init__(self, paths):
        # Many other paths like .ASP and PHP are tested as part of the URL fuzzing
        self.paths = paths
        self.max_traversals = 8
        self.win_traverse = "..\\"
        self.nix_traverse = "../"
        self.request_handler = RequestHandler()
        with open(os.path.join(MY_PATH, "payloads/traversal"), "r") as file:
            self.resources = json.loads(file.read())
    
    @staticmethod
    def _url_encode(url):
        return urllib.parse.quote_plus(url, safe='', encoding=None, errors=None)

    def _traverse(self, path, url, num):
        return self._url_encode(path * num + url)

    def _assert_resource_found(self):
        pass
