import urllib.parse


class DirectoryTraversal:

    def __init__(self):
        # Many other paths like .ASP and PHP are tested as part of the URL fuzzing
        self.paths = {
            "unix": ("/etc/passwd", "/etc/passwd%00", "etc/shadow%00", "etc/shadow", "/etc/group",
                     "/etc/security/group", "/etc/security/passwd", "/etc/security/user", "/etc/security/environ",
                     "/etc/security/limits", "/etc/at.allow", "/etc/at.deny"
                     ),

        }
        self.max_traverse = 8
        self.win_traverse = "..\\"
        self.nix_traverse = "../"

    @staticmethod
    def _url_encode(url):
        return urllib.parse.quote_plus(url, safe='', encoding=None, errors=None)

    def _traverse(self, path, url, num):
        return self._url_encode(path * num + url)
