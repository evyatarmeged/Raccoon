import urllib.parse


class Traversal:

    def __init__(self):
        # Many other paths like .ASP and PHP are tested as part of the URL fuzzing
        self.paths = {
            "unix": ("/etc/passwd", "/etc/passwd%00", "etc/shadow%00", "etc/shadow", "/etc/group",
                     "/etc/security/group", "/etc/security/passwd", "/etc/security/user", "/etc/security/environ",
                     "/etc/security/limits", "/etc/at.allow", "/etc/at.deny", "/b'i'n/c'a't /e't'c/p'a's's'w'd'"
                     ),

        }
        self.max_traverse = 7
#        path_traversal = "../" if not windows else "..\\"

    @staticmethod
    def _url_encode(url):
        return urllib.parse.quote_plus(url, safe='', encoding=None, errors=None)
