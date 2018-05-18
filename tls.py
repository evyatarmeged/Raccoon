import subprocess
from pprint import pprint


class TLSCipherSuiteChcker:

    def __init__(self, host):
        # TODO: add more
        self.host = host
        self.server_types = {
            "http": "443",
            "imap": "993",
            "smtp": None
        }

    def scan_ciphers(self, port):
        # TODO: Must be async / thredead
        script = "nmap --script ssl-enum-ciphers -p {} {}".format(str(port), self.host)
        result = subprocess.Popen(script.split(), stdout=subprocess.PIPE)
        print(result.communicate()[0].split('\n'))


class TLSVersionChecker:
    # TODO: Must be async / thredead
    def __init__(self, host):
        self.host = host
        self.versions = ('sslv3', 'tls1', 'tls1_1', 'tls1_2')

    def test_sni_versions(self):
        pass

    def test_non_sni_versions(self):
        pass
