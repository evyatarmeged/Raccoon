from subprocess import Popen, PIPE


class TLSCipherSuiteChcker:

    def __init__(self, host):
        self.host = host

    def scan_ciphers(self, port=443):
        script = "nmap --script ssl-enum-ciphers -p {} {}".format(str(port), self.host)
        process = Popen(script.split(), stdout=PIPE, stderr=PIPE)
        result, err = process.communicate()
        parsed = self.parse_nmap_outpt(result, err)
        return parsed

    def parse_nmap_outpt(self, result, err):
        if err:
            return str(err, encoding='ascii')
        else:
            result = str(result, encoding='ascii').split('\n')
            return '\n'.join([line for line in result if "TLS" in line or "ciphers" in line])


class TLSVersionChecker:
    def __init__(self, host):
        self.host = host
        self.versions = ('tls1', 'tls1_1', 'tls1_2')
        self.script = tuple("openssl s_client -connect {}:443".format(self.host).split())

    def test_supported_versions(self):
        sni = self._test_sni()
        non_sni = self._test_non_sni()

    def _test_sni(self):
        pass

    def _test_non_sni(self):
        pass

