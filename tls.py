from subprocess import Popen, PIPE
from threading import Thread


class TLSCipherSuiteChcker:

    def __init__(self, host):
        self.host = host

    def scan_ciphers(self, port=443):
        script = "nmap --script ssl-enum-ciphers -p {} {}".format(str(port), self.host)
        process = Popen(script.split(), stdout=PIPE, stderr=PIPE)
        result, err = process.communicate()
        parsed = self.parse_nmap_outpt(result, err)
        return parsed

    @staticmethod
    def parse_nmap_outpt(result, err):
        if err:
            return str(err, encoding='ascii')
        else:
            result = str(result, encoding='ascii').split('\n')
            return '\n'.join([line for line in result if "TLS" in line or "ciphers" in line])


class TLSVersionChecker:
    def __init__(self, host):
        self.host = host
        self.versions = {
            "tls1": "TLSv1.0",
            "tls1_1": "TLSv1.1",
            "tls1_2": "TLSv1.2"
        }
        self.base_script = "openssl s_client -connect {}:443 ".format(self.host)

    def test_supported_versions(self):
        sni = self._test_sni()
        # non_sni = self._test_non_sni()

    def _exec_openssl(self, script):
        # TODO: Overwrite with Popen array
        # commands = [ for v in self.versions]
        # procs = [Popen(cmd.split(), stdout=PIPE, stderr=PIPE) for cmd in commands]
        for v in self.versions.keys():
            proc = Popen(script + ' -{}'.format(v), stdout=PIPE, stderr=PIPE)
            p.wait()
            result, err = p.communicate()
            self._parse_openssl_output(result, err)

    def _test_sni(self):
        self._exec_openssl(self.base_script + ' -servername {}'.format(self.host))

    def _test_non_sni(self):
        pass

    @staticmethod
    def _parse_openssl_output(result, err):
        if err:
            return str(err, encoding='ascii')
        else:
            result = str(result, encoding='ascii').split('\n')
            return '\n'.join([line for line in result if "TLS" in line or "ciphers" in line])


a = TLSVersionChecker('www.walla.co.il')
a.test_supported_versions()