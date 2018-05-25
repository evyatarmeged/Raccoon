from subprocess import Popen, PIPE


class TLSCipherSuiteChecker:

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

    def run(self):
        # Thread Method
        pass


class TLSVersionChecker:

    def __init__(self, host):
        self.host = host
        self._versions = ("tls1", "tls1_1", "tls1_2")
        # OpenSSL likes to hang, Linux timeout to the rescue
        self._base_script = "timeout 7 openssl s_client -connect {}:443 ".format(self.host)

    def test_supported_versions(self):
        # TODO: should be threaded
        return {
            "SNI": self._test_sni(),
            "non-SNI": self._test_non_sni()
        }

    def _exec_openssl(self, script):
        procs = []
        outputs = []
        for v in self._versions:
            curr = script + ' -{}'.format(v)
            procs.append(Popen(curr.split(), stdout=PIPE, stderr=PIPE))
        for p in procs:
            p.wait()
            result, err = p.communicate()
            outputs.append(str(result, encoding='ascii'))
        return outputs

    def _test_sni(self):
        outputs = self._exec_openssl(self._base_script + ' -servername {}'.format(self.host))
        return self._parse_openssl_output(outputs)

    def _test_non_sni(self):
        outputs = self._exec_openssl(self._base_script)
        return self._parse_openssl_output(outputs)

    def _parse_openssl_output(self, results):
        is_supported = {"TLSv1": False, "TLSv1.1": False, "TLSv1.2": False}
        for res in results:
            if "no peer certificate available" in res:
                continue
            for line in res.split('\n'):
                if "Protocol" in line:
                    ver = line.strip().split(':')[1].strip()
                    is_supported[ver] = True
        return is_supported

    def run(self):
        # Thread Method
        pass
