from subprocess import Popen, PIPE


class TLSCipherSuiteChecker:

    def __init__(self, host):
        self.host = host

    def scan_ciphers(self, port=443):
        # TODO: should be threaded
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
        self.versions = ("tls1", "tls1_1", "tls1_2")
        self.supported_versions = {
            "SNI": {"TLSv1": False, "TLSv1.1": False, "TLSv1.2": False},
            "non-SNI": {"TLSv1": False, "TLSv1.1": False, "TLSv1.2": False}
        }
        self.base_script = "openssl s_client -connect {}:443 ".format(self.host)

    def test_supported_versions(self):
        # TODO: should be threaded
        sni = self._test_sni()
        non_sni = self._test_non_sni()
        self.supported_versions["SNI"].update(sni)
        self.supported_versions["non-SNI"].update(non_sni)
        return self.supported_versions

    def _exec_openssl(self, script):
        procs = []
        outputs = []
        for v in self.versions:
            curr = script + ' -{}'.format(v)
            procs.append(Popen(curr.split(), stdout=PIPE, stderr=PIPE))
        for p in procs:
            p.wait()
            result, err = p.communicate()
            result = str(result, encoding='ascii')
            outputs.append(result)
        return outputs

    def _test_sni(self):
        outputs = self._exec_openssl(self.base_script + ' -servername {}'.format(self.host))
        return self._parse_openssl_output(outputs)

    def _test_non_sni(self):
        outputs = self._exec_openssl(self.base_script)
        return self._parse_openssl_output(outputs)

    def _parse_openssl_output(self, results):
        is_supported = {}
        for res in results:
            if "CONNECTED" in res:
                for line in res.split('\n'):
                    if "Protocol" in line:
                        ver = line.strip().split(':')[1].strip()
                        is_supported[ver] = True
        return is_supported
