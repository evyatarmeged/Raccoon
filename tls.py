from subprocess import Popen, PIPE
import re


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


# noinspection PyTypeChecker
class TLSVersionChecker:

    def __init__(self, host):
        self.host = host
        self._versions = ("tls1", "tls1_1", "tls1_2")
        # OpenSSL likes to hang, Linux timeout to the rescue
        self._base_script = "timeout 7 openssl s_client -connect {}:443 ".format(self.host)
        self.begin = "-----BEGIN CERTIFICATE-----"
        self.end = "-----END CERTIFICATE-----"
        self.cert_pattern = re.compile("{}(.*?){}".format(self.begin, self.end, re.MULTILINE))

    def test_supported_versions(self):
        return {
            "SNI": self.extract_ssl_data(True),
            "non-SNI": self.extract_ssl_data()
        }

    def is_certificate(self, text):
        if self.begin in text and self.end in text:
            return True
        return

    def get_certificate(self, text):
        # TODO: add certificate to extracted data ?
        pass

    def extract_ssl_data(self, sni=False):
        # Do for all responses
        responses = self._exec_openssl(self._base_script, sni)
        tls_dict = self._parse_sclient_output(responses)
        # Do for any successful SSL response
        for res in responses:
            if self.is_certificate(res):
                tls_dict["SANs"] = self._parse_san_output(res)
                break
        return tls_dict

    def _exec_openssl(self, script, sni=False):
        procs = []
        outputs = []
        if sni:
            script += " -servername {}".format(self.host)
        for v in self._versions:
            curr = script + ' -{}'.format(v)
            procs.append(Popen(curr.split(), stdout=PIPE, stderr=PIPE))
        for p in procs:
            p.wait()
            result, err = p.communicate()
            outputs.append(str(result, encoding='ascii'))
        return outputs


    @staticmethod
    def _parse_san_output(data):
        process = Popen(("openssl", "x509", "-noout", "-text"), stdin=PIPE, stderr=PIPE, stdout=PIPE)
        result, err = process.communicate(input=bytes(data, encoding='ascii'))
        sans = re.findall(r"DNS:\S*\b", str(result, encoding='ascii'))
        return {san.replace("DNS:", '') for san in sans}

    def _parse_sclient_output(self, results):
        is_supported = {"TLSv1": False, "TLSv1.1": False, "TLSv1.2": False}
        for res in results:
            if not self.is_certificate(res):
                continue
            for line in res.split('\n'):
                if "Protocol" in line:
                    ver = line.strip().split(':')[1].strip()
                    is_supported[ver] = True
        return is_supported
