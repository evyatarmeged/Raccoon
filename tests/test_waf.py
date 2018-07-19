import unittest
from raccoon_src.lib.waf import WAFApplicationMethods


class Response:
    headers = {}


class TestWAFHttp(unittest.TestCase):

    def setUp(self):
        self.server = "Server"
        self.response = Response()

    def test_cloudflare_detection_by_headers(self):
        self.response.headers = {"CF-RAY": None}
        self.assertTrue(WAFApplicationMethods.detect_cloudflare(self.response))

    def test_cloudflare_detection_by_server(self):
        self.response.headers = {self.server: "cloudflare"}
        self.assertTrue(WAFApplicationMethods.detect_cloudflare(self.response))

    def test_cloudfront_detection_by_headers(self):
        self.response.headers = {"Via": "cloudfront"}
        self.assertTrue(WAFApplicationMethods.detect_cloudfront(self.response))
        self.response.headers = {"X-cache": "cloudfront"}
        self.assertTrue(WAFApplicationMethods.detect_cloudfront(self.response))

    def test_cloudfront_detection_by_server(self):
        self.response.headers = {self.server: "CloudFront"}
        self.assertTrue(WAFApplicationMethods.detect_cloudfront(self.response))

    def test_incapsula_detection_by_headers(self):
        self.response.headers = {"X-Iinfo": None}
        self.assertTrue(WAFApplicationMethods.detect_incapsula(self.response))
        self.response.headers = {"X-CDN": "Incapsula"}
        self.assertTrue(WAFApplicationMethods.detect_incapsula(self.response))

    def test_maxcdn_detection_by_server(self):
        self.response.headers = {self.server: "NetDNA-cache"}
        self.assertTrue(WAFApplicationMethods.detect_maxcdn(self.response))

    def test_edgecast_detection_by_server(self):
        self.response.headers = {self.server: "ECD-conglom"}
        self.assertTrue(WAFApplicationMethods.detect_edgecast(self.response))


class TestWAFCName(unittest.TestCase):

    def setUp(self):
        self.waf_cname_map = {
            "incapdns": "Incapsula",
            "edgekey": "Akamai",
            "akamai": "Akamai",
            "edgesuite": "Akamai",
            "distil": "Distil Networks",
            "cloudfront": "CloudFront",
            "netdna-cdn": "MaxCDN"
        }

    def detect_by_cname(self, cnames):
        for waf in self.waf_cname_map:
            if any(waf in str(cname) for cname in cnames):
                return self.waf_cname_map.get(waf)

    def test_akamai_detection(self):
        records = {"some_akamai_dns_value": "Akamai",
                   "otherkey": "othervalue"
                   }
        self.assertEqual(self.detect_by_cname(records), "Akamai")

    def test_second_akamai_detection(self):
        records = {"example_edgesuite_example": "Akamai",
                   "otherkey": "othervalue"
                   }
        self.assertEqual(self.detect_by_cname(records), "Akamai")

    def test_third_akamai_detection(self):
        records = {"example_edgekey_example": "Akamai",
                   "otherkey": "othervalue"}
        self.assertEqual(self.detect_by_cname(records), "Akamai")

    def test_incapsula_detection(self):
        records = {"example.incapdns.or.not": "Incapsula",
                   "otherkey": "othervalue"}
        self.assertEqual(self.detect_by_cname(records), "Incapsula")

    def test_distil_detection(self):
        records = {"lolz.distil.kthx": "Distil Networks",
                   "not": "real"}
        self.assertEqual(self.detect_by_cname(records), "Distil Networks")

    def test_cloudfront_detection(self):
        records = {"aws.cloudfront.is.it": "CloudFront",
                   "AWS": "CO.UK"}
        self.assertEqual(self.detect_by_cname(records), "CloudFront")

    def test_maxcdn_detection(self):
        records = {"mycdn.netdna-cdn.godmode": "MaxCDN",
                   "HAI1.2": "IHAZAVAR"}
        self.assertEqual(self.detect_by_cname(records), "MaxCDN")
