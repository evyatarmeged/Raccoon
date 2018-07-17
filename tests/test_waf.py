import unittest
from src.lib.waf import WAFApplicationMethods


SERVER = "Server"


class TestWAFHttp(unittest.TestCase):

    # def setUp(self):

    def test_cloudflare_detection_by_headers(self):
        headers = {"CF-RAY": None}
        self.assertTrue(WAFApplicationMethods.detect_cloudflare(headers))

    def test_cloudflare_detection_by_server(self):
        headers = {SERVER: "cloudflare"}
        self.assertTrue(WAFApplicationMethods.detect_cloudflare(headers))

    def test_cloudfront_detection_by_headers(self):
        headers = {"Via": "cloudfront"}
        self.assertTrue(WAFApplicationMethods.detect_cloudfront(headers))
        headers = {"X-cache": "cloudfront"}
        self.assertTrue(WAFApplicationMethods.detect_cloudfront(headers))

    def test_cloudfront_detection_by_server(self):
        headers = {SERVER: "CloudFront"}
        self.assertTrue(WAFApplicationMethods.detect_cloudfront(headers))

    def test_incapsula_detection_by_headers(self):
        headers = {"X-Iinfo": None}
        self.assertTrue(WAFApplicationMethods.detect_incapsula(headers))
        headers = {"X-CDN": "Incapsula"}
        self.assertTrue(WAFApplicationMethods.detect_incapsula(headers))

    def test_maxcdn_detection_by_server(self):
        headers = {SERVER: "NetDNA-cache"}
        self.assertTrue(WAFApplicationMethods.detect_maxcdn(headers))

    def test_edgecast_detection_by_server(self):
        headers = {SERVER: "ECD-conglom"}
        self.assertTrue(WAFApplicationMethods.detect_edgecast(headers))


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
