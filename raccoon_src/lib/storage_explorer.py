import xmltodict
from raccoon_src.utils.request_handler import RequestHandler


class StorageExplorer:
    """
    Find and test privileges of target cloud storage and look for sensitive files in storage
    """

    def __init__(self):

        self.sensitive_files = ("DS_Store", ".git")  # Add more
        self.request_handler = RequestHandler()
        self.storage_found = []

    def search_img_srcs_for_cloud_storages(self, soup):
        # ?xml version in response
        # Content-Type: application/xml
        images = soup.select("img")

    def test_s3_bucket_permissions(self):
        pass

    def scan_s3_bucket_for_sensitive_files(self, bucket):
        contents = self.request_handler.send("GET", url=bucket).text
        xpars = xmltodict.parse(contents)
        # for el in xpars.get("ListBucketResult").get("Contents"):
        # key = el.get("Key")



