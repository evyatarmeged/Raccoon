import xmltodict
from raccoon_src.utils.request_handler import RequestHandler
from raccoon_src.utils.help_utils import HelpUtilities
from raccoon_src.utils.exceptions import RaccoonException, RequestHandlerException
from raccoon_src.utils.coloring import COLORED_COMBOS, COLOR
from raccoon_src.utils.logger import Logger


class StorageExplorer:
    """
    Find and test privileges of target cloud storage and look for sensitive files in storage
    """

    def __init__(self, logger, host):

        self.host = host
        self.sensitive_files = ("DS_Store", ".git")  # Add more/read from file
        self.num_files_found = 0
        self.buckets_found = set()
        self.request_handler = RequestHandler()
        self.logger = logger  # Uses the logger from web_app module

    @staticmethod
    def _extract_scheme(url):
        if url.startswith("http://"):
            return "http://"
        else:
            return "https://"

    def _bucket_path_traversal(self, bucket_url):
        # Return the bucket's URL without the resource
        return "/".join(bucket_url.split("/")[:-1])

    def search_img_srcs_for_cloud_storages(self, soup):
        images = soup.select("img")
        for img in images:
            src = img.get("src")
            if src:
                # Not including third party Amazon host services - aka cdn.3rdparty.com
                if any(("s3" in src and "amazonaws" in src,
                        "cdn." + str(self.host.naked) in src,
                        "cdn." + self.host.target in src,
                        "cdn." + ".".join(self.host.target.split(".")[1:]) in src,
                        "cloudfront.net" in src
                        )):
                    self._test_s3_bucket_permissions(src)

    def _test_s3_bucket_permissions(self, bucket_url):
        traversed_bucket = self._bucket_path_traversal(bucket_url)  # Bucket path without the resource (image)
        if traversed_bucket in self.buckets_found:
            # Already scanned this bucket
            return
        else:
            self.logger.info("{} Found an S3 bucket: {} - testing permissions".format(
                COLORED_COMBOS.NOTIFY, traversed_bucket))
            self.buckets_found.add(self._bucket_path_traversal(bucket_url))

        scheme = self._extract_scheme(bucket_url)
        self.buckets_found.add(self._bucket_path_traversal(bucket_url))
        bucket_url = bucket_url.replace(scheme, "")
        bucket_url = [part for part in bucket_url.split("/") if part]
        try:
            for i in range(len(bucket_url)-1):
                url = "/".join(bucket_url[:i+1])
                res = self.request_handler.send("GET", url=scheme+url)
                if res.status_code == 200 and res.headers.get("Server") == "AmazonS3" \
                        and res.get("Content-Type") == "application/xml":
                    self.logger.info("{} Vulnerable S3 bucket detected: {}. Enumerating sensitive files".format(
                        COLORED_COMBOS.GOOD, url))
                    self._scan_s3_bucket_for_sensitive_files(url)
        except RequestHandlerException:
            self.logger.info("{} Failed to connect to bucket.".format(COLORED_COMBOS.BAD))
        finally:
            if self.num_files_found > 0:
                self.logger.info(
                    "{} Found {}{}{} sensitive files in S3 buckets. inspect output logs for more information.".format(
                        COLORED_COMBOS.GOOD, COLOR.RED, self.num_files_found, COLOR.RESET))

    def _scan_s3_bucket_for_sensitive_files(self, bucket):
        contents = self.request_handler.send("GET", url=bucket).text
        xpars = xmltodict.parse(contents)
        for el in xpars.get("ListBucketResult").get("Contents"):
            key = el.get("Key")
            for file in self.sensitive_files:
                if file in key:
                    self.logger.debug("Found {} file in bucket {}".format(file, bucket))
                    self.num_files_found += 1
