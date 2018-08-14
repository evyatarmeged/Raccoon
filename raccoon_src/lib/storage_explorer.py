import os
import xmltodict
from raccoon_src.utils.request_handler import RequestHandler
from raccoon_src.utils.exceptions import RaccoonException, RequestHandlerException
from raccoon_src.utils.coloring import COLORED_COMBOS, COLOR


# Set path for relative access to builtin files.
MY_PATH = os.path.abspath(os.path.dirname(__file__))
HTTP = "http://"
HTTPS = "https://"
BASE_S3_URL = "s3.amazonaws.com"


class Storage:

    def __init__(self, host, logger):
        self.host = host
        self.logger = logger
        self.request_handler = RequestHandler()
        self.storage_urls_found = set()
        self.num_files_found = 0
        file_list_path = os.path.join(MY_PATH, "../wordlists/storage_sensitive")
        with open(file_list_path, "r") as file:
            files = file.readlines()
            self.sensitive_files = [x.replace("\n", "") for x in files]

    @staticmethod
    def _normalize_url(url):
        if url.startswith(HTTP):
            url = url.replace(HTTP, "")
            url = "".join([part for part in url.split("//") if part])
            return HTTP+url
        else:
            url = url.replace(HTTPS, "")
            url = "".join([part for part in url.split("//") if part])
            return HTTPS+url


# Is this a thing ??
class AzureStorageHandler:
    pass


class GoogleStorageHandler:
    pass


class AmazonS3Handler(Storage):

    def __init__(self, host, logger):
        super().__init__(host, logger)
        self.s3_buckets = set()

    def _is_s3_url(self, src):
        # Not including third party Amazon host services - aka cdn.3rdparty.com
        return any(("s3" in src and "amazonaws" in src,
                    "cdn.{}".format(str(self.host.naked)) in src,
                    "cdn.{}".format(self.host.target) in src,
                    "cdn.{}".format(".".join(self.host.target.split(".")[1:])) in src,
                    "cloudfront.net" in src))

    @staticmethod
    def _is_amazon_s3_bucket(res):
        return res.headers.get("Server") == "AmazonS3"

    def _test_s3_bucket_permissions(self, bucket):
        try:
            bucket_url = [part for part in bucket.no_scheme_url.split("/") if part]
            bucket_len = len(bucket_url)

            for i in range(bucket_len-1):
                url = "/".join(bucket_url[:i+1])
                if url == BASE_S3_URL or url in self.storage_urls_found:
                    continue

                self.storage_urls_found.add(url)
                res = self.request_handler.send("GET", url=HTTPS+url)

                if res.status_code == 200 and res.headers.get("Content-Type") == "application/xml":
                    self.logger.info("{} Vulnerable S3 bucket detected: {}{}{}. Enumerating sensitive files".format(
                        COLORED_COMBOS.GOOD, COLOR.RED, url, COLOR.RESET))
                    bucket.vulnerable = True
                    self._scan_for_sensitive_files(res.text, url)

        except RequestHandlerException:
            # Cannot connect to bucket, move on
            pass

    def _scan_for_sensitive_files(self, contents, url):
        xpars = xmltodict.parse(contents)
        for el in xpars.get("ListBucketResult").get("Contents"):
            key = el.get("Key")
            for file in self.sensitive_files:
                if file in key:
                    self.logger.debug("Found {} file in bucket {}".format(key, url))
                    self.num_files_found += 1


class S3Bucket:

    def __init__(self, url):
        self.url = self._strip_resource_from_bucket(url)
        self.no_scheme_url = self._remove_scheme_from_url(self.url)
        self.vulnerable = False

    @staticmethod
    def _strip_resource_from_bucket(bucket_url):
        # Return the storage URL without the resource
        return "/".join(bucket_url.split("/")[:-1])

    @staticmethod
    def _remove_scheme_from_url(url):
        if url.startswith(HTTP):
            url = url.replace(HTTP, "")
        else:
            url = url.replace(HTTPS, "")
        return "".join([part for part in url.split("//") if part])


class StorageExplorer(AmazonS3Handler, GoogleStorageHandler, AzureStorageHandler):
    """
    Find and test privileges of target cloud storage and look for sensitive files in it.
    Can lead to finding .git/.DS_Store/etc files with tokens, passwords and more.
    """

    def __init__(self, host, logger):
        super().__init__(host, logger)
        self.host = host
        self.logger = logger  # Uses the logger from web_app module
        self.buckets_found = set()

    @staticmethod
    def _get_image_sources_from_html(soup):
        images = soup.select("img")
        return {img.get("src") for img in images if img.get("src")}

    def _add_to_found_storage(self, storage_url):
        """
        Will first normalize the img src and then check if this bucket was discovered before
        If it is in storage_urls_found, the function returns
        Else, it send a GET for the original URL (normalized image src) and will look for "AmazonS3" in
        the "Server" response header.
        If found, will add to URL with the resource stripped

        :param storage_url: img src scraped from page
        """
        storage_url = self._normalize_url(storage_url)
        bucket = S3Bucket(storage_url)
        if bucket.url not in self.storage_urls_found:
            try:
                res = self.request_handler.send("GET", url=storage_url)
                if self._is_amazon_s3_bucket(res):
                    self.storage_urls_found.add(bucket.url)
                    self.s3_buckets.add(bucket)
            except RequestHandlerException:
                # Cannot connect to storage, move on
                pass

    def run(self, soup):
        img_srcs = self._get_image_sources_from_html(soup)
        # First validation
        urls = {src for src in img_srcs if self._is_s3_url(src)}
        for url in urls:
            self._add_to_found_storage(url)
        if self.s3_buckets:
            self.logger.info("{} S3 buckets discovered. Testing for permissions".format(COLORED_COMBOS.NOTIFY))
            for bucket in self.s3_buckets:
                if bucket.no_scheme_url in self.storage_urls_found:
                    continue
                else:
                    self._test_s3_bucket_permissions(bucket)

            if self.num_files_found > 0:
                self.logger.info(
                    "{} Found {}{}{} sensitive files in S3 buckets. inspect web scan logs for more information.".format(
                        COLORED_COMBOS.GOOD, COLOR.GREEN, self.num_files_found, COLOR.RESET))
            elif any(b.vulnerable for b in self.s3_buckets):
                self.logger.info("{} No sensitive files found in target's cloud storage".format(COLORED_COMBOS.BAD))
            else:
                self.logger.info("{} Could not access target's cloud storage."
                                 " All permissions are set properly".format(COLORED_COMBOS.BAD))
