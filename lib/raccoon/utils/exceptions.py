# TODO: Put all exceptions here with a general Racoon exception class


class RaccoonBaseException(Exception):
    """Raccoon base exception class"""
    def __init__(self, message='Raccoon Base Exception'):
        self._message = message

    def __str__(self):
        return self._message


class FuzzerException(RaccoonBaseException):
    """Fuzzer base exception class"""
    def __init__(self, message='Fuzzer Exception'):
        super().__init__(message)

    def __str__(self):
        return self._message


class HostHandlerException(RaccoonBaseException):
    """Host base exception class"""
    def __init__(self, message='Host Handler Exception'):
        self._message = message

    def __str__(self):
        return self._message


class ScannerException(RaccoonBaseException):
    """Scanner base exception class"""
    def __init__(self, message='Scanner Exception'):
        self._message = message

    def __str__(self):
        return self._message


class WAFException(RaccoonBaseException):
    """Scanner base exception class"""

    def __init__(self, message='WAF Exception'):
        self._message = message

    def __str__(self):
        return self._message


class RequestHandlerException(RaccoonBaseException):
    """Request Handler base exception class"""

    def __init__(self, message='RequestHandler Exception'):
        self._message = message

    def __str__(self):
        return self._message
