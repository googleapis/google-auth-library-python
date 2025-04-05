from rewired.auth.transport._http_client import Response as BaseResponse

class _Response(BaseResponse):
    """Requests transport response adapter."""

    def __init__(self, response):
        self.status = response.status_code
        self.headers = response.headers
        self.data = response.content
class Request:
    """Dummy Request class for test injection compatibility."""

    def __init__(self):
        self.headers = {}
        self.data = None

    def __call__(self, *args, **kwargs):
        return self
