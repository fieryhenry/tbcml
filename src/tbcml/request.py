"""Handles HTTP requests."""

from typing import Optional

import requests

import tbcml


class RequestHandler:
    """Handles HTTP requests."""

    @staticmethod
    def sizeof_fmt(num: float, suffix: str = "B"):
        for unit in ("", "Ki", "Mi", "Gi", "Ti", "Pi", "Ei", "Zi"):
            if abs(num) < 1024.0:
                return f"{num:3.1f}{unit}{suffix}"
            num /= 1024.0
        return f"{num:.1f}Yi{suffix}"

    def __init__(
        self,
        url: str,
        headers: Optional[dict[str, str]] = None,
        data: Optional["tbcml.Data"] = None,
        timeout: Optional[int] = None,
    ):
        """Initializes a new instance of the RequestHandler class.

        Args:
            url (str): URL to request.
            headers (Optional[dict[str, str]], optional): Headers to send with the request. Defaults to None.
            data (Optional[tbcml.Data], optional): Data to send with the request. Defaults to None.
            timeout (Optional[int], optional): Timeout in seconds. Defaults to None.
        """
        if data is None:
            data = tbcml.Data()
        self.url = url
        self.headers = headers
        self.data = data
        self.timeout = timeout

    def get(self) -> requests.Response:
        """Sends a GET request.

        Returns:
            requests.Response: Response from the server.
        """
        return requests.get(
            self.url, headers=self.headers, timeout=self.timeout, data=self.data.data
        )

    def get_stream(
        self,
    ) -> requests.Response:
        """Sends a GET request and streams the response.

        Returns:
            requests.Response: Response from the server.
        """
        return requests.get(
            self.url,
            headers=self.headers,
            stream=True,
            timeout=self.timeout,
            data=self.data.data,
        )

    def post(self) -> requests.Response:
        """Sends a POST request.

        Returns:
            requests.Response: Response from the server.
        """
        return requests.post(
            self.url, headers=self.headers, data=self.data.data, timeout=self.timeout
        )
