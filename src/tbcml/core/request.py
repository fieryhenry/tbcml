from typing import Any, Callable, Optional
import requests
from tbcml.core import io


class RequestHandler:
    """Handles HTTP requests."""

    def __init__(
        self,
        url: str,
        headers: Optional[dict[str, str]] = None,
        data: Optional["io.data.Data"] = None,
    ):
        """Initializes a new instance of the RequestHandler class.

        Args:
            url (str): URL to request.
            headers (Optional[dict[str, str]], optional): Headers to send with the request. Defaults to None.
            data (Optional[io.data.Data], optional): Data to send with the request. Defaults to None.
        """
        if data is None:
            data = io.data.Data()
        self.url = url
        self.headers = headers
        self.data = data

    def get(self) -> requests.Response:
        """Sends a GET request.

        Returns:
            requests.Response: Response from the server.
        """
        return requests.get(self.url, headers=self.headers)

    def get_stream(
        self, progress_callback: Callable[[float, int, int, bool], None]
    ) -> requests.Response:
        """Sends a GET request and streams the response.

        Args:
            progress_callback (Callable[[float, int, int, bool], None]): Callback to call with progress information. Progress between 0 and 1, downloaded bytes, total bytes, and whether it is a filesize

        Returns:
            requests.Response: Response from the server.
        """
        return requests.get(
            self.url,
            headers=self.headers,
            stream=True,
            hooks=dict(response=self.__progress_hook(progress_callback)),
        )

    def get_stream_no_file_size(
        self,
        progress_callback: Callable[[float, int, int], None],
    ) -> requests.Response:
        """Sends a GET request and streams the response.

        Args:
            progress_callback (Callable[[float, int, int], None]): Callback to call with progress information. Progress between 0 and 1, downloaded bytes, and total bytes

        Returns:
            requests.Response: Response from the server.
        """
        return requests.get(
            self.url,
            headers=self.headers,
            stream=True,
            hooks=dict(response=self.__progress_hook_no_file_size(progress_callback)),
        )

    def __progress_hook(
        self,
        progress_callback: Callable[[float, int, int, bool], None],
    ) -> Callable[[requests.Response], None]:
        """Creates a progress hook for a GET request.

        Args:
            progress_callback (Callable[[float, int, int, bool], None]): Callback to call with progress information. Progress between 0 and 1, downloaded bytes, total bytes, and whether it is a filesize

        Returns:
            Callable[[requests.Response], None]: Hook to pass to requests.
        """

        def hook(response: requests.Response, *args: Any, **kwargs: Any) -> None:
            """Hook to pass to requests.

            Args:
                response (requests.Response): Response from the server.
            """
            total_length = response.headers.get("content-length")
            if total_length is None:
                return
            total_length = int(total_length)
            downloaded = 0
            all_data: list[io.data.Data] = []
            for data in response.iter_content(chunk_size=4096):
                downloaded += len(data)
                progress = downloaded / total_length
                progress_callback(progress, downloaded, total_length, True)
                all_data.append(io.data.Data(data))
            response._content = io.data.Data.from_many(all_data).data

        return hook

    def __progress_hook_no_file_size(
        self,
        progress_callback: Callable[[float, int, int], None],
    ) -> Callable[[requests.Response], None]:
        """Creates a progress hook for a GET request.

        Args:
            progress_callback (Callable[[float, int, int], None]): Callback to call with progress information. Progress between 0 and 1, downloaded bytes, and total bytes

        Returns:
            Callable[[requests.Response], None]: Hook to pass to requests.
        """

        def hook(response: requests.Response, *args: Any, **kwargs: Any) -> None:
            """Hook to pass to requests.

            Args:
                response (requests.Response): Response from the server.
            """
            total_length = response.headers.get("content-length")
            if total_length is None:
                return
            total_length = int(total_length)
            downloaded = 0
            all_data: list[io.data.Data] = []
            for data in response.iter_content(chunk_size=4096):
                downloaded += len(data)
                progress = downloaded / total_length
                progress_callback(progress, downloaded, total_length)
                all_data.append(io.data.Data(data))
            response._content = io.data.Data.from_many(all_data).data

        return hook

    def post(self) -> requests.Response:
        """Sends a POST request.

        Returns:
            requests.Response: Response from the server.
        """
        return requests.post(self.url, headers=self.headers, data=self.data.data)
