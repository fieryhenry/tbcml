from typing import Any, Callable, Optional
import requests
from bcml.core import io


class RequestHandler:
    def __init__(
        self,
        url: str,
        headers: Optional[dict[str, str]] = None,
        data: Optional["io.data.Data"] = None,
    ):
        if data is None:
            data = io.data.Data()
        self.url = url
        self.headers = headers
        self.data = data

    def get(self) -> requests.Response:
        return requests.get(self.url, headers=self.headers)

    def get_stream(self, progress_callback: Callable[[float, int, int, bool], None]):
        return requests.get(
            self.url,
            headers=self.headers,
            stream=True,
            hooks=dict(response=self.__progress_hook(progress_callback)),
        )

    def __progress_hook(
        self, progress_callback: Callable[[float, int, int, bool], None]
    ) -> Callable[[requests.Response], None]:
        def hook(response: requests.Response, *args: Any, **kwargs: Any) -> None:
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

    def post(self) -> requests.Response:
        return requests.post(self.url, headers=self.headers, data=self.data.data)
