from __future__ import annotations
from typing import Any

import tbcml


class Result:
    def __init__(
        self,
        success: bool,
        data: Any | None = None,
        error: str | None = None,
    ):
        self.success = success
        self.data = data
        self.error = error

    def __bool__(self) -> bool:
        return self.success

    def __str__(self) -> str:
        if self.data:
            return str(self.data)
        if self.error:
            return self.error
        return str(self.success)

    def __repr__(self) -> str:
        return f"Result(success={self.success}, data={self.data}, error={self.error})"

    @staticmethod
    def file_not_found(path: tbcml.PathStr) -> Result:
        return Result(False, error=f"The file at {path} does not exist!")

    @staticmethod
    def program_not_installed(
        prog_name: str, install_from: str | None = None, extra: str | None = None
    ):
        text = f"{prog_name} is not installed or not in your PATH."
        if install_from is not None:
            text += f" Install from: {install_from}."
        if extra is not None:
            text += f" {extra}."

        return Result(False, error=text)

    @staticmethod
    def from_exception(e: Exception):
        return Result(False, error=str(e))
