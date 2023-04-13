from typing import Any, Optional
from tbcml.core import io
import uuid


class TempFile:
    def __init__(self, name: Optional[str] = None, extension: Optional[str] = None):
        if name is None:
            name = str(uuid.uuid4())
        if extension is None:
            extension = ""
        else:
            if not extension.startswith("."):
                extension = f".{extension}"
        self.path = (
            io.path.Path.get_appdata_folder()
            .add("temp")
            .add(f"{name}{extension}")
            .get_absolute_path()
        )
        self.path.parent().generate_dirs()

    def __enter__(self):
        return self.path

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any):
        self.path.remove()

    @staticmethod
    def get_temp_path(name: Optional[str] = None, extension: Optional[str] = None):
        return TempFile(name, extension).path
