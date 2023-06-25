from typing import Any, Optional
from tbcml import core
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
            core.Path.get_appdata_folder()
            .add("temp")
            .add(f"{name}{extension}")
            .get_absolute_path()
        )
        self.path.parent().generate_dirs()

    def __enter__(self):
        return self.path

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any):
        self.path.remove(in_thread=True)

    @staticmethod
    def get_temp_path(name: Optional[str] = None, extension: Optional[str] = None):
        return TempFile(name, extension).path


class TempFolder:
    def __init__(self, name: Optional[str] = None):
        if name is None:
            name = str(uuid.uuid4())
        self.path = (
            core.Path.get_appdata_folder().add("temp").add(name).get_absolute_path()
        )
        self.path.generate_dirs()

    def __enter__(self):
        return self.path

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any):
        self.path.remove(in_thread=True)

    @staticmethod
    def get_temp_path(name: Optional[str] = None):
        return TempFolder(name).path
