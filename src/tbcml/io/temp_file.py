from typing import Any, Optional
import tbcml
import uuid


class TempFile:
    def __init__(
        self,
        name: Optional[str] = None,
        extension: Optional[str] = None,
        path: Optional["tbcml.Path"] = None,
    ):
        if name is None:
            name = str(uuid.uuid4())
        if extension is None:
            extension = ""
        else:
            if not extension.startswith("."):
                extension = f".{extension}"
        if path is None:
            path = (
                tbcml.Path.get_documents_folder()
                .add("temp")
                .add(f"{name}{extension}")
                .get_absolute_path()
            )

        path.parent().generate_dirs()

        self.path = path

    def __enter__(self):
        return self.path

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any):
        self.path.remove(in_thread=True)

    @staticmethod
    def get_temp_path(name: Optional[str] = None, extension: Optional[str] = None):
        return TempFile(name, extension).path


class TempFolder:
    def __init__(self, name: Optional[str] = None, path: Optional["tbcml.Path"] = None):
        if name is None:
            name = str(uuid.uuid4())
        if path is None:
            path = (
                tbcml.Path.get_documents_folder()
                .add("temp")
                .add(name)
                .get_absolute_path()
            )
        path.generate_dirs()
        self.path = path

    def __enter__(self):
        return self.path

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any):
        self.path.remove(in_thread=True)

    @staticmethod
    def get_temp_path(name: Optional[str] = None):
        return TempFolder(name).path
