from typing import Optional
import zipfile
from tbcml import core


class Zip:
    password_length = 16

    def __init__(
        self,
        file_data: Optional["core.Data"] = None,
    ):
        mode = "r"
        if file_data is None:
            file_data = core.Data()
        if file_data.is_empty():
            mode = "w"
        self.file_data = file_data.to_bytes_io()

        self.zip = zipfile.ZipFile(
            self.file_data, mode=mode, compression=zipfile.ZIP_DEFLATED
        )

    @staticmethod
    def from_file(path: "core.Path") -> "Zip":
        return Zip(path.read())

    def add_file(self, file_name: "core.Path", file_data: "core.Data"):
        self.zip.writestr(file_name.to_str_forwards(), file_data.to_bytes())

    def get_file(
        self, file_name: "core.Path", show_error: bool = False
    ) -> Optional["core.Data"]:
        try:
            return core.Data(self.zip.read(file_name.to_str_forwards()))
        except KeyError:
            if show_error:
                print(f"File {file_name} not found in zip")
            return None

    def to_data(self) -> "core.Data":
        self.close()
        data = core.Data(self.file_data.getvalue())
        return data

    def folder_exists(self, folder_name: str) -> bool:
        return folder_name in self.zip.namelist()

    def close(self):
        self.zip.close()

    def save(self, path: "core.Path"):
        self.close()
        path.write(self.to_data())

    def extract(self, path: "core.Path"):
        self.zip.extractall(path.to_str_forwards())

    def get_paths(self) -> list["core.Path"]:
        return [core.Path(name) for name in self.zip.namelist()]

    def get_paths_in_folder(self, folder_name: "core.Path") -> list["core.Path"]:
        return [
            core.Path(name)
            for name in self.zip.namelist()
            if name.startswith(folder_name.to_str_forwards())
        ]
