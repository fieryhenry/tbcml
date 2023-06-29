from typing import Optional
import zipfile
from tbcml import core


class Zip:
    password_length = 16

    def __init__(
        self,
        file_data: Optional["core.Data"] = None,
        encrypted: bool = False,
        password: Optional[str] = None,
        validate_password: bool = True,
    ):
        mode = "r"
        if file_data is None:
            file_data = core.Data()
        if file_data.is_empty():
            mode = "w"
        self.file_data = file_data.to_bytes_io()
        self.salt = None
        self.password = None
        self.encrypted = encrypted

        if encrypted:
            pepper = "tbcml"
            if password is not None:
                password_hash = core.Hash(core.HashAlgorithm.SHA256).get_hash(
                    core.Data(password + pepper), length=self.password_length
                )
            else:
                password_hash = core.Hash(core.HashAlgorithm.SHA256).get_hash(
                    core.Data(pepper), length=self.password_length
                )

            if not file_data.is_empty():
                file_data.set_pos(0)
                salt_data = core.Data(file_data.read_bytes(32 - self.password_length))
                actual_password_hash = core.Data(
                    file_data.read_bytes(self.password_length)
                )
                if actual_password_hash != password_hash and validate_password:
                    raise ValueError("Invalid password")
                main_data = core.Data(file_data.data[32:])
                key_data = salt_data + actual_password_hash
                self.file_data = (
                    core.AesCipher(key_data.to_bytes()).decrypt(main_data).to_bytes_io()
                )
                self.password = actual_password_hash
                self.salt = salt_data
            else:
                self.password = password_hash
                self.salt = core.Data(core.Random.get_bytes(32 - self.password_length))

        self.zip = zipfile.ZipFile(
            self.file_data, mode=mode, compression=zipfile.ZIP_DEFLATED
        )

    def validate_password(self, password: str) -> bool:
        if self.password is None:
            return False
        if self.password != core.Hash(core.HashAlgorithm.SHA256).get_hash(
            core.Data(password + "tbcml"), length=self.password_length
        ):
            return False
        return True

    @staticmethod
    def from_file(
        path: "core.Path",
        encrypted: bool = False,
        password: Optional[str] = None,
        validate_password: bool = True,
    ) -> "Zip":
        return Zip(path.read(), encrypted, password, validate_password)

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
        if self.encrypted:
            if self.password is not None and self.salt is not None:
                salt_data = core.Data(self.salt.to_bytes())
                password_data = core.Data(self.password.to_bytes())
                key_data = salt_data + password_data
                data = data.pad_pkcs7()
                data = core.AesCipher(key_data.to_bytes()).encrypt(data)
                data = key_data + data
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

    def get_paths_in_folder(self, folder_name: str) -> list["core.Path"]:
        return [
            core.Path(name)
            for name in self.zip.namelist()
            if name.startswith(folder_name)
        ]
