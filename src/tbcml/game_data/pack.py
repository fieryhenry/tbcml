"""Module for handling game data."""

from typing import Optional, Union
import copy

import tbcml


class GameFile:
    def __init__(
        self,
        enc_data: Optional["tbcml.Data"],
        file_name: str,
        pack_name: str,
        cc: "tbcml.CountryCode",
        gv: "tbcml.GameVersion",
        key: Optional[str] = None,
        iv: Optional[str] = None,
        dec_data: Optional["tbcml.Data"] = None,
    ):
        self.enc_data = enc_data
        self.file_name = file_name
        self.pack_name = pack_name
        self.cc = cc
        self.gv = gv
        self.key = key
        self.iv = iv
        self.__dec_data: Optional["tbcml.Data"] = dec_data
        self.original_dec_data: Optional["tbcml.Data"] = None

    @property
    def dec_data(self):
        return self.decrypt_data()

    def decrypt_data(self):
        if self.__dec_data is not None:
            return self.__dec_data

        cipher = PackFile.get_cipher(
            self.cc, self.pack_name, self.gv, key=self.key, iv=self.iv
        )
        if self.enc_data is None:
            raise ValueError("No enc_data or dec_data specified")
        data = cipher.decrypt(self.enc_data)
        try:
            data = data.unpad_pkcs7()
        except ValueError:
            pass
        self.__dec_data = data
        return self.__dec_data

    @dec_data.setter
    def dec_data(self, data: "tbcml.Data"):
        self.__dec_data = data

    def encrypt(
        self,
        force_server: bool = False,
        key: Optional[str] = None,
        iv: Optional[str] = None,
    ) -> "tbcml.Data":
        """Encrypt the decrypted data.

        Returns:
            tbcml.Data: The encrypted data.
        """
        if key is not None or iv is not None:
            self.decrypt_data()  # needs to be re-encrypted if key or iv is different
        if self.enc_data is not None:
            if self.__dec_data is None or self.__dec_data == self.original_dec_data:
                return self.enc_data
            if (
                PackFile.is_image_data_local_pack(self.pack_name)
                and not force_server
                and self.__dec_data == self.original_dec_data
            ):
                return self.enc_data
        if self.__dec_data is None:
            raise ValueError("dec data or enc data need to be provided")

        cipher = PackFile.get_cipher(
            self.cc, self.pack_name, self.gv, force_server, key, iv
        )
        data = self.__dec_data.pad_pkcs7()
        return cipher.encrypt(data)

    def extract(self, path: "tbcml.Path", encrypt: bool = False):
        """Extract the decrypted data to a file.

        Args:
            path (tbcml.Path): The path to extract the file to.
        """
        path = path.add(self.file_name)
        if not encrypt:
            path.write(self.dec_data)
        else:
            path.write(self.encrypt(force_server=True))

    @staticmethod
    def is_anim(file_name: str) -> bool:
        """Check if a file is an animation file.

        Args:
            file_name (str): The name of the file.

        Returns:
            bool: True if the file is an animation file, False otherwise.
        """

        extensions = [".maanim", ".mamodel", ".imgcut"]
        return any(file_name.endswith(ext) for ext in extensions)


class PackFile:
    """Represents a pack file containing multiple game files."""

    def __init__(
        self,
        pack_name: str,
        country_code: "tbcml.CountryCode",
        gv: "tbcml.GameVersion",
    ):
        """Initialize a new PackFile.

        Args:
            pack_name (str): The name of the pack.
            country_code (country_code.CountryCode): The country code of the game data.
            gv (game_version.GameVersion): The game version of the game data.
        """
        self.pack_name = pack_name
        self.country_code = country_code
        self.gv = gv
        self.__files: dict[str, GameFile] = {}
        self.loaded = False
        self.modified = False
        self.enc_path: Optional[tbcml.Path] = None
        self.key: Optional[str] = None
        self.iv: Optional[str] = None
        self.list_map: dict[str, tuple[int, int]] = {}

    def check_file(self, file_name: str) -> bool:
        if not self.list_map or not self.loaded:
            return file_name in self.__files
        return file_name in self.list_map

    def get_file(self, file_name: str) -> Optional[GameFile]:
        self.load_files()

        return self.__files.get(file_name)

    def get_files(self) -> list[GameFile]:
        self.load_files()

        return list(self.__files.values())

    @staticmethod
    def get_lang(pack_name: str) -> Optional["tbcml.Language"]:
        parts = pack_name.split("_")
        if len(parts) == 1:
            return None
        lang_str = parts[-1]
        if lang_str == "en":
            return None

        return tbcml.Language(lang_str)

    def add_file(self, file: "GameFile"):
        """Add a file to the pack.

        Args:
            file (GameFile): The file to add.
        """
        self.load_files()
        self.__files[file.file_name] = file

    def add_files(self, files: list["GameFile"]):
        """Add multiple files to the pack.

        Args:
            files (list[GameFile]): The files to add.
        """
        for file in files:
            self.add_file(file)

    def set_files(self, files: dict[str, "GameFile"]):
        """Set the files in the pack.

        Args:
            files (dict[str, GameFile]): The files to set.
        """
        self.__files = files

    def clear_files(self):
        """Clear the files in the pack."""
        self.__files = {}

    def remove_file(self, file_name: str):
        """Remove a file from the pack.

        Args:
            file_name (str): The name of the file to remove.
        """
        self.load_files()
        self.__files.pop(file_name)

    def set_modified(self, modified: bool):
        """Set the modified status of the pack.

        Args:
            modified (bool): The modified status of the pack.
        """
        self.modified = modified

    @staticmethod
    def is_server_pack(pack_name: str) -> bool:
        """Check if a pack is a server pack.

        Args:
            pack_name (str): The name of the pack.

        Returns:
            bool: True if the pack is a server pack, False otherwise.
        """
        return "Server" in pack_name

    @staticmethod
    def get_gv(pack_name: str) -> Optional[int]:
        parts = pack_name.split("_")
        if len(parts) == 1 and not PackFile.is_server_pack(pack_name):
            return (ord(parts[0][0].upper()) - 65) * 100
        if len(parts) < 3:
            return None
        gv_part = parts[1]
        sub_gv = parts[2]
        if not gv_part.isdigit():
            return None
        if sub_gv.isdigit():
            return int(gv_part) * 100 + int(sub_gv)
        return int(gv_part) * 100

    @staticmethod
    def is_image_data_local_pack(pack_name: str) -> bool:
        """Check if a pack is ImageDataLocal. This pack is not encrypted for some reason.

        Args:
            pack_name (str): The name of the pack.

        Returns:
            bool: True if the pack is ImageDataLocal, False otherwise.
        """
        return "imagedatalocal" in pack_name.lower()

    @staticmethod
    def get_cipher(
        cc: "tbcml.CountryCode",
        pack_name: str,
        gv: "tbcml.GameVersion",
        force_server: bool = False,
        key: Optional[str] = None,
        iv: Optional[str] = None,
    ) -> "tbcml.AesCipher":
        """Get the cipher for a pack.

        Args:
            cc (country_code.CountryCode): The country code of the game data.
            pack_name (str): The name of the pack.
            gv (game_version.GameVersion): The game version.

        Returns:
            crypto.AesCipher: The cipher for the pack.
        """
        return tbcml.AesCipher.get_cipher_from_pack(
            cc, pack_name, gv, force_server, key, iv
        )

    def set_file(self, file_name: str, file_data: "tbcml.Data") -> Optional[GameFile]:
        """Set a file in the pack.

        Args:
            file_name (str): The name of the file.
            file_data (tbcml.Data): The data of the file.

        Returns:
            Optional[GameFile]: The file if it exists, None otherwise.
        """
        file = self.get_file(file_name)
        if file is None:
            file = GameFile(
                None,
                file_name,
                self.pack_name,
                self.country_code,
                self.gv,
                dec_data=file_data,
            )
            self.add_file(file)
        else:
            file.dec_data = file_data
        return file

    @staticmethod
    def convert_pack_name_server_local(pack_name: str) -> str:
        """Convert a server pack name to a local pack name.

        Args:
            pack_name (str): The name of the pack.

        Returns:
            str: The converted pack name.
        """
        is_lang = False
        parts = pack_name.split("_")
        if len(parts) >= 3:
            if parts[-1] != "en":
                is_lang = True
                pack_name = f"{parts[0]}_{parts[-1]}"
            else:
                pack_name = parts[0]
        packs = [
            "MapServer",
            "NumberServer",
            "UnitServer",
            "ImageServer",
            "ImageDataServer",
        ]
        if is_lang:
            for i, pack in enumerate(packs):
                packs[i] += f"_{parts[-1]}"

        file_name = pack_name
        for pack in packs:
            if pack in file_name:
                file_name = pack.replace("Server", "Local")
                break
        return file_name

    def create_list_map(self, list_file: "tbcml.CSV"):
        total_files = int(list_file.lines[0][0])
        for i in range(total_files):
            line = list_file.lines[i + 1]
            tp = (int(line[1]), int(line[2]))
            self.list_map[line[0]] = tp

    @staticmethod
    def from_pack_file(
        enc_list_data: "tbcml.Data",
        enc_pack_path: "tbcml.Path",
        country_code: "tbcml.CountryCode",
        pack_name: str,
        gv: "tbcml.GameVersion",
        key: Optional[str] = None,
        iv: Optional[str] = None,
    ) -> Optional["PackFile"]:
        """Create a PackFile from a pack file.

        Args:
            enc_list_data (tbcml.Data): Encrypted list data.
            enc_pack_path (tbcml.Path): Path to encrypted pack data.
            country_code (country_code.CountryCode): The country code of the game data.
            pack_name (str): The name of the pack.
            gv (game_version.GameVersion): The game version.

        Returns:
            Optional[PackFile]: The PackFile if it was created successfully, None otherwise.
        """
        list_key = b"b484857901742afc"
        ls_dec_data = tbcml.AesCipher(list_key).decrypt(enc_list_data)
        ls_data = tbcml.CSV(ls_dec_data)

        pack_file = PackFile(pack_name, country_code, gv)
        pack_file.create_list_map(ls_data)
        pack_file.enc_path = enc_pack_path
        pack_file.key = key
        pack_file.iv = iv

        return pack_file

    def load_files(self):
        if self.enc_path is None or self.loaded:
            return
        path = self.enc_path.path
        with open(path, "rb") as f:
            for file_name, (start, size) in self.list_map.items():
                f.seek(start, 0)
                data = f.read(size)
                self.__files[file_name] = GameFile(
                    tbcml.Data(data),
                    file_name,
                    self.pack_name,
                    self.country_code,
                    self.gv,
                    key=self.key,
                    iv=self.iv,
                )
        self.loaded = True

    def to_pack_list_file(
        self,
        key: Optional[str] = None,
        iv: Optional[str] = None,
    ) -> tuple[str, "tbcml.Data", "tbcml.Data"]:
        """Convert the pack object to a pack file and a list file.

        Returns:
            tuple[str, tbcml.Data, tbcml.Data]: The pack name, encrypted pack data, and encrypted list data.
        """
        self.load_files()
        ls_data = tbcml.CSV()
        ls_data.lines.append([str(len(self.get_files()))])
        offset = 0
        pack_data_ls: list[tbcml.Data] = []
        for file in self.get_files():
            data = file.encrypt(key=key, iv=iv)
            ls_data.lines.append([file.file_name, str(offset), str(len(data))])
            pack_data_ls.append(data)
            offset += len(data)
        pack_data = tbcml.Data.from_many(pack_data_ls)
        ls_data = ls_data.to_data().pad_pkcs7()
        ls_data = tbcml.AesCipher(
            key=(
                tbcml.Hash(tbcml.HashAlgorithm.MD5)
                .get_hash(tbcml.Data("pack"), 8)
                .to_hex()
            ).encode("utf-8")
        ).encrypt(ls_data)
        return self.pack_name, pack_data, ls_data

    def extract(self, path: "tbcml.Path", encrypt: bool = False) -> "tbcml.Path":
        """Extract the pack as separate files into a directory.

        Args:
            path (tbcml.Path): The path to extract the pack to.

        Returns:
            tbcml.Path: the path of the pack folder
        """
        path = path.add(self.pack_name)
        path.generate_dirs()
        for file in self.get_files():
            file.extract(path, encrypt)
        return path


class GamePacks:
    """A class to represent the game packs."""

    def __init__(
        self,
        packs: dict[str, PackFile],
        country_code: "tbcml.CountryCode",
        gv: "tbcml.GameVersion",
        lang: Optional["tbcml.Language"] = None,
    ):
        """Create a GamePacks object.

        Args:
            packs (dict[str, PackFile]): The packs.
            country_code (country_code.CountryCode): The country code of the game data.
            gv (game_version.GameVersion): The game version.
        """
        self.packs = packs
        self.country_code = country_code
        self.gv = gv
        self.lang = lang

        self.modified_packs: dict[str, bool] = {}
        self.csv_cache: dict[str, tbcml.CSV] = {}
        self.modified_csv_cache: dict[str, tbcml.CSV] = {}
        self.cache: dict[str, GameFile] = {}

        self.logging = False

        self.log: dict[str, tbcml.Data] = {}

        self.init_data()

    def get_log(self):
        self.apply_all_csvs()
        return self.log

    def set_log_enabled(self, enabled: bool):
        self.logging = enabled

    def clear_log(self):
        self.log = {}

    def init_data(self):
        """Initialize the data objects."""

        self.localizable = tbcml.Localizable()
        self.localizable.read(self)

    def get_lang(self) -> str:
        return self.localizable.get_lang()

    def get_pack(self, pack_name: str) -> Optional["PackFile"]:
        """Get a pack from the game packs.

        Args:
            pack_name (str): The name of the pack.

        Returns:
            Optional[PackFile]: The pack if it exists, None otherwise.
        """
        return self.packs.get(pack_name, None)

    def get_csv(
        self,
        file_name: str,
        delimeter: Optional[Union["tbcml.Delimeter", str]] = ",",
        country_code: Optional["tbcml.CountryCode"] = None,
        show_error: bool = False,
        use_cache: bool = True,
        update_cache: bool = True,
        remove_padding: bool = True,
        remove_comments: bool = True,
        remove_empty: bool = True,
    ) -> Optional["tbcml.CSV"]:
        if use_cache:
            csv = self.csv_cache.get(file_name)
            if csv is not None:
                return csv.copy()
        if country_code is not None:
            delimeter = tbcml.Delimeter.from_country_code_res(country_code)
        if delimeter is None:
            raise ValueError("delimeter and country_code cannot both be None!")
        file = self.find_file(file_name, show_error)
        if file is None:
            return
        csv = tbcml.CSV(
            file.dec_data,
            delimeter=delimeter,
            remove_padding=remove_padding,
            remove_comments=remove_comments,
            remove_empty=remove_empty,
        )
        if update_cache:
            self.csv_cache[file_name] = csv.copy()

        return csv

    def set_csv(
        self,
        file_name: str,
        csv: Optional["tbcml.CSV"] = None,
        update_cache: bool = True,
    ) -> Optional["GameFile"]:
        if csv is None:
            return None

        if update_cache:
            self.csv_cache[file_name] = csv.copy()
            self.modified_csv_cache[file_name] = csv.copy()
        #   return None

        return self.set_file(file_name, csv.to_data())

    def apply_all_csvs(self):
        for file_name, csv in self.modified_csv_cache.items():
            self.set_file(file_name, csv.to_data())

    def get_img(
        self, file_name: str, show_error: bool = False
    ) -> Optional["tbcml.BCImage"]:
        file = self.find_file(file_name, show_error)
        if file is None:
            return None
        return tbcml.BCImage(file.dec_data.to_base_64())

    def set_img(
        self, file_name: str, img: Optional["tbcml.BCImage"]
    ) -> Optional["GameFile"]:
        if img is None:
            return None
        file = self.set_file(file_name, img.to_data())
        return file

    def find_file(
        self,
        file_name: str,
        show_error: bool = False,
    ) -> Optional["GameFile"]:
        """Find a file in the game packs.

        Args:
            file_name (str): The name of the file.
            show_error (bool, optional): Whether to show an error if the file is not found. Defaults to True.

        Returns:
            Optional[GameFile]: The file if it exists, None otherwise.
        """
        file = self.cache.get(file_name)
        if file is not None:
            return file
        found_files: list[GameFile] = []
        for pack in self.packs.values():
            file = pack.get_file(file_name)
            if file is None:
                continue
            file_lang = PackFile.get_lang(file.pack_name)
            if file_lang is not None and len(found_files) > 0:
                if self.lang != file_lang:
                    continue
            found_files.append(file)

        if len(found_files) == 0:
            if show_error:
                print(f"Could not find file {file_name}")
            else:
                return None
        elif len(found_files) == 1:
            self.cache[file_name] = found_files[0]
            return found_files[0]
        else:
            lang_packs: list[GameFile] = []
            for file in found_files:
                if PackFile.get_lang(file.pack_name) == self.lang:
                    lang_packs.append(file)

            if not lang_packs:
                return found_files[0]

            gv_packs: dict[int, GameFile] = {}
            for file in lang_packs:
                gv = PackFile.get_gv(file.pack_name)
                if gv is None:
                    continue
                gv_packs[gv] = file

            gv_packs_sorted = sorted(gv_packs.items(), key=lambda item: item[0])

            if len(lang_packs) == 1:
                self.cache[file_name] = lang_packs[0]
                return lang_packs[0]
            else:
                for file in lang_packs:
                    if not PackFile.is_server_pack(file.pack_name):
                        self.cache[file_name] = file
                        return file
                if not gv_packs_sorted:
                    self.cache[file_name] = lang_packs[0]
                    return lang_packs[0]

                self.cache[file_name] = gv_packs_sorted[-1][1]
                return gv_packs_sorted[-1][1]

    def to_packs_lists(
        self,
        key: Optional[str] = None,
        iv: Optional[str] = None,
    ) -> list[tuple[str, "tbcml.Data", "tbcml.Data"]]:
        """Convert the game packs to a list of pack lists.

        Returns:
            list[tuple[str, tbcml.Data, tbcml.Data]]: The pack lists. The first element is the pack name, the second is the encrypted pack data, the third is the encrypted list data.
        """
        self.apply_all_csvs()
        packs_lists: list[tuple[str, "tbcml.Data", "tbcml.Data"]] = []
        should_reencrypt = (
            key is not None or iv is not None
        ) and self.gv >= tbcml.GameVersion.from_string("8.9.0")
        for pack_name, pack in self.packs.items():
            if pack_name in self.modified_packs or pack.modified or should_reencrypt:
                if pack.is_server_pack(pack_name):
                    continue
                packs_lists.append(pack.to_pack_list_file(key, iv))
        return packs_lists

    def to_java_name(self, name: str) -> str:
        """Convert a name to a java name.

        Args:
            name (str): The name to convert.

        Returns:
            str: The converted name.
        """
        return name.lower() + "1"

    def get_pack_gv(self, pack_name: str) -> Optional["PackFile"]:
        """Get a pack from the game packs.

        Args:
            pack_name (str): The name of the pack.

        Returns:
            Optional[PackFile]: The pack if it exists, None otherwise.
        """
        if not pack_name.endswith("1"):
            pack_name = self.to_java_name(pack_name) if self.gv.is_java() else pack_name
        return self.get_pack(pack_name)

    def set_file(self, file_name: str, data: "tbcml.Data") -> Optional["GameFile"]:
        """Set a file in the game packs.

        Args:
            file_name (str): The name of the file.
            data (tbcml.Data): The data of the file.

        Raises:
            FileNotFoundError: If the file is not found.

        Returns:
            Optional[GameFile]: The file if it exists, None otherwise.
        """
        if not file_name.strip():
            raise FileNotFoundError("File name cannot be empty")
        if self.logging:
            self.log[file_name] = data.copy()
        file = self.find_file(file_name)
        if file is None:
            if GameFile.is_anim(file_name):
                pack = self.get_pack_gv("ImageDataLocal")
            elif file_name.endswith(".png"):
                pack = self.get_pack_gv("ImageLocal")
            else:
                pack = self.get_pack_gv("DataLocal")
            if pack is None:
                raise FileNotFoundError(f"Could not find pack for {file_name}")
            file = GameFile(
                None,
                file_name,
                pack.pack_name,
                self.country_code,
                self.gv,
                dec_data=data,
            )
        else:
            if file.dec_data == data:
                return file
        new_pack_name = PackFile.convert_pack_name_server_local(file.pack_name)
        pack = self.get_pack_gv(new_pack_name)
        if pack is None:
            raise FileNotFoundError(f"Could not find pack {new_pack_name}")
        file = pack.set_file(file_name, data)
        if file is None:
            raise FileNotFoundError(f"Could not set file {file_name}")
        self.modified_packs[file.pack_name] = True
        return file

    def set_file_from_path(self, file_path: "tbcml.Path") -> Optional["GameFile"]:
        """Set a file in the game packs from a path.

        Args:
            file_path (tbcml.Path): The path of the file.

        Returns:
            Optional[GameFile]: The file if it exists, None otherwise.
        """
        file_name = file_path.get_file_name()
        data = tbcml.Data.from_file(file_path)
        return self.set_file(file_name, data)

    def set_files_from_folder(self, folder_path: "tbcml.Path") -> None:
        """Set a file in the game packs from a folder.

        Args:
            folder_path (tbcml.Path): The path of the folder.
        """
        for file_path in folder_path.get_files():
            self.set_file_from_path(file_path)

    @staticmethod
    def from_pkg(
        apk: "tbcml.PKG", lang: Optional["tbcml.Language"] = None
    ) -> "GamePacks":
        """Create a GamePacks object from a package.

        Args:
            apk (tbcml.PKG): The pkg.

        Returns:
            GamePacks: The GamePacks object.
        """
        return apk.get_game_packs(lang)

    def extract(
        self,
        path: "tbcml.PathStr",
        clear: bool = False,
        only_local: bool = False,
    ):
        """Extract the game packs to a path.

        Args:
            path (tbcml.Path): The path.
            clear (bool, optional): Whether to clear the path before extracting. Defaults to False.
            only_local (bool, optional): Whether to only extract local packs. Defaults to False.
        """
        self.apply_all_csvs()
        path = tbcml.Path(path)
        if clear:
            path.remove()
        for pack in self.packs.values():
            if only_local:
                if pack.is_server_pack(pack.pack_name):
                    continue
            pack.extract(path)

    def apply_mods(self, mods: list["tbcml.Mod"]):
        if not mods:
            return
        for mod in mods:
            mod.apply_to_game_data(self)

    def copy(self) -> "GamePacks":
        """Deep copy the game packs.

        Returns:
            GamePacks: The copied game packs.
        """
        data = copy.deepcopy(self)
        return data
