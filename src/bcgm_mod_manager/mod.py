import json
import os
import shutil
import struct
from typing import Any, Optional
from Cryptodome.Cipher import AES
from . import helper


class File:
    """
    File class for the bcgm_mod_manager package
    """

    def __init__(
        self,
        name: str,
        file_data: bytes,
        packname: str,
        exclude: bool = False,
        overwritable: bool = False,
    ) -> None:
        """
        Initialize a File object

        Args:
            name (str): Name of file
            file_data (bytes): Bytes of file data
            packname (str): Name of pack
            exclude (bool, optional): Exclude from mod log. Defaults to False.
            overwritable (bool, optional): Is the file overwritable. Defaults to False.
        """
        self.name = os.path.basename(name)
        self.data = file_data
        self.packname = packname
        self.exclude = exclude
        self.overwritable = overwritable

    def read(self) -> bytes:
        """
        Read the file data

        Returns:
            bytes: File data
        """
        return self.data

    def write(self, data: bytes) -> None:
        """
        Write data to file

        Args:
            data (bytes): Data to write to file
        """
        self.data = data

    def add_pkcs7_padding(self) -> bytes:
        """
        Add PKCS#7 padding to data

        Args:
            data (bytes): Data to add padding to

        Returns:
            bytes: Data with padding
        """
        if not self.data:
            return helper.add_pkcs7_padding(self.data)
        return helper.add_pkcs7_padding(helper.remove_pkcs7_padding(self.data))

    def get_cipher(self, is_jp: bool) -> Any:
        """
        Get the aes object for the file

        Args:
            is_jp (bool): Is the file a JP file

        Returns:
            Any: Aes object
        """
        return helper.get_aes(is_jp, self.packname)

    def encrypt(self, is_jp: bool) -> bytes:
        """
        Encrypt the file data

        Returns:
            bytes: Encrypted file data
        """

        if "imagedatalocal" in self.name:
            return self.data
        cipher = self.get_cipher(is_jp)
        return cipher.encrypt(self.add_pkcs7_padding())

    def decrypt(self, is_jp: bool) -> bytes:
        """
        Decrypt the file data

        Returns:
            bytes: Decrypted file data
        """
        if "imagedatalocal" in self.name:
            return self.data
        cipher = self.get_cipher(is_jp)
        return cipher.decrypt(self.data)

    def export(self) -> bytes:
        """
        Export the mod as a file

        Returns:
            bytes: File data
        """
        json_data = {
            "file_name": self.name,
            "pack_name": self.packname,
            "data_len": len(self.data),
            "exclude": self.exclude,
            "overwritable": self.overwritable,
        }
        json_data = json.dumps(json_data).encode("utf-8")
        data = struct.pack("<I", len(json_data))
        data += json_data
        data += self.data
        return data

    def unpack(self, file_path: str) -> None:
        """
        Unpack the mod file to the given path

        Args:
            file_path (str): Path to unpack to
        """
        helper.write_file_bytes(file_path, self.data)


class Mod:
    """
    Mod object
    """

    def __init__(
        self,
        name: str,
        author: str,
        description: str,
        game_version: int,
        country_code: str,
        files: Optional[dict[str, File]] = None,
        create_mod_info: bool = True,
    ) -> None:
        """
        Initialize a Mod object

        Args:
            name (str): Name of mod
            author (str): Author of mod
            description (str): Description of mod
            game_version (int): Game version of mod
            country_code (str): Country code of mod
            files (Optional[dict[str, File]], optional): Files in mod. Defaults to None.
            create_mod_info (bool, optional): Whether or not to create mod info. Defaults to True.
        """
        self.name = name
        self.author = author
        self.description = description
        self.game_version = game_version
        self.country_code = country_code
        self.do_mod_info = create_mod_info
        self.files: dict[str, File] = {}
        if files is not None:
            self.files = files
            self.add_padding()

    def add_file(self, file_path: str, packname: str, exlude: bool = False) -> None:
        """
        Add a file to the mod

        Args:
            file_path (str): Path to file to add
            packname (str): Name of pack
            exlude (bool, optional): Exclude from mod log. Defaults to False.
        """
        file_data = helper.read_file_bytes(file_path)
        self.add_file_from_bytes(file_data, file_path, packname, exlude)
        self.add_padding()

    def add_files(self, file_paths: list[str], packname: str) -> None:
        """
        Add files to the mod

        Args:
            file_paths (list[str]): Paths to files to add
            packname (str): Name of pack
        """
        for file_path in file_paths:
            self.add_file(file_path, packname)
        self.add_padding()

    def add_file_from_bytes(
        self,
        file_data: bytes,
        file_name: str,
        pack_name: str,
        exclude: bool = False,
        overwritable: bool = False,
    ) -> None:
        """
        Add a file to the mod from bytes

        Args:
            file_data (bytes): Bytes of file data
            file_name (str): Name of file
            pack_name (str): Name of pack
            exclude (bool, optional): Exclude from mod log. Defaults to False.
            overwritable (bool, optional): Is the file overwritable. Defaults to False.
        """
        self.files[file_name] = File(
            file_name, file_data, pack_name, exclude, overwritable
        )
        self.files[file_name].add_pkcs7_padding()

    def add_dir(self, dir_path: str, packname: str) -> None:
        """
        Add a directory to the mod

        Args:
            dir_path (str): Path to directory to add
            packname (str): Name of pack
        """
        """Add all files in a directory"""

        for root, _, files in os.walk(dir_path):
            for file in files:
                self.add_file(os.path.join(root, file), packname)

    def get_files(self) -> dict[str, File]:
        """
        Get all files in the mod

        Returns:
            dict[str, File]: Files in mod
        """
        return self.files

    def get_file_names(self) -> list[str]:
        """
        Get all file names in the mod

        Returns:
            list[str]: File names in mod
        """
        return [file.name for file in self.files.values()]

    def get_file_data(self) -> list[bytes]:
        """
        Get all file data in the mod

        Returns:
            list[bytes]: File data in mod
        """
        return [file.data for file in self.files.values()]

    def get_file_count(self) -> int:
        """
        Get the number of files in the mod

        Returns:
            int: Number of files in mod
        """
        return len(self.files)

    def get_file_sizes(self) -> list[int]:
        """
        Get the sizes of all files in the mod

        Returns:
            list[int]: File sizes in mod
        """
        return [len(file.data) for file in self.files.values()]

    def get_file_by_name(self, name: str) -> Optional[File]:
        """
        Get a file by name

        Args:
            name (str): Name of file to get

        Returns:
            Optional[File]: File with given name
        """
        return self.files.get(name)

    def get_files_by_packname(self, packname: str) -> list[File]:
        """
        Get all files in a pack

        Args:
            packname (str): Name of pack to get files from

        Returns:
            list[File]: Files in pack
        """
        return [file for file in self.files.values() if file.packname == packname]

    def get_all_unique_pack_names(self) -> list[str]:
        """
        Get all unique pack names in the mod

        Returns:
            list[str]: Unique pack names in mod
        """
        return list(set([file.packname for file in self.files.values()]))

    def is_jp(self) -> bool:
        """
        Check if the mod is jp

        Returns:
            bool: True if jp, False if not
        """
        if self.country_code == "jp" or self.country_code == "ja":
            return True
        else:
            return False

    def create_list_files(self) -> dict[str, bytes]:
        """
        Creates an encrypted .list file of the mod

        Returns:
            dict[str, bytes]: Dictionary of .list file data
        """
        packs = self.get_all_unique_pack_names()
        pack_data: dict[str, bytes] = {}
        for pack in packs:
            data: list[Any] = []
            files = self.get_files_by_packname(pack)
            data = [len(files)]
            offset = 0
            for file in files:
                data.append([file.name, offset, len(file.data)])
                offset += len(file.data)
            list_data = helper.list_to_csv(data)
            list_data = helper.add_pkcs7_padding(list_data.encode("utf-8"))

            key = helper.get_md5("pack")[:16].encode("utf-8")
            cipher = AES.new(key, AES.MODE_ECB)  # type: ignore
            pack_data[pack] = cipher.encrypt(list_data)
        return pack_data

    def create_pack_files(self) -> dict[str, bytes]:
        """
        Creates an encrypted .pack file of the mod

        Returns:
            dict[str, bytes]: Dictionary of .pack file data
        """
        packs = self.get_all_unique_pack_names()
        pack_data: dict[str, bytes] = {}
        for pack in packs:
            data = b""
            for file in self.get_files_by_packname(pack):
                data += file.encrypt(self.is_jp())
            pack_data[pack] = data
        return pack_data

    def create_game_files(self) -> dict[str, tuple[bytes, bytes]]:
        """
        Creates a encrypted .pack and .list file of the mod

        Returns:
            dict[str, tuple[bytes, bytes]]: Dictionary of .pack and .list file data
        """
        game_files: dict[str, tuple[bytes, bytes]] = {}
        pack_files = self.create_pack_files()
        list_files = self.create_list_files()
        for pack, list in zip(pack_files, list_files):
            game_files[pack] = (pack_files[pack], list_files[list])
        return game_files

    def write_game_files(self, path: str) -> None:
        """
        Writes a encrypted .pack and .list file of the mod to a path

        Args:
            path (str): Path to write files to
        """
        game_files = self.create_game_files()
        helper.check_dir(path)
        for pack, data in game_files.items():
            helper.write_file_bytes(os.path.join(path, pack + ".pack"), data[0])
            helper.write_file_bytes(os.path.join(path, pack + ".list"), data[1])

    def encrypt(self) -> list[bytes]:
        """
        Encrypts all the files the mod

        Returns:
            list[bytes]: Encrypted files
        """
        self.add_padding()
        return [file.encrypt(self.is_jp()) for file in self.files.values()]

    def decrypt(self) -> list[bytes]:
        """
        Decrypts all the files the mod

        Returns:
            list[bytes]: Decrypted files
        """
        return [file.decrypt(self.is_jp()) for file in self.files.values()]

    def export(self) -> bytes:
        """
        Exports the mod to a bytes object

        Returns:
            bytes: Exported mod
        """
        json_data = {
            "mod_name": self.name,
            "author": self.author,
            "description": self.description,
            "game_version": self.game_version,
            "country_code": self.country_code,
            "file_count": self.get_file_count(),
        }
        data = Mod.get_valid_str().encode("utf-8")
        js_data = json.dumps(json_data).encode("utf-8")
        data += struct.pack("<I", len(js_data))
        data += js_data
        for file in self.files.values():
            data += file.export()
        return data

    def export_to_file(self, path: str) -> None:
        """
        Exports the mod to a file

        Args:
            path (str): Path to write mod to
        """
        helper.check_dir(path)
        path = os.path.join(path, self.author + "-" + self.name + Mod.get_extension())
        helper.write_file_bytes(path, self.export())

    def add_padding(self) -> None:
        """
        Adds padding to all files in the mod
        """
        for file in self.files.values():
            file.data = file.add_pkcs7_padding()

    def import_pack(
        self, pack_file_path: str, exclude_all: bool = False, pack_name: str = ""
    ) -> None:
        """
        Imports a pack file into the mod

        Args:
            pack_file_path (str): Path to pack file
            exclude_all (bool, optional): If True, all files in the pack will be excluded from the mod log. Defaults to False.
            pack_name (str, optional): Name of pack to import. Defaults to "".
        """
        files = self.load_from_pack(
            pack_file_path,
            self.is_jp(),
            self.name,
            self.author,
            self.description,
            self.game_version,
            self.country_code,
            exclude_all,
            pack_name,
        ).files
        for file in files.values():
            self.files[file.name] = file

    def import_mod_from_file(self, mod_file_path: str) -> None:
        """
        Imports a mod file into the mod

        Args:
            mod_file_path (str): Path to mod file
        """
        for file in self.load_from_mod_file(mod_file_path).files.values():
            self.files[file.name] = file

    def import_mod(self, new_mod: "Mod") -> None:
        """
        Imports a mod into the mod

        Args:
            new_mod (Mod): Mod to import
        """
        for file in new_mod.files.values():
            self.files[file.name] = file

    def unpack(self, file_path: str) -> None:
        """
        Unpacks each mod into a folder

        Args:
            file_path (str): Output path for unpacked files
        """
        if os.path.exists(file_path):
            shutil.rmtree(file_path)
        helper.check_dir(file_path)

        for file in self.files.values():
            file.unpack(os.path.join(file_path, file.name))

    @staticmethod
    def load_from_mod_file(file_path: str) -> "Mod":
        """
        Loads a mod from a file

        Args:
            file_path (str): Path to mod file

        Returns:
            Mod: Loaded mod
        """
        return Mod.load_from_bytes(helper.read_file_bytes(file_path))

    @staticmethod
    def load_from_bytes(data: bytes) -> "Mod":
        """
        Loads a mod from bytes

        Args:
            data (bytes): Bytes of mod file

        Returns:
            Mod: Loaded mod

        Raises:
            ValueError: If the mod file is invalid
        """
        if data[:3] != Mod.get_valid_str().encode("utf-8"):
            raise Exception("Invalid mod file")
        data = data[3:]

        len_json = struct.unpack("<I", data[:4])[0]
        json_data = data[4 : 4 + len_json]
        json_data = json.loads(json_data.decode("utf-8"))

        mod_name = json_data["mod_name"]
        author = json_data["author"]
        description = json_data["description"]
        game_version = json_data["game_version"]
        country_code = json_data["country_code"]
        file_count = json_data["file_count"]

        files: list[File] = []
        offset = 4 + len_json
        for _ in range(file_count):
            json_len = struct.unpack("<I", data[offset : offset + 4])[0]
            file_js_data = data[offset + 4 : offset + 4 + json_len]
            file_js_data = json.loads(file_js_data.decode("utf-8"))

            file_name = file_js_data["file_name"]
            file_size = file_js_data["data_len"]
            packname = file_js_data["pack_name"]
            exclude = file_js_data["exclude"]

            file_data = data[offset + 4 + json_len : offset + 4 + json_len + file_size]
            files.append(File(file_name, file_data, packname, exclude))

            offset += json_len + 4 + file_size

        mod = Mod(mod_name, author, description, game_version, country_code)

        for file in files:
            mod.add_file_from_bytes(file.data, file.name, file.packname, file.exclude)
        return mod

    @staticmethod
    def load_from_pack(
        pack_file_path: str,
        is_jp: bool,
        name: str,
        author: str,
        description: str,
        game_version: int,
        country_code: str,
        exlude_all: bool = False,
        pack_name: str = "",
    ) -> "Mod":
        """
        Loads a mod from a pack file

        Args:
            pack_file_path (str): Path to pack file
            is_jp (bool): Is the pack for the jp version?
            name (str): Name of the mod
            author (str): Author of the mod
            description (str): Description of the mod
            game_version (int): Game version of the mod
            country_code (str): Country code of the mod
            exlude_all (bool, optional): If True, all files in the pack will be excluded from the mod log. Defaults to False.
            pack_name (str, optional): Name of pack to import. Defaults to "".

        Returns:
            Mod: Loaded mod
        """
        helper.colored_text(
            f"Loading pack from file: &{pack_file_path}&",
            helper.Color.WHITE,
            helper.Color.GREEN,
        )
        list_path = pack_file_path.strip(".pack") + ".list"
        data = helper.read_file_bytes(list_path)
        key = helper.get_md5("pack")[:16].encode("utf-8")
        cipher = AES.new(key, AES.MODE_ECB)  # type: ignore
        data = cipher.decrypt(data)

        ls_data = helper.parse_csv(file_data=data)
        pack_data = helper.read_file_bytes(pack_file_path)
        base_name = os.path.basename(pack_file_path.strip(".pack"))
        if not pack_name:
            pack_name = os.path.basename(pack_file_path.strip(".pack"))
        files: list[File] = []
        total_files = ls_data[0][0]
        for file_data in ls_data[1 : total_files + 1]:
            file_name = file_data[0]
            file_offset = file_data[1]
            file_size = file_data[2]
            file_data = pack_data[file_offset : file_offset + file_size]
            if "imagedatalocal" in base_name.lower():
                files.append(File(file_name, file_data, pack_name, exlude_all))
            else:
                cipher = helper.get_aes(is_jp, base_name)
                files.append(
                    File(file_name, cipher.decrypt(file_data), pack_name, exlude_all)
                )
        mod = Mod(
            name,
            author,
            description,
            game_version,
            country_code,
            create_mod_info=False,
        )
        for file in files:
            mod.add_file_from_bytes(file.data, file.name, file.packname, exlude_all)
        return mod

    def format(self) -> str:
        """
        Formats the mod for output

        Returns:
            str: Formatted mod
        """
        output = ""
        output += f"Name: &{self.name}&\n"
        output += f"Author: &{self.author}&\n"
        output += f"Description: &{self.description}&\n"
        output += f"Game Version: &{self.game_version}&\n"
        output += f"Country Code: &{self.country_code}&\n"
        output += f"Files: &{len(self.files)}&\n"
        return output

    @staticmethod
    def get_extension() -> str:
        """
        Gets the extension of the mod file

        Returns:
            str: Extension of the mod file
        """
        return ".bcmod"

    @staticmethod
    def get_valid_str() -> str:
        """
        Gets the valid string for the mod file

        Returns:
            str: Valid string for the mod file
        """
        return "MOD"


class ModPack:
    """
    Class to represent a mod pack
    """

    def __init__(
        self,
        is_jp: bool,
        mods: Optional[list[Mod]] = None,
    ) -> None:
        """
        Creates a new mod pack

        Args:
            is_jp (bool): Is the pack for the jp version?
            mods (Optional[list[Mod]], optional): Mods to add to the pack. Defaults to None.
        """
        self.is_jp = is_jp
        self.mods: list[Mod] = []
        self.mod_log = f"Mods:{self.get_str_sep()}\n"
        if mods is not None:
            self.mods = mods
    
    def get_str_sep(self) -> str:
        if self.is_jp:
            return ","
        return "|"

    def add_to_mod_info(self, mod: Mod) -> None:
        """
        Adds mod info to the mod log

        Args:
            mod (Mod): Mod to add to the mod log
        """
        self.mod_log += f"{mod.name} by {mod.author}"
        if len(mod.files) < 10:
            self.mod_log += f"{self.get_str_sep()}\n{mod.description}{self.get_str_sep()}\nFiles:{self.get_str_sep()}\n"
            for file in mod.files.values():
                self.mod_log += f"-Loaded {file.name} from {file.packname}{self.get_str_sep()}\n"
        self.mod_log += f"{self.get_str_sep()}\n"
        self.write_mod_log()

    def get_mod_log_file_name(self) -> str:
        """
        Gets the name of the mod log file

        Returns:
            str: Name of the mod log file
        """
        if self.is_jp:
            return "OP_ja.csv"
        return "OP_en.csv"


    def write_mod_log(self) -> None:
        """
        Writes the mod log to OP_%s.csv
        """
        mod_log_mod = self.get_mod_by_name("mod_log")
        if mod_log_mod is not None:
            mod_log = mod_log_mod.get_file_by_name(self.get_mod_log_file_name())
            if mod_log is not None:
                mod_log.write(self.mod_log.encode("utf-8"))
            else:
                mod_log = File(
                    self.get_mod_log_file_name(),
                    self.mod_log.encode("utf-8"),
                    "DownloadLocal",
                    True,
                )
                mod_log_mod.add_file_from_bytes(
                    mod_log.data, mod_log.name, mod_log.packname, True
                )
        else:
            mod_log = File(
                self.get_mod_log_file_name(),
                self.mod_log.encode("utf-8"),
                "DownloadLocal",
                True,
            )
            mod_log_mod = Mod("mod_log", "", "", 0, "", create_mod_info=False)
            mod_log_mod.add_file_from_bytes(
                mod_log.data, mod_log.name, mod_log.packname, True
            )
            self.mods.append(mod_log_mod)

    def add_mod(self, mod: Mod) -> None:
        """
        Adds a mod to the mod pack

        Args:
            mod (Mod): Mod to add to the mod pack
        """
        self.mods.append(mod)

    def add_mods(self, mods: list[Mod]) -> None:
        """
        Adds multiple mods to the mod pack

        Args:
            mods (list[Mod]): Mods to add to the mod pack
        """
        for mod in mods:
            self.add_mod(mod)

    def get_mod_by_name(self, name: str) -> Optional[Mod]:
        """
        Gets a mod by name from the mod pack

        Args:
            name (str): Name of the mod to get from the mod pack

        Returns:
            Optional[Mod]: Mod with the given name or None if not found
        """
        for mod in self.mods:
            if mod.name == name:
                return mod
        return None

    def unpack(self, file_path: str) -> None:
        """
        Unpacks the mod pack to the given file path

        Args:
            file_path (str): File path to unpack the mod pack to
        """
        if os.path.exists(file_path):
            shutil.rmtree(file_path)
        helper.check_dir(file_path)

        for mod in self.mods:
            mod.unpack(os.path.join(file_path, mod.name))

    def create_game_files(self) -> dict[str, tuple[bytes, bytes]]:
        """
        Creates game files from the mod pack

        Returns:
            dict[str, tuple[bytes, bytes]]: Game files
        """
        temp_mod = Mod("", "", "", 0, "", self.get_all_files())
        return temp_mod.create_game_files()

    def write_game_files(self, path: str) -> None:
        """
        Writes game files to the given path

        Args:
            path (str): Path to write the game files to
        """
        # TODO: parallel
        country_code = "jp" if self.is_jp else "en"
        temp_mod = Mod("", "", "", 0, country_code, self.get_all_files())
        temp_mod.write_game_files(path)

    def get_all_files(self) -> dict[str, File]:
        """
        Gets all files from the mod pack

        Returns:
            dict[str, File]: Files
        """
        all_files: dict[str, File] = {}
        for mod in self.mods:
            for file in mod.files.values():
                all_files[file.name] = file
        return all_files

    def export(self) -> bytes:
        """
        Exports the mod pack to a bytes object

        Returns:
            bytes: Mod pack as bytes
        """
        json_data = {
            "mod_count": len(self.mods),
            "is_jp": self.is_jp,
        }
        data = ModPack.get_valid_str().encode("utf-8")
        js_data = json.dumps(json_data).encode("utf-8")
        data += struct.pack("<I", len(js_data))
        data += js_data
        for mod in self.mods:
            mod_data = mod.export()
            data += struct.pack("<I", len(mod_data))
            data += mod_data
        return data

    @staticmethod
    def get_extension() -> str:
        """
        Gets the extension of the mod pack

        Returns:
            str: Extension of the mod pack
        """
        return ".bcmodpack"

    @staticmethod
    def get_valid_str() -> str:
        """
        Gets the valid string of the mod pack

        Returns:
            str: Valid string of the mod pack
        """
        return "MODPACK"

    @staticmethod
    def load_from_mod_pack(file_path: str) -> "ModPack":
        """
        Loads a mod pack from a file path

        Args:
            file_path (str): File path to load the mod pack from

        Raises:
            Exception: If the mod pack is invalid

        Returns:
            ModPack: Mod pack
        """
        data = helper.read_file_bytes(file_path)
        if data[:7] != ModPack.get_valid_str().encode("utf-8"):
            raise Exception("Invalid mod pack")
        data = data[7:]
        len_json = struct.unpack("<I", data[:4])[0]
        json_data = json.loads(data[4 : 4 + len_json].decode("utf-8"))

        mod_count = json_data["mod_count"]
        is_jp = json_data["is_jp"]

        mods: list[Mod] = []
        offset = 4 + len_json
        for _ in range(mod_count):
            len_mod = struct.unpack("<I", data[offset : offset + 4])[0]
            mods.append(Mod.load_from_bytes(data[offset + 4 : offset + len_mod]))
            offset += len_mod + 4
        mod_pack = ModPack(is_jp)
        mod_pack.add_mods(mods)
        return mod_pack

    def mismatch_version(self) -> bool:
        """
        Checks to see if mods for jp and not for jp exist

        Returns:
            bool: True if mods for jp and not for jp exist
        """
        for mod in self.mods:
            if mod.is_jp() != self.is_jp:
                return True
        return False
