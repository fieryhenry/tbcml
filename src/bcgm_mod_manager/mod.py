import json
import os
import shutil
import struct
from typing import Any, Optional

from alive_progress import alive_bar  # type: ignore
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
        if "imagedatalocal" in self.packname.lower():
            return self.data
        if not self.data:
            return helper.add_pkcs7_padding(self.data)
        return helper.add_pkcs7_padding(helper.remove_pkcs7_padding(self.data))
    
    def remove_pkcs7_padding(self) -> bytes:
        """
        Remove PKCS#7 padding from data

        Args:
            data (bytes): Data to remove padding from

        Returns:
            bytes: Data with padding
        """
        if "imagedatalocal" in self.packname.lower():
            return self.data
        return helper.remove_pkcs7_padding(self.data)

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
        if "imagedatalocal" in self.packname.lower():
            return self.data
        cipher = self.get_cipher(is_jp)
        return cipher.encrypt(self.add_pkcs7_padding())

    def decrypt(self, is_jp: bool) -> bytes:
        """
        Decrypt the file data

        Returns:
            bytes: Decrypted file data
        """
        if "imagedatalocal" in self.packname.lower():
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
        overwritable = self.get_file_by_name(os.path.basename(file_path))
        file_data = helper.read_file_bytes(file_path)
        if overwritable is None:
            self.add_file_from_bytes(file_data, file_path, packname, exlude)
        else:
            overwritable.data = file_data

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
        self.files[file_name].data =  self.files[file_name].add_pkcs7_padding()

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
            pack_data[pack] = self.create_pack_file(pack)
        return pack_data
    
    def create_pack_file(self, pack_name: str) -> bytes:
        """
        Creates an encrypted .pack file of the mod

        Args:
            pack_name (str): Name of pack to create

        Returns:
            bytes: .pack file data
        """        
        data = b""
        for file in self.get_files_by_packname(pack_name):
            data += file.encrypt(self.is_jp())
        return data

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

    def import_files(self, files: list[File], overwite: bool = True) -> None:
        """
        Import files into the mod

        Args:
            files (list[File]): Files to import
            overwite (bool, optional): Overwrite existing files. Defaults to True.
        """
        for file in files:
            if file.name in self.files and not overwite:
                continue
            self.files[file.name] = file

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
        file_data: list[bytes] = []
        for file in self.files.values():
            file_data.append(file.export())
        data += b"".join(file_data)
        return data

    def export_to_file(self, path: str) -> None:
        """
        Exports the mod to a file

        Args:
            path (str): Path to write mod to
        """
        helper.check_dir(path)
        path = os.path.join(path, self.get_name() + Mod.get_extension())
        helper.write_file_bytes(path, self.export())

    def get_name(self) -> str:
        """
        Get the name of the mod

        Returns:
            str: Name of the mod
        """
        return self.author + "-" + self.name

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

    def import_mod(self, new_mod: "Mod", overwite: bool = True) -> None:
        """
        Imports a mod into the mod

        Args:
            new_mod (Mod): Mod to import
            overwite (bool, optional): Overwrite existing files. Defaults to True.
        """
        for file in new_mod.files.values():
            if file.name in self.files and not overwite:
                continue
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
    def get_list_data(list_path: str) -> bytes:
        """
        Gets the list data from a list file

        Args:
            list_path (str): Path to list file

        Returns:
            bytes: List data
        """
        data = helper.read_file_bytes(list_path)
        key = helper.get_md5("pack")[:16].encode("utf-8")
        cipher = AES.new(key, AES.MODE_ECB)  # type: ignore
        try:
            data = cipher.decrypt(data)
        except ValueError:
            raise Exception(f"Invalid list file: {list_path}")
        return data

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
        ls_data = helper.parse_csv(
            file_data=Mod.get_list_data(pack_file_path.replace(".pack", ".list"))
        )
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

    def format(self, indent: bool = False) -> str:
        """
        Formats the mod for printing

        Args:
            indent (bool, optional): If True, the mod will be indented. Defaults to False.

        Returns:
            str: Formatted mod
        """
        indent_text = "    " if indent else ""
        output = f"{indent_text}&Mod&\n"
        output += f"{indent_text}Name: &{self.name}&\n"
        output += f"{indent_text}Author: &{self.author}&\n"
        output += f"{indent_text}Description: &{self.description}&\n"
        output += f"{indent_text}Game Version: &{self.game_version}&\n"
        output += f"{indent_text}Country Code: &{self.country_code}&\n"
        output += f"{indent_text}Files: &{len(self.files)}&\n"
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


def generate_mod_info(mods: list[Mod], is_jp: bool, mod_log: str) -> str:
    """
    Generates mod info for the given mods

    Args:
        mods (list[Mod]): Mods to generate mod info for
        is_jp (bool): True if the mods are for jp
        mod_log (str, optional): Mod log to append to

    Returns:
        str: Mod info
    """
    mod_log += f"Total mods: {len(mods)}{get_str_sep(is_jp)}\n"
    mod_log += f"Mods:{get_str_sep(is_jp)}\n"
    for mod in mods:
        if mod.do_mod_info:
            mod_log = add_mod_to_mod_info(mod_log, mod)
    return mod_log


def add_mod_to_mod_info(mod_log: str, mod: Mod) -> str:
    """
    Adds a mod to the mod log

    Args:
        mod_log (str): Mod log
        mod (Mod): Mod to add to the mod log

    Returns:
        str: Mod log with the mod added
    """
    mod_log += f"Mod: {mod.name} by {mod.author}"
    mod_log += (
        f"{get_str_sep(mod.is_jp())}\n{mod.description}{get_str_sep(mod.is_jp())}\n"
    )
    if len(mod.files) < 10:
        mod_log += f"Files:{get_str_sep(mod.is_jp())}\n"
        for file in mod.files.values():
            mod_log += (
                f"File: {file.name} from {file.packname}{get_str_sep(mod.is_jp())}\n"
            )
    mod_log += f"{get_str_sep(mod.is_jp())}\n"
    return mod_log


def get_mod_log_file_name(is_jp: bool) -> str:
    """
    Gets the mod log file name for the given is_jp

    Args:
        is_jp (bool): Is jp

    Returns:
        str: Mod log file name
    """
    if is_jp:
        return "OP_ja.csv"
    return "OP_en.csv"


def write_mod_log(mod_log: str, is_jp: bool) -> Mod:
    """
    Writes the mod log to the mod log file

    Args:
        mod_log (str): Mod log
        is_jp (bool): Is jp

    Returns:
        Mod: Mod
    """
    mod_log_file = File(
        get_mod_log_file_name(is_jp),
        mod_log.encode("utf-8"),
        "resLocal",
        True,
    )
    country_code = "en"
    if is_jp:
        country_code = "jp"
    mod_log_mod = Mod("mod_log", "", "", 0, country_code, create_mod_info=False)
    mod_log_mod.add_file_from_bytes(
        mod_log_file.data, mod_log_file.name, mod_log_file.packname, True
    )
    return mod_log_mod


def get_str_sep(is_jp: bool) -> str:
    """
    Gets the string separator for the given is_jp

    Args:
        is_jp (bool): Is jp

    Returns:
        str: String separator
    """
    if is_jp:
        return ","
    return "|"

def has_mismatched_version(mods: list[Mod]) -> bool:
    """
    Checks if all the mods are either all jp or all en

    Args:
        mods (list[Mod]): Mods to check
    
    Returns:
        bool: True if there is a mismatched version
    """
    is_jp = mods[0].is_jp()
    for mod in mods:
        if mod.is_jp() != is_jp:
            return True
    return False

def get_all_unique_pack_names(mods: list[Mod]) -> list[str]:
    """
    Gets all unique pack names from the mods

    Args:
        mods (list[Mod]): Mods to get pack names from

    Returns:
        list[str]: Unique pack names
    """
    return list(set([file.packname for mod in mods for file in mod.files.values()]))

def write_all_game_files(mods: list[Mod], output_dir: str):
    """
    Writes all the game files to the output directory

    Args:
        mods (list[Mod]): Mods to write game files from
        output_dir (str): Output directory to write the game files to
    """
    if not mods:
        return
    new_mod = combine_mods(mods)
    new_mod.write_game_files(output_dir)

def combine_mods(mods: list[Mod]) -> Mod:
    """
    Combines the mods into a single mod

    Args:
        mods (list[Mod]): Mods to combine

    Returns:
        Mod: Combined mod
    """    
    new_mod = Mod("", "", "", 0, mods[0].country_code, create_mod_info=False)
    for mod in mods:
        new_mod.import_files(list(mod.files.values()))
    return new_mod