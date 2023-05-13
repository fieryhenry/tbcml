from typing import Any, Optional
from tbcml.core import io, country_code, crypto, langs, mods, game_version, game_data
import copy

from tbcml.core.game_data.cat_base import cats, enemies, item_shop


class GameFile:
    def __init__(
        self,
        dec_data: "io.data.Data",
        file_name: str,
        pack_name: str,
        cc: country_code.CountryCode,
        gv: game_version.GameVersion,
    ):
        """Initialize a new GameFile.

        Args:
            dec_data (io.data.Data): Decrypted data.
            file_name (str): Name of the file.
            pack_name (str): Name of the pack the file is in.
            cc (country_code.CountryCode): Country code of the game data.
            gv (game_version.GameVersion): Game version of the game data.
        """
        self.dec_data = dec_data
        self.file_name = file_name
        self.pack_name = pack_name
        self.cc = cc
        self.gv = gv

    def set_data(self, data: "io.data.Data"):
        """Set the decrypted data.

        Args:
            data (io.data.Data): Decrypted data.
        """
        self.dec_data = data

    @staticmethod
    def from_enc_data(
        enc_data: "io.data.Data",
        file_name: str,
        pack_name: str,
        cc: country_code.CountryCode,
        gv: game_version.GameVersion,
    ) -> "GameFile":
        """Create a GameFile from encrypted data.

        Args:
            enc_data (io.data.Data): Encrypted data.
            file_name (str): The name of the file.
            pack_name (str): The name of the pack the file is in.
            cc (country_code.CountryCode): The country code of the game data.
            gv (game_version.GameVersion): The game version of the game data.

        Returns:
            GameFile: The GameFile object.
        """
        cipher = PackFile.get_cipher(cc, pack_name, gv)
        data = cipher.decrypt(enc_data)
        try:
            data = data.unpad_pkcs7()
        except ValueError:
            pass
        return GameFile(data, file_name, pack_name, cc, gv)

    def encrypt(self) -> "io.data.Data":
        """Encrypt the decrypted data.

        Returns:
            io.data.Data: The encrypted data.
        """
        if PackFile.is_image_data_local_pack(self.pack_name):
            return self.dec_data
        cipher = PackFile.get_cipher(self.cc, self.pack_name, self.gv)
        data = self.dec_data.pad_pkcs7()
        return cipher.encrypt(data)

    def extract(self, path: "io.path.Path"):
        """Extract the decrypted data to a file.

        Args:
            path (io.path.Path): The path to extract the file to.
        """
        path = path.add(self.file_name)
        path.write(self.dec_data)

    @staticmethod
    def is_anim(file_name: str) -> bool:
        extensions = [".maanim", ".mamodel", ".imgcut"]
        return any(file_name.endswith(ext) for ext in extensions)


class PackFile:
    def __init__(
        self,
        pack_name: str,
        country_code: country_code.CountryCode,
        gv: game_version.GameVersion,
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
        self.files: dict[str, GameFile] = {}

    def add_file(self, file: GameFile):
        """Add a file to the pack.

        Args:
            file (GameFile): The file to add.
        """
        self.files[file.file_name] = file

    def add_files(self, files: list[GameFile]):
        """Add multiple files to the pack.

        Args:
            files (list[GameFile]): The files to add.
        """
        for file in files:
            self.add_file(file)

    def set_files(self, files: dict[str, GameFile]):
        """Set the files in the pack.

        Args:
            files (dict[str, GameFile]): The files to set.
        """
        self.files = files

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
        cc: country_code.CountryCode,
        pack_name: str,
        gv: game_version.GameVersion,
    ) -> crypto.AesCipher:
        """Get the cipher for a pack.

        Args:
            cc (country_code.CountryCode): The country code of the game data.
            pack_name (str): The name of the pack.
            gv (game_version.GameVersion): The game version.

        Returns:
            crypto.AesCipher: The cipher for the pack.
        """
        return crypto.AesCipher.get_cipher_from_pack(cc, pack_name, gv)

    def get_files(self) -> list[GameFile]:
        """Get all the files in the pack.

        Returns:
            list[GameFile]: The files in the pack.
        """
        return list(self.files.values())

    def set_file(self, file_name: str, file_data: "io.data.Data") -> Optional[GameFile]:
        """Set a file in the pack.

        Args:
            file_name (str): The name of the file.
            file_data (io.data.Data): The data of the file.

        Returns:
            Optional[GameFile]: The file if it exists, None otherwise.
        """
        file = self.files.get(file_name)
        if file is None:
            file = GameFile(
                file_data, file_name, self.pack_name, self.country_code, self.gv
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
        packs = [
            "MapServer",
            "NumberServer",
            "UnitServer",
            "ImageServer",
            "ImageDataServer",
        ]
        lgs = langs.Languages.get_all()
        file_name = pack_name
        for pack in packs:
            if pack in file_name:
                file_name = pack.replace("Server", "Local")
                break
        for lang in lgs:
            if f"_{lang}" in file_name:
                file_name = file_name.replace(f"_{lang}", "")
                break
        return file_name

    @staticmethod
    def from_pack_file(
        enc_list_data: "io.data.Data",
        enc_pack_data: "io.data.Data",
        country_code: country_code.CountryCode,
        pack_name: str,
        gv: game_version.GameVersion,
    ) -> Optional["PackFile"]:
        """Create a PackFile from a pack file.

        Args:
            enc_list_data (io.data.Data): Encrypted list data.
            enc_pack_data (io.data.Data): Encrypted pack data.
            country_code (country_code.CountryCode): The country code of the game data.
            pack_name (str): The name of the pack.
            gv (game_version.GameVersion): The game version.

        Returns:
            Optional[PackFile]: The PackFile if it was created successfully, None otherwise.
        """
        key = (
            crypto.Hash(crypto.HashAlgorithm.MD5)
            .get_hash(io.data.Data("pack"), 8)
            .to_hex()
        )
        ls_dec_data = crypto.AesCipher(key.encode("utf-8")).decrypt(enc_list_data)
        ls_data = io.bc_csv.CSV(ls_dec_data)

        total_files = ls_data.read_line()
        if total_files is None:
            return None
        total_files = int(total_files[0])
        pack_file = PackFile(pack_name, country_code, gv)
        files: dict[str, GameFile] = {}
        for _ in range(total_files):
            line = ls_data.read_line()
            if line is None:
                return None
            file_name = line[0]
            start = int(line[1])
            size = int(line[2])
            files[file_name] = GameFile.from_enc_data(
                enc_pack_data[start : start + size],
                file_name,
                pack_name,
                country_code,
                gv,
            )
        pack_file.set_files(files)
        return pack_file

    def to_pack_list_file(self) -> tuple[str, "io.data.Data", "io.data.Data"]:
        """Convert the pack object to a pack file and a list file.

        Returns:
            tuple[str, io.data.Data, io.data.Data]: The pack name, encrypted pack data, and encrypted list data.
        """
        ls_data = io.bc_csv.CSV()
        ls_data.lines.append([str(len(self.files))])
        offset = 0
        pack_data_ls: list[io.data.Data] = []
        for file in self.files.values():
            data = file.encrypt()
            ls_data.lines.append([file.file_name, str(offset), str(len(data))])
            pack_data_ls.append(data)
            offset += len(data)
        pack_data = io.data.Data.from_many(pack_data_ls)
        ls_data = ls_data.to_data().pad_pkcs7()
        ls_data = crypto.AesCipher(
            key=(
                crypto.Hash(crypto.HashAlgorithm.MD5)
                .get_hash(io.data.Data("pack"), 8)
                .to_hex()
            ).encode("utf-8")
        ).encrypt(ls_data)
        return self.pack_name, pack_data, ls_data

    def extract(self, path: "io.path.Path"):
        """Extract the pack as separate files into a directory.

        Args:
            path (io.path.Path): The path to extract the pack to.
        """
        path = path.add(self.pack_name)
        path.generate_dirs()
        for file in self.files.values():
            file.extract(path)


class GamePacks:
    def __init__(
        self,
        packs: dict[str, PackFile],
        country_code: country_code.CountryCode,
        gv: game_version.GameVersion,
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
        self.modified_packs: dict[str, bool] = {}
        self.init_data()

    def init_data(self):
        self.item_shop: Optional[item_shop.ItemShop] = None
        self.unit_buy: Optional[cats.UnitBuy] = None
        self.talents: Optional[cats.Talents] = None
        self.nyanko_picture_book: Optional[cats.NyankoPictureBook] = None
        self.evolve_text: Optional[cats.EvolveText] = None
        self.cats: Optional[cats.Cats] = None
        self.localizable = Localizable.from_game_data(self)
        self.enemies: Optional[enemies.Enemies] = None
        self.enemy_stats: Optional[enemies.StatsData] = None
        self.enemy_names: Optional[enemies.Names] = None

    def get_pack(self, pack_name: str) -> Optional[PackFile]:
        """Get a pack from the game packs.

        Args:
            pack_name (str): The name of the pack.

        Returns:
            Optional[PackFile]: The pack if it exists, None otherwise.
        """
        return self.packs.get(pack_name, None)

    def find_file(self, file_name: str, show_error: bool = False) -> Optional[GameFile]:
        """Find a file in the game packs.

        Args:
            file_name (str): The name of the file.
            show_error (bool, optional): Whether to show an error if the file is not found. Defaults to True.

        Returns:
            Optional[GameFile]: The file if it exists, None otherwise.
        """
        found_files: list[GameFile] = []
        for pack_name, pack in self.packs.items():
            file = pack.files.get(file_name)
            if file is None:
                continue
            split_pack_name = pack_name.split("_")
            if len(split_pack_name) > 1:
                if split_pack_name[1] in langs.Languages.get_all_strings():
                    continue
            file = pack.files.get(file_name)
            if file is None:
                continue
            found_files.append(file)
        if len(found_files) == 0:
            if show_error:
                print(f"Could not find file {file_name}")
            else:
                return None
        elif len(found_files) == 1:
            return found_files[0]
        elif len(found_files) == 2:
            if not PackFile.is_server_pack(found_files[0].pack_name):
                return found_files[0]
            elif not PackFile.is_server_pack(found_files[1].pack_name):
                return found_files[1]
            elif len(found_files[0].dec_data) > len(found_files[1].dec_data):
                return found_files[0]
            elif len(found_files[0].dec_data) < len(found_files[1].dec_data):
                return found_files[1]
            else:
                return found_files[0]
        else:
            if show_error:
                print(f"Found multiple files for {file_name}")
            else:
                return None

    def to_packs_lists(self) -> list[tuple[str, "io.data.Data", "io.data.Data"]]:
        """Convert the game packs to a list of pack lists.

        Returns:
            list[tuple[str, io.data.Data, io.data.Data]]: The pack lists. The first element is the pack name, the second is the encrypted pack data, the third is the encrypted list data.
        """
        packs_lists: list[tuple[str, "io.data.Data", "io.data.Data"]] = []
        for pack_name, pack in self.packs.items():
            if pack_name in self.modified_packs:
                packs_lists.append(pack.to_pack_list_file())
        return packs_lists

    def set_file(self, file_name: str, data: "io.data.Data") -> Optional[GameFile]:
        """Set a file in the game packs.

        Args:
            file_name (str): The name of the file.
            data (io.data.Data): The data of the file.

        Raises:
            Exception: If the pack could not be found.

        Returns:
            Optional[GameFile]: The file if it exists, None otherwise.
        """
        file = self.find_file(file_name)
        if file is None:
            if GameFile.is_anim(file_name):
                pack = self.get_pack("ImageDataLocal")
            elif file_name.endswith(".png"):
                pack = self.get_pack("ImageLocal")
            else:
                pack = self.get_pack("DataLocal")
            if pack is None:
                pack = self.get_pack("datalocal2")
            if pack is None:
                raise Exception("Could not find pack")
            file = GameFile(data, file_name, pack.pack_name, self.country_code, self.gv)
        if file.dec_data == data:
            return file
        new_pack_name = PackFile.convert_pack_name_server_local(file.pack_name)
        pack = self.get_pack(new_pack_name)
        if pack is None:
            raise Exception(f"Could not find pack {new_pack_name}")
        file = pack.set_file(file_name, data)
        if file is None:
            raise Exception(f"Could not set file {file_name}")
        self.modified_packs[file.pack_name] = True
        return file

    def set_file_from_path(self, file_path: "io.path.Path") -> Optional[GameFile]:
        """Set a file in the game packs from a path.

        Args:
            file_path (io.path.Path): The path of the file.

        Returns:
            Optional[GameFile]: The file if it exists, None otherwise.
        """
        file_name = file_path.get_file_name()
        data = io.data.Data.from_file(file_path)
        return self.set_file(file_name, data)

    def set_files_from_folder(self, folder_path: "io.path.Path") -> None:
        """Set a file in the game packs from a folder.

        Args:
            folder_path (io.path.Path): The path of the folder.
        """
        for file_path in folder_path.get_files():
            self.set_file_from_path(file_path)

    @staticmethod
    def from_apk(apk: "io.apk.Apk") -> "GamePacks":
        """Create a GamePacks object from an APK.

        Args:
            apk (io.apk.Apk): The APK.

        Returns:
            GamePacks: The GamePacks object.
        """
        packs: dict[str, PackFile] = {}
        for pack_file, list_file in apk.get_packs_lists():
            pack_data = pack_file.read()
            list_data = list_file.read()
            pack_name = list_file.get_file_name_without_extension()
            pack = PackFile.from_pack_file(
                list_data, pack_data, apk.country_code, pack_name, apk.game_version
            )
            if pack is None:
                continue
            packs[pack_name] = pack
        return GamePacks(packs, apk.country_code, apk.game_version)

    def apply_mod(self, mod: "mods.bc_mod.Mod"):
        """Apply mod data to the game packs. Should be called after all mods have been imported into a single mod.

        Args:
            mod (mods.bc_mod.Mod): The mod.
        """
        game_data.cat_base.item_shop.ItemShop.apply_mod_to_game_data(mod, self)
        game_data.cat_base.cats.Cats.apply_mod_to_game_data(mod, self)
        game_data.cat_base.enemies.Enemies.apply_mod_to_game_data(mod, self)
        Localizable.apply_mod_to_game_data(mod, self)

        for file_name, data in mod.game_files.items():
            self.set_file(file_name, data)

    def extract(self, path: "io.path.Path", clear: bool = False):
        """Extract the game packs to a path.

        Args:
            path (io.path.Path): The path.
        """
        if clear:
            path.remove()
        for pack in self.packs.values():
            pack.extract(path)

    def apply_mods(self, mods: list["mods.bc_mod.Mod"]):
        """Apply a list of mods to the game packs.

        Args:
            mods (list[mods.bc_mod.Mod]): The mods.
        """
        if not mods:
            return
        main_mod = mods[0]
        main_mod.import_mods(mods[1:])
        self.apply_mod(main_mod)

    def copy(self) -> "GamePacks":
        """Deep copy the game packs.

        Returns:
            GamePacks: The copied game packs.
        """
        data = copy.deepcopy(self)
        return data


class LocalItem:
    def __init__(self, key: str, value: str):
        """Initialize a LocalItem.

        Args:
            key (str): The key of the text.
            value (str): The text itself.
        """
        self.key = key
        self.value = value


class Localizable:
    """A class to handle the localizable.tsv file."""

    def __init__(self, localizable: dict[str, LocalItem]):
        """Initialize a Localizable object.

        Args:
            localizable (dict[str, LocalItem]): The localizable data.
        """
        self.localizable = localizable

    @staticmethod
    def from_game_data(game_data: "GamePacks") -> "Localizable":
        """Create a Localizable object from a GamePacks object.

        Args:
            game_data (GamePacks): The GamePacks object.

        Returns:
            Localizable: The Localizable object.
        """
        file_name = Localizable.get_file_name()

        file = game_data.find_file(file_name)
        if file is None:
            return Localizable.create_empty()
        csv_data = io.bc_csv.CSV(file.dec_data, "\t")

        localizable: dict[str, LocalItem] = {}
        for line in csv_data:
            try:
                key = line[0]
                value = line[1]
                localizable[key] = LocalItem(key, value)
            except IndexError:
                pass
        localizable_o = Localizable(localizable)
        game_data.localizable = localizable_o
        return localizable_o

    @staticmethod
    def get_file_name() -> str:
        """Get the file name of the localizable.tsv file.

        Returns:
            str: The file name.
        """
        return "localizable.tsv"

    def to_game_data(self, game_data: "GamePacks"):
        """Apply the localizable data to a GamePacks object.

        Args:
            game_data (GamePacks): The GamePacks object.
        """

        if len(self.localizable) == 0:
            return
        file_name = self.get_file_name()

        file = game_data.find_file(file_name)
        if file is None:
            return
        csv = io.bc_csv.CSV(file.dec_data, "\t")
        remaining_items = self.localizable.copy()
        for line in csv:
            try:
                key = line[0]
                item = self.get(key)
                if item is None:
                    continue
                line[1] = item
                del remaining_items[key]
            except IndexError:
                pass
        for item in remaining_items.values():
            csv.lines.append([item.key, item.value])
        game_data.set_file(file_name, csv.to_data())

    @staticmethod
    def create_empty() -> "Localizable":
        """Create an empty Localizable object.

        Returns:
            Localizable: The empty Localizable object.
        """
        return Localizable({})

    def get(self, key: str) -> Optional[str]:
        """Get the value of a localizable item.

        Args:
            key (str): The key of the localizable item.

        Returns:
            Optional[str]: The value of the localizable item. None if the item does not exist.
        """
        try:
            return self.localizable[key].value
        except KeyError:
            return None

    def get_lang(self) -> str:
        lang = self.get("lang")
        if lang is None:
            raise ValueError("lang is not set")
        return lang

    def set(self, key: str, value: str):
        """Set the value of a localizable item.

        Args:
            key (str): The key of the localizable item.
            value (str): The value of the localizable item.
        """
        self.localizable[key] = LocalItem(key, value)

    def remove(self, key: str):
        """Remove a localizable item.

        Args:
            key (str): The key of the localizable item to remove.
        """
        try:
            del self.localizable[key]
        except KeyError:
            pass

    def rename(self, key: str, new_key: str):
        """Rename a localizable item.

        Args:
            key (str): The key of the localizable item to rename.
            new_key (str): The new key of the localizable item.
        """
        try:
            old = self.localizable[key]
            new = LocalItem(new_key, old.value)
            del self.localizable[key]
            self.localizable[new_key] = new
        except KeyError:
            pass

    def sort(self):
        """Sort the localizable items by key alphabetically in ascending order."""

        self.localizable = dict(sorted(self.localizable.items()))

    def apply_dict(self, dict_data: dict[str, Any]):
        """Apply a dictionary to the localizable items.

        Args:
            dict_data (dict[str, Any]): The dictionary.
        """
        localizable = dict_data.get("localizable")
        if localizable is None:
            return
        current_data = self.localizable.copy()
        mod_data = mods.bc_mod.ModEditDictHandler(localizable, current_data).get_dict()
        for key, value in mod_data.items():
            self.set(key, value)

    @staticmethod
    def apply_mod_to_game_data(mod: "mods.bc_mod.Mod", game_data: "GamePacks"):
        """Apply a mod to a GamePacks object.

        Args:
            mod (mods.bc_mod.Mod): The mod.
            game_data (GamePacks): The GamePacks object.
        """
        localizable_data = mod.mod_edits.get("localizable")
        if localizable_data is None:
            return
        localizable = game_data.localizable
        localizable.apply_dict(mod.mod_edits)
        localizable.to_game_data(game_data)
