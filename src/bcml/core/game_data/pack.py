from typing import Any, Optional
from bcml.core import io, country_code, crypto, langs, mods


class GameFile:
    def __init__(
        self,
        dec_data: "io.data.Data",
        file_name: str,
        pack: "PackFile",
    ):
        self.dec_data = dec_data
        self.file_name = file_name
        self.pack = pack
        self.country_code = country_code

    def set_data(self, data: "io.data.Data"):
        self.dec_data = data

    @staticmethod
    def from_enc_data(
        enc_data: "io.data.Data",
        file_name: str,
        pack: "PackFile",
    ) -> "GameFile":
        cipher = pack.get_cipher()
        data = cipher.decrypt(enc_data)
        try:
            data = data.unpad_pkcs7()
        except ValueError:
            pass
        return GameFile(data, file_name, pack)

    def encrypt(self) -> "io.data.Data":
        if self.pack.is_image_data_local_pack():
            return self.dec_data
        cipher = self.pack.get_cipher()
        data = self.dec_data.pad_pkcs7()
        return cipher.encrypt(data)

    def extract(self, path: "io.path.Path"):
        path = path.add(self.file_name)
        path.write(self.dec_data)

    def serialize(self) -> dict[str, str]:
        return {
            "data": self.dec_data.to_base_64(),
        }

    @staticmethod
    def deserialize(
        data: dict[str, str], file_name: str, pack: "PackFile"
    ) -> "GameFile":
        return GameFile(
            io.data.Data.from_base_64(data["data"]),
            file_name,
            pack,
        )


class PackFile:
    def __init__(
        self,
        pack_name: str,
        country_code: country_code.CountryCode,
    ):
        self.pack_name = pack_name
        self.country_code = country_code
        self.files: dict[str, GameFile] = {}

    def add_file(self, file: GameFile):
        self.files[file.file_name] = file

    def add_files(self, files: list[GameFile]):
        for file in files:
            self.add_file(file)

    def set_files(self, files: dict[str, GameFile]):
        self.files = files

    def is_server_pack(self) -> bool:
        return "Server" in self.pack_name

    def is_image_data_local_pack(self) -> bool:
        return "ImageDataLocal" in self.pack_name

    def get_cipher(self) -> crypto.AesCipher:
        return crypto.AesCipher.get_cipher_from_pack(self)

    def get_file(self, file_name: str) -> Optional[GameFile]:
        return self.files.get(file_name)

    def get_files(self) -> list[GameFile]:
        return list(self.files.values())

    def set_file(self, file_name: str, file_data: "io.data.Data") -> Optional[GameFile]:
        file = self.get_file(file_name)
        if file is None:
            file = GameFile(file_data, file_name, self)
            self.add_file(file)
        else:
            file.dec_data = file_data
        return file

    def convert_pack_name_server_local(self) -> str:
        packs = [
            "MapServer",
            "NumberServer",
            "UnitServer",
            "ImageServer",
            "ImageDataServer",
        ]
        lgs = langs.Languages.get_all()
        file_name = self.pack_name
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
    ):
        key = (
            crypto.Hash(crypto.HashAlgorithm.MD5, io.data.Data("pack"))
            .get_hash(8)
            .to_hex()
        )
        ls_dec_data = crypto.AesCipher(key.encode("utf-8")).decrypt(enc_list_data)
        ls_data = io.bc_csv.CSV(ls_dec_data, remove_empty=True)

        total_files = ls_data.read_line()
        if total_files is None:
            return None
        total_files = total_files[0].to_int()
        pack_file = PackFile(pack_name, country_code)
        files: dict[str, GameFile] = {}
        for _ in range(total_files):
            line = ls_data.read_line()
            if line is None:
                return None
            file_name = line[0].to_str()
            start = line[1].to_int()
            size = line[2].to_int()
            files[file_name] = GameFile.from_enc_data(
                enc_pack_data[start : start + size],
                file_name,
                pack_file,
            )
        pack_file.set_files(files)
        return pack_file

    def to_pack_list_file(self) -> tuple[str, "io.data.Data", "io.data.Data"]:
        ls_data = io.bc_csv.CSV()
        ls_data.add_line(io.data.Data.int_list_data_list([len(self.files)]))
        offset = 0
        pack_data_ls: list[io.data.Data] = []
        for file in self.files.values():
            data = file.encrypt()
            ls_data.add_line(
                io.data.Data.string_list_data_list([file.file_name, offset, len(data)])
            )
            pack_data_ls.append(data)
            offset += len(data)
        pack_data = io.data.Data.from_many(pack_data_ls)
        ls_data = ls_data.to_data().pad_pkcs7()
        ls_data = crypto.AesCipher(
            key=(
                crypto.Hash(crypto.HashAlgorithm.MD5, io.data.Data("pack"))
                .get_hash(8)
                .to_hex()
            ).encode("utf-8")
        ).encrypt(ls_data)
        return self.pack_name, pack_data, ls_data

    def extract(self, path: "io.path.Path"):
        path = path.add(self.pack_name)
        path.generate_dirs()
        for file in self.files.values():
            file.extract(path)

    def serialize(self) -> dict[str, Any]:
        return {
            "files": {file.file_name: file.serialize() for file in self.files.values()},
        }

    @staticmethod
    def deserialize(
        data: dict[str, Any], pack_name: str, country_code: country_code.CountryCode
    ) -> Optional["PackFile"]:
        pack_file = PackFile(pack_name, country_code)
        files: dict[str, GameFile] = {}
        for file_name, file_data in data["files"].items():
            file = GameFile.deserialize(file_data, file_name, pack_file)
            files[file_name] = file
        pack_file.set_files(files)
        return pack_file


class GamePacks:
    def __init__(
        self, packs: dict[str, PackFile], country_code: country_code.CountryCode
    ):
        self.packs = packs
        self.country_code = country_code
        self.modified_packs: dict[str, bool] = {}

    def get_pack(self, pack_name: str) -> Optional[PackFile]:
        return self.packs.get(pack_name, None)

    def find_file(self, file_name: str, show_error: bool = True) -> Optional[GameFile]:
        found_files: list[GameFile] = []
        for pack_name, pack in self.packs.items():
            file = pack.get_file(file_name)
            if file is None:
                continue
            split_pack_name = pack_name.split("_")
            if len(split_pack_name) > 1:
                if split_pack_name[1] in langs.Languages.get_all_strings():
                    continue
            file = pack.get_file(file_name)
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
            if not found_files[0].pack.is_server_pack():
                return found_files[0]
            elif not found_files[1].pack.is_server_pack():
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

    def to_packs_lists(self):
        packs_lists: list[tuple[str, "io.data.Data", "io.data.Data"]] = []
        for pack_name, pack in self.packs.items():
            if pack_name in self.modified_packs:
                packs_lists.append(pack.to_pack_list_file())
        return packs_lists

    def set_file(self, file_name: str, data: "io.data.Data") -> Optional[GameFile]:
        file = self.find_file(file_name)
        if file is None:
            pack = self.get_pack("DownloadLocal")
            if pack is None:
                raise Exception(f"Could not find pack DownloadLocal")
            file = GameFile(data, file_name, pack)
        new_pack_name = file.pack.convert_pack_name_server_local()
        pack = self.get_pack(new_pack_name)
        if pack is None:
            raise Exception(f"Could not find pack {new_pack_name}")
        file = pack.set_file(file_name, data)
        if file is None:
            raise Exception(f"Could not set file {file_name}")
        self.modified_packs[file.pack.pack_name] = True
        return file

    @staticmethod
    def from_apk(apk: "io.apk.Apk"):
        packs: dict[str, PackFile] = {}
        for pack_file, list_file in apk.get_packs_lists():
            pack_data = pack_file.read()
            list_data = list_file.read()
            pack_name = list_file.get_file_name_without_extension()
            pack = PackFile.from_pack_file(
                list_data, pack_data, apk.country_code, pack_name
            )
            if pack is None:
                continue
            packs[pack_name] = pack
        return GamePacks(packs, apk.country_code)

    def apply_mod(self, mod: "mods.bc_mod.Mod"):
        mod.gamototo.to_game_data(self)
        mod.battle.to_game_data(self)
        mod.cat_base.to_game_data(self)
        mod.maps.to_game_data(self)
        mod.localizable.to_game_data(self)

    def extract(self, path: "io.path.Path"):
        for pack in self.packs.values():
            pack.extract(path)

    def apply_mods(self, mods: list["mods.bc_mod.Mod"]):
        if not mods:
            return
        main_mod = mods[0]
        main_mod.import_mods(mods[1:])
        self.apply_mod(main_mod)

    def serialize(self) -> dict[str, Any]:
        return {
            "country_code": self.country_code.get_code(),
            "packs": {
                pack_name: pack.serialize() for pack_name, pack in self.packs.items()
            },
        }

    @staticmethod
    def deserialize(data: dict[str, Any]) -> Optional["GamePacks"]:
        cc = country_code.CountryCode.from_code(data["country_code"])
        packs: dict[str, PackFile] = {}
        for pack_name, pack_data in data["packs"].items():
            pack = PackFile.deserialize(pack_data, pack_name, cc)
            if pack is None:
                return None
            packs[pack_name] = pack
        return GamePacks(packs, cc)


class LocalItem:
    def __init__(self, key: str, value: str):
        self.key = key
        self.value = value

    def get_formatted_text(self) -> str:
        return self.value.replace("<br>", "\n")

    def serialize(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "value": self.value,
        }

    @staticmethod
    def deserialize(data: dict[str, Any]) -> "LocalItem":
        return LocalItem(data["key"], data["value"])


class Localizable:
    def __init__(self, localizable: dict[str, LocalItem]):
        self.localizable = localizable

    @staticmethod
    def from_game_data(game_data: "GamePacks") -> "Localizable":
        file_name = Localizable.get_file_name()

        file = game_data.find_file(file_name)
        if file is None:
            return Localizable.create_empty()
        csv_data = io.bc_csv.CSV(file.dec_data, "\t")

        localizable: dict[str, LocalItem] = {}
        for line in csv_data:
            try:
                key = line[0].to_str()
                value = line[1].to_str()
                localizable[key] = LocalItem(key, value)
            except IndexError:
                pass
        return Localizable(localizable)

    @staticmethod
    def get_file_name() -> str:
        return "localizable.tsv"

    def to_game_data(self, game_data: "GamePacks"):
        if len(self.localizable) == 0:
            return
        file_name = self.get_file_name()

        file = game_data.find_file(file_name)
        if file is None:
            return
        csv = io.bc_csv.CSV(None, "\t")
        for item in self.localizable.values():
            csv.add_line([item.key, item.value])

        game_data.set_file(file_name, csv.to_data())

    @staticmethod
    def create_empty() -> "Localizable":
        return Localizable({})

    def serialize(self) -> dict[str, Any]:
        return {
            "localizable": {
                key: item.serialize() for key, item in self.localizable.items()
            }
        }

    @staticmethod
    def deserialize(data: dict[str, Any]) -> "Localizable":
        localizable: dict[str, LocalItem] = {}
        for key, item_data in data["localizable"].items():
            localizable[key] = LocalItem.deserialize(item_data)
        return Localizable(localizable)

    @staticmethod
    def get_json_file_name() -> "io.path.Path":
        return io.path.Path("localizable.json")

    def add_to_zip(self, zip: "io.zip.Zip"):
        json = io.json_file.JsonFile.from_json(self.serialize())
        zip.add_file(Localizable.get_json_file_name(), json.to_data())

    @staticmethod
    def from_zip(zip: "io.zip.Zip") -> "Localizable":
        json = zip.get_file(Localizable.get_json_file_name())
        if json is None:
            return Localizable.create_empty()
        return Localizable.deserialize(io.json_file.JsonFile.from_data(json).get_json())

    def import_localizable(self, localizable: "Localizable"):
        self.localizable.update(localizable.localizable)

    def get(self, key: str) -> Optional[str]:
        try:
            return self.localizable[key].value
        except KeyError:
            return None

    def set(self, key: str, value: str):
        self.localizable[key] = LocalItem(key, value)

    def remove(self, key: str):
        try:
            del self.localizable[key]
        except KeyError:
            pass

    def rename(self, key: str, new_key: str):
        try:
            old = self.localizable[key]
            new = LocalItem(new_key, old.value)
            del self.localizable[key]
            self.localizable[new_key] = new
        except KeyError:
            pass

    def sort(self):
        self.localizable = dict(sorted(self.localizable.items()))
