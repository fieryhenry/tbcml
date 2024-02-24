from typing import Any, Literal, Optional, Union
import tbcml

try:
    import lief
except ImportError:
    lief = None

ARC = Union[
    Literal["x86"],
    Literal["x86_64"],
    Literal["arm64-v8a"],
    Literal["armeabi-v7a"],
    Literal["armeabi"],
    Literal["mips"],
    Literal["mips64"],
]

ARCS = Union[list[ARC], Literal["all"], Literal["32"], Literal["64"]]


def is_lief_installed() -> bool:
    return lief is not None


class Patch:
    def __init__(self):
        pass

    def apply_patch(self, lib: "Lib"): ...

    def serialize(self) -> dict[str, Any]: ...

    @staticmethod
    def deserialize(data: dict[str, Any]) -> Any: ...


class FuncPatch(Patch):
    def __init__(
        self, code: "tbcml.Data", offset: int = 0, func_name: Optional[str] = None
    ):
        self.code = code
        self.offset = offset
        self.func_name = func_name

        super().__init__()

    def apply_patch(self, lib: "Lib"):
        if self.func_name is not None:
            func = lib.get_export_function(self.func_name)
            if func is None:
                raise ValueError("Function not found")
            address = func.address + self.offset
        else:
            address = self.offset
        lib.data.set_pos(address)
        lib.data.write(self.code)
        lib.save()

    def serialize(self) -> dict[str, Any]:
        return {
            "code": self.code.to_hex(),
            "offset": self.offset,
            "func_name": self.func_name,
            "type": "func",
        }

    @staticmethod
    def deserialize(data: dict[str, Any]) -> "FuncPatch":
        return FuncPatch(
            tbcml.Data.from_hex(data["code"]),
            data.get("offset", 0),
            data.get("func_name", None),
        )


class StringReplacePatch(Patch):
    def __init__(self, orig: str, new: str, padding: str = "\x00"):
        self.orig = orig
        self.new = new
        self.padding = padding

        super().__init__()

    def apply_patch(self, lib: "Lib"):
        if len(self.new) > len(self.orig):
            raise ValueError("New string is longer than original string")
        to_add = len(self.orig) - len(self.new)
        new = self.new + self.padding * to_add
        lib.data = lib.data.replace(tbcml.Data(self.orig), tbcml.Data(new))
        lib.save()

    def serialize(self) -> dict[str, Any]:
        return {
            "orig": self.orig,
            "new": self.new,
            "padding": self.padding,
            "type": "string_replace",
        }

    @staticmethod
    def deserialize(data: dict[str, Any]) -> "StringReplacePatch":
        return StringReplacePatch(
            data.get("orig", ""), data.get("new", ""), data.get("padding", "\x00")
        )


class LibPatch:
    def __init__(
        self,
        name: str,
        architectures: ARCS,
        patches: Union[list[Patch], Patch],
        valid_ccs: Optional[list["tbcml.CC"]] = None,
        valid_game_versions: Optional[list["tbcml.GV"]] = None,
    ):
        self.name = name
        self.architectures: ARCS = architectures
        if isinstance(patches, Patch):
            patches = [patches]
        self.patches = patches

        self.valid_ccs: Optional[list[tbcml.CountryCode]] = None
        self.valid_gvs: Optional[list[tbcml.GameVersion]] = None

        if valid_ccs is not None:
            ccs: list[tbcml.CountryCode] = []
            for valid_cc in valid_ccs:
                if isinstance(valid_cc, str):
                    valid_cc = tbcml.CountryCode.from_code(valid_cc)
                ccs.append(valid_cc)
            self.valid_ccs = ccs

        if valid_game_versions is not None:
            gvs: list[tbcml.GameVersion] = []
            for valid_gv in valid_game_versions:
                if isinstance(valid_gv, str):
                    valid_gv = tbcml.GameVersion.from_string(valid_gv)
                gvs.append(valid_gv)
            self.valid_gvs = gvs

    def serialize(self):
        return {
            "name": self.name,
            "architectures": self.architectures,
            "patches": [patch.serialize() for patch in self.patches],
        }

    @staticmethod
    def deserialize(data: dict[str, Any]) -> "LibPatch":
        return LibPatch(
            data.get("name", ""),
            data.get("architectures", "all"),
            LibPatch.deserialize_patches(data.get("patches", [])),
        )

    @staticmethod
    def deserialize_patches(data: list[dict[str, Any]]) -> list[Patch]:
        patches: list[Patch] = []
        for patch in data:
            type = patch.get("type", None)
            if type == "func":
                patches.append(FuncPatch.deserialize(patch))
            elif type == "string_replace":
                patches.append(StringReplacePatch.deserialize(patch))
            else:
                raise ValueError(f"Invalid patch type '{type}'")
        return patches

    def add_to_zip(self, zip: "tbcml.Zip", index: int):
        """Adds the lib patch to a zip file.

        Args:
            zip (tbcml.Zip): The zip file to add the lib patch to
        """
        json_data = self.serialize()
        json_file = tbcml.JsonFile.from_object(json_data)
        zip.add_file(
            self.get_file_path(index),
            json_file.to_data(),
        )

    @staticmethod
    def from_zip(zip: "tbcml.Zip", path: "tbcml.Path") -> "LibPatch":
        """Gets a lib patch from a zip file.

        Args:
            zip (tbcml.Zip): The zip file to get the lib patch from
            path (tbcml.Path): patch path

        Returns:
            LibPatch: The lib patch
        """
        json_file = zip.get_file(path)
        if json_file is None:
            raise FileNotFoundError(f"Could not find lib patch '{path}'")
        json_data = tbcml.JsonFile.from_data(json_file).get_json()
        return LibPatch.deserialize(json_data)

    @staticmethod
    def get_file_path(index: int) -> "tbcml.Path":
        """Gets the file path for a lib patch.

        Args:
            index (int): index of the patch

        Returns:
            tbcml.Path: The file path for the lib patch
        """
        return tbcml.Path(tbcml.ModPath.LIB_PATCHES.value).add(f"{index}.json")

    def is_valid(self, cc: "tbcml.CountryCode", gv: "tbcml.GameVersion") -> bool:
        if self.valid_ccs is not None:
            if cc not in self.valid_ccs:
                return False
        if self.valid_gvs is not None:
            if gv not in self.valid_gvs:
                return False
        return True


class LibPatches:
    def __init__(self, lib_patches: list[LibPatch]):
        self.lib_patches = lib_patches

    @staticmethod
    def create_empty() -> "LibPatches":
        return LibPatches([])

    def serialize(self):
        return [lib_patch.serialize() for lib_patch in self.lib_patches]

    def is_empty(self):
        return len(self.lib_patches) == 0

    def add_patch(self, lib_patch: LibPatch):
        self.lib_patches.append(lib_patch)

    def add_patches(self, lib_patches: "LibPatches"):
        for lib_patch in lib_patches.lib_patches:
            self.add_patch(lib_patch)

    def validate_patches(self, cc: "tbcml.CountryCode", gv: "tbcml.GameVersion"):
        new_lib_patches: list[LibPatch] = []
        for lib_patch in self.lib_patches:
            if lib_patch.is_valid(cc, gv):
                new_lib_patches.append(lib_patch)
        self.lib_patches = new_lib_patches

    def add_to_zip(self, zip: "tbcml.Zip"):
        """Adds the lib patches to a zip file.

        Args:
            zip (tbcml.Zip): The zip file to add the lib patches to
        """
        for i, lib_patch in enumerate(self.lib_patches):
            lib_patch.add_to_zip(zip, i)

    @staticmethod
    def from_zip(zip: "tbcml.Zip") -> "LibPatches":
        """Gets the lib patches from a zip file.

        Args:
            zip (tbcml.Zip): The zip file to get the lib patches from

        Returns:
            LibPatches: The lib patches
        """
        lib_patches: list[LibPatch] = []
        for path in tbcml.Mod.get_files_in_mod_path(zip, tbcml.ModPath.LIB_PATCHES):
            lib_patches.append(LibPatch.from_zip(zip, path))
        return LibPatches(lib_patches)

    def import_patches(self, other: "LibPatches"):
        for lib_patch in other.lib_patches:
            self.add_patch(lib_patch)


class Lib:
    def __init__(self, architecture: str, path: "tbcml.Path"):
        self.architecture = architecture
        self.path = path
        self.lib = self.parse()
        self.data = path.read()

    @staticmethod
    def get_32_bit_arcs() -> list[str]:
        return ["x86", "armeabi-v7a", "armeabi", "mips"]

    @staticmethod
    def get_64_bit_arcs() -> list[str]:
        return ["x86_64", "arm64-v8a", "mips64"]

    def save(self):
        self.data.to_file(self.path)
        self.lib = self.parse()
        self.write()

    def parse(self) -> Optional["lief.ELF.Binary"]:  # type: ignore
        if lief is None:
            return None

        return lief.parse(str(self.path))  # type: ignore

    def not_installed_error(self):
        print(
            "Please install the scripting dependencies to use lib patching / frida importing (pip install -r requirements_scripting.txt)"
        )

    def add_library(self, library_path: "tbcml.Path"):
        if self.lib is None:
            self.not_installed_error()
            return

        self.lib.add_library(library_path.basename())

    def write(self):
        if self.lib is None:
            return
        self.lib.write(str(self.path))

    def search(self, search: "tbcml.Data", start: int = 0):
        return self.data.search(search, start)

    def read_int_list(self, start: int, length: int) -> list[int]:
        self.data.set_pos(start)
        return self.data.read_int_list(length)

    def get_export_functions(self) -> list[Any]:
        if self.lib is None:
            self.not_installed_error()
            return []
        return self.lib.exported_functions

    def get_export_function(self, name: str) -> Any:
        self.not_installed_error()
        funcs = self.lib.exported_functions
        for func in funcs:
            if func.name == name:
                return func

    def apply_patch(self, patch: LibPatch):
        for patch_ in patch.patches:
            patch_.apply_patch(self)


class LibFiles:
    def __init__(self, apk: "tbcml.PKG"):
        self.apk = apk
        self.so_files = self.get_so_files()
        self.modified_packs = self.get_modified_packs()
        self.modified_packs_hashes = self.get_all_pack_list_hashes()
        if self.apk.key is not None:
            self.change_key(self.apk.key)
        if self.apk.iv is not None:
            self.change_iv(self.apk.iv)

    def replace_str(self, original: str, new: str, pad: str) -> str:
        if len(new) > len(original):
            raise ValueError("New string is larger than original string")
        to_add = len(original) - len(new)
        new += pad * to_add

        for arc, so in self.so_files.items():
            so = so.replace(tbcml.Data(original), tbcml.Data(new))
            self.so_files[arc] = so

        self.write()

        return new

    def get_so_files(self):
        files: dict[str, "tbcml.Data"] = {}
        for arc, path in self.apk.get_lib_paths().items():
            files[arc] = path.read()
        return files

    def get_modified_packs(self) -> list["tbcml.Path"]:
        return self.apk.modified_packs_path.get_files()

    def get_all_pack_list_hashes(self):
        hashes: dict[str, tbcml.Data] = {}
        for pack in self.modified_packs:
            hashes[pack.basename()] = tbcml.Data(
                tbcml.Hash(tbcml.HashAlgorithm.MD5).get_hash(pack.read()).to_hex()
            )

        return hashes

    def replace_hashes_in_so(self):
        for arc, so in self.so_files.items():
            for pack_name, modified_hash in self.modified_packs_hashes.items():
                original_packs = self.get_original_packs_lists()
                original_Pack = None
                for pack in original_packs:
                    if pack.basename() == pack_name:
                        original_Pack = pack
                        break
                if original_Pack is None:
                    continue
                original_hash = tbcml.Data(
                    tbcml.Hash(tbcml.HashAlgorithm.MD5)
                    .get_hash(original_Pack.read())
                    .to_hex()
                )
                so = so.replace(original_hash, modified_hash)
            self.so_files[arc] = so

    def replace_hashes_in_smali(self):
        if isinstance(self.apk, tbcml.Ipa):
            return
        smali_handler = self.apk.get_smali_handler()
        for pack_name, modified_hash in self.modified_packs_hashes.items():
            if pack_name.endswith("1.pack") and self.apk.is_java():
                pack_name = pack_name.replace("1.pack", "2.pack")
            original_packs = self.get_original_packs_lists()
            original_Pack = None
            for pack in original_packs:
                if pack.basename() == pack_name:
                    original_Pack = pack
                    break
            if original_Pack is None:
                continue
            original_hash = tbcml.Data(
                tbcml.Hash(tbcml.HashAlgorithm.MD5)
                .get_hash(original_Pack.read())
                .to_hex()
            )
            smali_handler.replace_all_strings(
                original_hash.to_str(), modified_hash.to_str()
            )

    def get_duplicate_packs_lists(self) -> dict["tbcml.Path", list["tbcml.Path"]]:
        """
        Returns a dict where the keys are the modified packs and the values are the duplicate original packs

        Returns:
            dict[pathHandler.Path, list[pathHandler.Path]]: Duplicate packs
        """
        duplicates: dict[tbcml.Path, list[tbcml.Path]] = {}
        original_data_dict: dict[str, tbcml.Data] = {}
        for pack in self.modified_packs:
            pack_base_name = pack.basename()
            original_pack_path = self.get_pack_folder_original().add(pack_base_name)
            if pack_base_name.endswith("1.pack") and self.apk.is_java():
                original_pack_path = self.get_pack_folder_original().add(
                    pack_base_name.replace("1.pack", "2.pack")
                )
            for original in self.get_pack_folder_original().get_files(
                regex=".*\\.pack|.*\\.list"
            ):
                original_base_name = original.basename()
                if original_base_name == pack_base_name:
                    continue
                original_data = original_data_dict.get(original_base_name)
                orignal_pack_path_data = original_data_dict.get(pack_base_name)
                if original_data is None:
                    original_data = original.read()
                    original_data_dict[original_base_name] = original_data
                if orignal_pack_path_data is None:
                    orignal_pack_path_data = original_pack_path.read()
                    original_data_dict[pack_base_name] = orignal_pack_path_data

                if orignal_pack_path_data.to_bytes() == original_data.to_bytes():
                    if pack not in duplicates:
                        duplicates[pack] = []
                    duplicates[pack].append(original)

        return duplicates

    def get_original_packs_lists(self) -> list["tbcml.Path"]:
        return self.get_pack_folder_original().get_files(regex=".*\\.pack|.*\\.list")

    def get_pack_folder_original(self):
        return self.apk.get_original_pack_location()

    def write(self):
        for arc, so in self.so_files.items():
            lib_path = self.apk.get_libnative_path(arc)
            if lib_path is None:
                continue
            lib_path.write(so)

    def overwrite_duplicate_packs(self):
        duplicates = self.get_duplicate_packs_lists()
        for pack, originals in duplicates.items():
            for original in originals:
                original_path = self.apk.modified_packs_path.add(original.basename())
                original_path.write(pack.read())

    def patch(self):
        if self.apk.is_java():
            self.replace_hashes_in_smali()
        else:
            self.replace_hashes_in_so()
        self.overwrite_duplicate_packs()
        self.write()

    def change_key(self, key: str):
        orignal_key, _ = tbcml.AesCipher.get_key_iv_from_cc(self.apk.country_code)
        key1 = tbcml.Data(key[:16])
        key2 = tbcml.Data(key[16:])

        orig_key1 = tbcml.Data(orignal_key[:16])
        orig_key2 = tbcml.Data(orignal_key[16:])

        for arc, so in self.so_files.items():
            so = so.replace(orig_key1, key1)
            so = so.replace(orig_key2, key2)
            self.so_files[arc] = so

    def change_iv(self, iv: str):
        _, original_iv = tbcml.AesCipher.get_key_iv_from_cc(self.apk.country_code)
        iv1 = tbcml.Data(iv[:16])
        iv2 = tbcml.Data(iv[16:])

        orig_iv1 = tbcml.Data(original_iv[:16])
        orig_iv2 = tbcml.Data(original_iv[16:])

        for arc, so in self.so_files.items():
            so = so.replace(orig_iv1, iv1)
            so = so.replace(orig_iv2, iv2)
            self.so_files[arc] = so
