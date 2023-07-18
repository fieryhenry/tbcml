from typing import Any, Optional
import uuid
from tbcml import core
import lief


class Patch:
    def __init__(self):
        pass

    def apply_patch(self, lib: "Lib"):
        ...

    def serialize(self) -> dict[str, Any]:
        ...

    @staticmethod
    def deserialize(data: dict[str, Any]) -> Any:
        ...


class FuncPatch(Patch):
    def __init__(
        self, code: "core.Data", offset: int = 0, func_name: Optional[str] = None
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
            core.Data.from_hex(data["code"]),
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
        lib.data = lib.data.replace(core.Data(self.orig), core.Data(new))
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
        architecture: str,
        cc: "core.CountryCode",
        gv: "core.GameVersion",
        patches: list[Patch],
        id: str,
    ):
        self.name = name
        self.architecture = architecture
        self.cc = cc
        self.gv = gv
        self.patches = patches
        self.id = id

    @staticmethod
    def create_id() -> str:
        return str(uuid.uuid4())

    def serialize(self):
        return {
            "name": self.name,
            "architecture": self.architecture,
            "cc": self.cc.get_code(),
            "gv": self.gv.to_string(),
            "patches": [patch.serialize() for patch in self.patches],
            "id": self.id,
        }

    @staticmethod
    def deserialize(data: dict[str, Any]) -> "LibPatch":
        return LibPatch(
            data.get("name", ""),
            data.get("architecture", "x86"),
            core.CountryCode.from_code(data.get("cc", "en")),
            core.GameVersion.from_string(data.get("gv", "12.4.0")),
            LibPatch.deserialize_patches(data.get("patches", [])),
            data.get("id", LibPatch.create_id()),
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

    def add_to_zip(self, zip: "core.Zip"):
        """Adds the lib patch to a zip file.

        Args:
            zip (core.Zip): The zip file to add the lib patch to
        """
        json_data = self.serialize()
        json_file = core.JsonFile.from_object(json_data)
        zip.add_file(
            self.get_file_path(self.architecture, self.id),
            json_file.to_data(),
        )

    @staticmethod
    def from_zip(zip: "core.Zip", arc: str, id: str) -> "LibPatch":
        """Gets a lib patch from a zip file.

        Args:
            zip (core.Zip): The zip file to get the lib patch from
            arc (str): Architecture the patch is designed for
            id (str): ID of the patch

        Returns:
            LibPatch: The lib patch
        """
        json_file = zip.get_file(LibPatch.get_file_path(arc, id))
        if json_file is None:
            raise FileNotFoundError(
                f"Could not find lib patch '{id}' for architecture '{arc}'"
            )
        json_data = core.JsonFile.from_data(json_file).get_json()
        return LibPatch.deserialize(json_data)

    @staticmethod
    def get_file_path(arc: str, id: str) -> "core.Path":
        """Gets the file path for a lib patch.

        Args:
            arc (str): Architecture the patch is designed for
            id (str): ID of the patch

        Returns:
            core.Path: The file path for the lib patch
        """
        return core.Path(f"lib_patches/{arc}/{id}.json")


class LibPatches:
    def __init__(self, lib_patches: list[LibPatch]):
        self.lib_patches = lib_patches

    def serialize(self):
        return [lib_patch.serialize() for lib_patch in self.lib_patches]

    def is_empty(self):
        return len(self.lib_patches) == 0

    def add_patch(self, lib_patch: LibPatch):
        self.lib_patches.append(lib_patch)

    def add_patches(self, lib_patches: "LibPatches"):
        for lib_patch in lib_patches.lib_patches:
            self.add_patch(lib_patch)

    def is_valid_patch(
        self, patch: LibPatch, cc: "core.CountryCode", gv: "core.GameVersion"
    ):
        return patch.cc == cc and patch.gv == gv

    def validate_patches(self, cc: "core.CountryCode", gv: "core.GameVersion"):
        new_lib_patches: list[LibPatch] = []
        for lib_patch in self.lib_patches:
            if self.is_valid_patch(lib_patch, cc, gv):
                new_lib_patches.append(lib_patch)
        self.lib_patches = new_lib_patches

    def add_to_zip(self, zip: "core.Zip"):
        """Adds the lib patches to a zip file.

        Args:
            zip (core.Zip): The zip file to add the lib patches to
        """
        arcs: dict[str, list[str]] = {}
        for lib_patch in self.lib_patches:
            lib_patch.add_to_zip(zip)
            if lib_patch.architecture not in arcs:
                arcs[lib_patch.architecture] = []
            arcs[lib_patch.architecture].append(lib_patch.id)
        json_data = {"arcs": arcs}
        json_file = core.JsonFile.from_object(json_data)
        zip.add_file(
            core.Path("lib_patches/lib_patches.json"),
            json_file.to_data(),
        )

    @staticmethod
    def from_zip(zip: "core.Zip") -> "LibPatches":
        """Gets the lib patches from a zip file.

        Args:
            zip (core.Zip): The zip file to get the lib patches from

        Returns:
            LibPatches: The lib patches
        """
        json_file = zip.get_file(core.Path("lib_patches/lib_patches.json"))
        if json_file is None:
            raise FileNotFoundError("Could not find lib patches")
        json_data = core.JsonFile.from_data(json_file).get_json()
        lib_patches: list[LibPatch] = []
        for arc, names in json_data["arcs"].items():
            for name in names:
                lib_patches.append(LibPatch.from_zip(zip, arc, name))
        return LibPatches(lib_patches)

    def import_patches(self, other: "LibPatches"):
        for lib_patch in other.lib_patches:
            self.add_patch(lib_patch)


class Lib:
    def __init__(self, architecture: str, path: "core.Path"):
        self.architecture = architecture
        self.path = path
        self.lib = self.parse()
        self.data = path.read()

    def save(self):
        self.data.to_file(self.path)
        self.lib = self.parse()
        self.write()

    def parse(self) -> lief.ELF.Binary:  # type: ignore
        return lief.parse(str(self.path))  # type: ignore

    def add_library(self, library_path: "core.Path"):
        self.lib.add_library(library_path.basename())

    def write(self):
        self.lib.write(str(self.path))

    def search(self, search: "core.Data", start: int = 0):
        return self.data.search(search, start)

    def read_int_list(self, start: int, length: int) -> list[int]:
        self.data.set_pos(start)
        return self.data.read_int_list(length)

    def get_export_functions(self) -> list[Any]:
        return self.lib.exported_functions

    def get_export_function(self, name: str) -> Any:
        funcs = self.lib.exported_functions
        for func in funcs:
            if func.name == name:
                return func

    def apply_patch(self, patch: LibPatch, force: bool = False):
        if patch.architecture != self.architecture and not force:
            raise ValueError("Architecture mismatch")
        for patch_ in patch.patches:
            patch_.apply_patch(self)


class LibFiles:
    def __init__(self, apk: "core.Apk"):
        self.libs_folder = apk.extracted_path.add("lib")
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
            so = so.replace(core.Data(original), core.Data(new))
            self.so_files[arc] = so

        self.write()

        return new

    def get_so_files(self):
        files: dict[str, "core.Data"] = {}
        for arc in self.libs_folder.get_dirs():
            arc_name = arc.basename()
            lib_path = self.apk.get_libnative_path(arc_name)
            files[arc_name] = lib_path.read()
        return files

    def get_modified_packs(self) -> list["core.Path"]:
        return self.apk.modified_packs_path.get_files()

    def get_all_pack_list_hashes(self):
        hashes: dict[str, core.Data] = {}
        for pack in self.modified_packs:
            hashes[pack.basename()] = core.Data(
                core.Hash(core.HashAlgorithm.MD5).get_hash(pack.read()).to_hex()
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
                original_hash = core.Data(
                    core.Hash(core.HashAlgorithm.MD5)
                    .get_hash(original_Pack.read())
                    .to_hex()
                )
                so = so.replace(original_hash, modified_hash)
            self.so_files[arc] = so

    def replace_hashes_in_smali(self):
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
            original_hash = core.Data(
                core.Hash(core.HashAlgorithm.MD5)
                .get_hash(original_Pack.read())
                .to_hex()
            )
            smali_handler.replace_all_strings(
                original_hash.to_str(), modified_hash.to_str()
            )

    def get_duplicate_packs_lists(self) -> dict["core.Path", list["core.Path"]]:
        """
        Returns a dict where the keys are the modified packs and the values are the duplicate original packs

        Returns:
            dict[pathHandler.Path, list[pathHandler.Path]]: Duplicate packs
        """
        duplicates: dict[core.Path, list[core.Path]] = {}
        for pack in self.modified_packs:
            duplicates[pack] = []
            original_pack_path = self.get_pack_folder_original().add(pack.basename())
            if pack.basename().endswith("1.pack") and self.apk.is_java():
                original_pack_path = self.get_pack_folder_original().add(
                    pack.basename().replace("1.pack", "2.pack")
                )
            for original in self.get_pack_folder_original().get_files(
                regex=".*\\.pack|.*\\.list"
            ):
                if original.basename() == pack.basename():
                    continue
                if original_pack_path.read().to_bytes() == original.read().to_bytes():
                    duplicates[pack].append(original)

        return duplicates

    def get_original_packs_lists(self) -> list["core.Path"]:
        return self.get_pack_folder_original().get_files(regex=".*\\.pack|.*\\.list")

    def get_pack_folder_original(self):
        if self.apk.is_java():
            return self.apk.original_extracted_path.add("res").add("raw")
        else:
            return self.apk.original_extracted_path.add("assets")

    def write(self):
        for arc, so in self.so_files.items():
            lib_path = self.apk.get_libnative_path(arc)
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
        orignal_key, _ = core.AesCipher.get_key_iv_from_cc(self.apk.country_code)
        key1 = core.Data(key[:16])
        key2 = core.Data(key[16:])

        orig_key1 = core.Data(orignal_key[:16])
        orig_key2 = core.Data(orignal_key[16:])

        for arc, so in self.so_files.items():
            so = so.replace(orig_key1, key1)
            so = so.replace(orig_key2, key2)
            self.so_files[arc] = so

    def change_iv(self, iv: str):
        _, original_iv = core.AesCipher.get_key_iv_from_cc(self.apk.country_code)
        iv1 = core.Data(iv[:16])
        iv2 = core.Data(iv[16:])

        orig_iv1 = core.Data(original_iv[:16])
        orig_iv2 = core.Data(original_iv[16:])

        for arc, so in self.so_files.items():
            so = so.replace(orig_iv1, iv1)
            so = so.replace(orig_iv2, iv2)
            self.so_files[arc] = so
