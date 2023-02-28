from bcml.core.io import data, path, apk
from bcml.core import crypto
import lief  # type: ignore


class Lib:
    def __init__(self, architecture: str, path: "path.Path"):
        self.architecture = architecture
        self.path = path
        self.lib = self.parse()  # type: ignore

    def parse(self) -> lief.ELF.Binary:  # type: ignore
        return lief.parse(str(self.path))  # type: ignore

    def add_library(self, library_path: "path.Path"):
        self.lib.add_library(library_path.basename())  # type: ignore

    def write(self):
        self.lib.write(str(self.path))  # type: ignore


class LibFiles:
    def __init__(self, apk: "apk.Apk"):
        self.libs_folder = apk.extracted_path.add("lib")
        self.apk = apk
        self.so_files = self.get_so_files()
        self.modified_packs = self.get_modified_packs()
        self.modified_packs_hashes = self.get_all_pack_list_hashes()

    def get_so_files(self):
        files: dict[str, data.Data] = {}
        for arc in self.libs_folder.get_dirs():
            arc_name = arc.basename()
            lib_path = self.apk.get_libnative_path(arc_name)
            files[arc_name] = lib_path.read()
        return files

    def get_modified_packs(self) -> list[path.Path]:
        return self.apk.modified_packs_path.get_files()

    def get_all_pack_list_hashes(self):
        hashes: dict[str, data.Data] = {}
        for pack in self.modified_packs:
            hashes[pack.basename()] = data.Data(
                crypto.Hash(crypto.HashAlgorithm.MD5, pack.read()).get_hash().to_hex()
            )

        return hashes

    def replace_hashes(self):
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
                original_hash = data.Data(
                    crypto.Hash(crypto.HashAlgorithm.MD5, original_Pack.read())
                    .get_hash()
                    .to_hex()
                )
                so = so.replace(original_hash, modified_hash)
            self.so_files[arc] = so

    def get_duplicate_packs_lists(self) -> dict[path.Path, list[path.Path]]:
        """
        Returns a dict where the keys are the modified packs and the values are the duplicate original packs

        Returns:
            dict[pathHandler.Path, list[pathHandler.Path]]: Duplicate packs
        """
        duplicates: dict[path.Path, list[path.Path]] = {}
        for pack in self.modified_packs:
            duplicates[pack] = []
            original_pack_path = self.apk.original_extracted_path.add("assets").add(
                pack.basename()
            )
            for original in self.apk.original_extracted_path.add("assets").get_files(
                regex=".*\\.pack|.*\\.list"
            ):
                if original.basename() == pack.basename():
                    continue
                if original_pack_path.read().to_bytes() == original.read().to_bytes():
                    duplicates[pack].append(original)

        return duplicates

    def get_original_packs_lists(self) -> list[path.Path]:
        return self.apk.original_extracted_path.add("assets").get_files(
            regex=".*\\.pack|.*\\.list"
        )

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
        self.replace_hashes()
        self.overwrite_duplicate_packs()
        self.write()
