from __future__ import annotations
import enum
import filecmp
from typing import Any, Callable, Sequence
import tbcml


class PkgType(enum.Enum):
    APK = enum.auto()
    IPA = enum.auto()


class Pkg:
    pkg_extension = ".zip"
    pkg_type: PkgType | None = None

    def __init__(
        self,
        game_version: tbcml.GV,
        country_code: tbcml.CC,
        pkg_folder: tbcml.PathStr | None = None,
        allowed_script_mods: bool = True,
        is_modded: bool = False,
        use_pkg_name_for_folder: bool = False,
        pkg_name: str | None = None,
        create_dirs: bool = True,
    ):
        self.is_modded = is_modded
        self.allowed_script_mods = allowed_script_mods

        self.game_version = tbcml.GameVersion.from_gv(game_version)
        self.country_code = tbcml.CountryCode.from_cc(country_code)

        self.__app_name: str | None = None
        self.__package_name: str | None = pkg_name

        self.use_pkg_name_for_folder = use_pkg_name_for_folder

        if pkg_folder is None:
            self.pkg_folder = type(self).get_default_pkg_folder().get_absolute_path()
            if is_modded:
                self.pkg_folder = self.pkg_folder.add("modded")
        else:
            self.pkg_folder = tbcml.Path(pkg_folder).get_absolute_path()

        if not self.pkg_folder.is_valid():
            raise ValueError(f"Invalid path: {self.output_path}")

        self.init_paths(create_dirs)

        self.key = None
        self.iv = None

        self.libs: dict[str, tbcml.Lib] | None = None

    def replace_lib_string(self, original: str, new: str, pad: str = "\x00") -> str:
        return tbcml.LibFiles(self).replace_str(original, new, pad)

    def get_default_package_name(self) -> str:
        return f"jp.co.ponos.battlecats{self.country_code.get_patching_code()}"

    def get_package_name(self) -> str | None:
        if self.__package_name is not None:
            return self.__package_name

        name = self.read_pkg_name()
        if name is None:
            return None
        self.__package_name = name
        return name

    def set_package_name(self, package_name: str) -> bool:
        res = self.apply_pkg_name(package_name)
        if res:
            self.__package_name = package_name
        return res

    def apply_pkg_name(self, package_name: str) -> bool:
        raise NotImplementedError

    def read_pkg_name(self) -> str | None:
        raise NotImplementedError

    def init_paths(self, create_dirs: bool = True):
        folder_name = f"{self.game_version}{self.country_code.get_code()}"
        if self.use_pkg_name_for_folder:
            pkg_name = self.get_package_name()
            if pkg_name is not None:
                folder_name += f"-{pkg_name}"

        self.output_path = self.pkg_folder.add(folder_name)
        if not self.output_path.is_valid():
            raise ValueError(f"Invalid path: {self.output_path}")

        self.final_pkg_path = self.output_path.add(
            f"{self.get_default_package_name()}-modded{self.pkg_extension}"
        )
        self.pkg_path = self.output_path.add(
            f"{self.get_default_package_name()}-original{self.pkg_extension}"
        )

        self.extracted_path = self.output_path.add("extracted")
        self.modified_packs_path = self.output_path.add("modified_packs")
        self.original_extracted_path = self.output_path.add("original_extracted")

        self.lib_gadgets_folder = self.get_defualt_libgadgets_folder()

        self.modified_packs_path.remove_tree()

        if create_dirs:
            self.pkg_folder.generate_dirs()
            self.output_path.generate_dirs()
            self.extracted_path.generate_dirs()
            self.modified_packs_path.generate_dirs()
            self.original_extracted_path.generate_dirs()

    @staticmethod
    def get_defualt_libgadgets_folder() -> tbcml.Path:
        return tbcml.Path.get_documents_folder().add("LibGadgets").generate_dirs()

    @staticmethod
    def get_default_pkg_folder() -> tbcml.Path:
        raise NotImplementedError

    def get_lib_paths(self) -> dict[str, tbcml.Path]:
        raise NotImplementedError

    def set_key(self, key: str | None):
        self.key = key

    def set_iv(self, iv: str | None):
        self.iv = iv

    def randomize_key(self):
        key = tbcml.Random().get_hex_string(32)
        self.set_key(key)
        return key

    def randomize_iv(self):
        iv = tbcml.Random().get_hex_string(32)
        self.set_iv(iv)
        return iv

    def get_assets_folder_path(self) -> tbcml.Path:
        raise NotImplementedError

    def get_original_pack_location(self) -> tbcml.Path:
        raise NotImplementedError

    def get_native_lib_path(self, architecture: str) -> tbcml.Path | None:
        raise NotImplementedError

    def has_seperate_packs_lists(self) -> bool:
        return self.game_version <= "6.10.0"

    def get_pack_location(self) -> tbcml.Path:
        raise NotImplementedError

    @staticmethod
    def get_server_path_static(
        cc: tbcml.CountryCode, pkg_folder: tbcml.Path | None = None
    ) -> tbcml.Path:
        if pkg_folder is None:
            pkg_folder = Pkg.get_default_pkg_folder()
        if pkg_folder.parent().basename() == "modded":
            pkg_folder = pkg_folder.parent()
        return pkg_folder.parent().add(f"{cc.get_code()}_server")

    def get_server_path(self) -> tbcml.Path:
        return Pkg.get_server_path_static(self.country_code, self.pkg_folder)

    def get_packs_from_dir(self) -> list[tbcml.Path]:
        return self.get_pack_location().get_files() + self.get_server_path().get_files()

    def get_packs_lists(self) -> list[tuple[tbcml.Path, tbcml.Path]]:
        files: list[tuple[tbcml.Path, tbcml.Path]] = []
        for file in self.get_packs_from_dir():
            if file.get_extension() != "pack":
                continue
            list_file = file.change_extension("list")
            if self.has_seperate_packs_lists() and "local" in file.basename().lower():
                list_file = list_file.change_name(
                    f"{file.get_file_name_without_extension()[:-1]}1.list"
                )
            if list_file.exists():
                files.append((file, list_file))
        return files

    def get_packs(self) -> list[tbcml.Path]:
        packs_list = self.get_packs_lists()
        return [pack[0] for pack in packs_list]

    def get_original_extracted_path(self, extracted_path: tbcml.Path) -> tbcml.Path:
        return self.original_extracted_path.add(
            extracted_path.replace(self.extracted_path.path, "").strip_leading_slash()
        )

    def copy_extracted(self, force: bool = False):
        if force:
            self.extracted_path.remove_tree().generate_dirs()
            self.original_extracted_path.copy(self.extracted_path)
            return

        self.copy_extracted_sub_dir("")

    def copy_extracted_sub_dir(self, sub_dir: str):
        original_sub_dir = self.original_extracted_path.add(sub_dir)
        extracted_sub_dir = self.extracted_path.add(sub_dir)
        if not original_sub_dir.exists() and extracted_sub_dir.exists():
            extracted_sub_dir.remove_tree()
            return
        if not original_sub_dir.exists():
            return

        diff = filecmp.dircmp(original_sub_dir.path, extracted_sub_dir.path)
        for file in diff.left_only:
            file = tbcml.Path(file)
            original_sub_dir.add(file).copy(extracted_sub_dir.add(file))
        for file in diff.right_only:
            file = tbcml.Path(file)
            extracted_sub_dir.add(file).remove()
        for file in diff.diff_files:
            file = tbcml.Path(file)
            original_sub_dir.add(file).copy(extracted_sub_dir.add(file))
        for dir in diff.subdirs:
            file = tbcml.Path(sub_dir).add(dir)
            self.copy_extracted_sub_dir(file.path)

    def get_extracted_path(self, original_extracted_path: tbcml.Path) -> tbcml.Path:
        return self.extracted_path.add(
            original_extracted_path.replace(
                self.original_extracted_path.path, ""
            ).strip_leading_slash()
        )

    def get_game_packs(
        self,
        lang: tbcml.Language | None = None,
        all_langs: bool = False,
        pack_names: list[str] | None = None,
    ) -> tbcml.GamePacks:

        packs: dict[str, tbcml.PackFile] = {}

        for pack_file, list_file in self.get_packs_lists():
            pack_name = list_file.get_file_name_without_extension()
            pack_lang = tbcml.PackFile.get_lang(pack_name)
            if pack_lang is not None and pack_lang != lang and not all_langs:
                continue
            if pack_names is not None and pack_name not in pack_names:
                continue
            list_data = list_file.read()
            pack = tbcml.PackFile.from_pack_file(
                list_data,
                pack_file,
                self.country_code,
                pack_name,
                self.game_version,
                self.key,
                self.iv,
            )
            if pack is not None:
                packs[pack_name] = pack

        return tbcml.GamePacks(packs, self.country_code, self.game_version, lang=lang)

    def extract(self, force: bool = False) -> tbcml.Result:
        raise NotImplementedError

    def pack(self) -> tbcml.Result:
        raise NotImplementedError

    def sign(self) -> tbcml.Result:
        raise NotImplementedError

    def add_packs_lists(
        self,
        packs: tbcml.GamePacks,
    ):
        files = packs.to_packs_lists(self.key, self.iv)
        for pack_name, pack_data, list_data in files:
            self.add_pack_list(pack_name, pack_data, list_data)

    def add_pack_list(
        self, pack_name: str, pack_data: tbcml.Data, list_data: tbcml.Data
    ):
        pack_path = self.modified_packs_path.add(pack_name + ".pack")
        list_path = self.modified_packs_path.add(pack_name + ".list")
        pack_data.to_file(pack_path)
        list_data.to_file(list_path)

    def copy_modded_packs(self):
        for file in self.modified_packs_path.get_files():
            if self.has_seperate_packs_lists() and file.basename().endswith("1.pack"):
                file.copy(
                    self.get_pack_location().add(
                        file.basename().replace("1.pack", "2.pack")
                    )
                )
            else:
                file.copy(self.get_pack_location().add(file.basename()))

    def load_packs_into_game(
        self,
        packs: tbcml.GamePacks,
        copy_path: tbcml.Path | None = None,
        save_in_modded_pkgs: bool = False,
        progress_callback: (
            Callable[[tbcml.PKGProgressSignal], bool | None] | None
        ) = None,
    ) -> tbcml.Result:
        raise NotImplementedError

    def save_in_modded_pkgs(self):
        new_pkg = type(self)(
            self.game_version,
            self.country_code,
            is_modded=True,
            use_pkg_name_for_folder=True,
            pkg_name=self.get_package_name(),
        )
        self.final_pkg_path.copy(new_pkg.pkg_path)

    def copy_final_pkg(self, path: tbcml.Path):
        if path == self.final_pkg_path:
            return
        self.final_pkg_path.copy(path)

    @staticmethod
    def try_get_pkg_from_path_pkg(
        path: tbcml.Path,
        all_pkg_dir: tbcml.Path | None = None,
        clzz: type[Pkg] | None = None,
    ) -> tuple[Any | None, tbcml.Result]:
        if clzz is None:
            clzz = Pkg
        if all_pkg_dir is None:
            all_pkg_dir = clzz.get_default_pkg_folder()
        if not path.exists():
            return None, tbcml.Result.file_not_found(path)
        path = path.parent()

        is_modded = False
        pkg_name = None
        if path.parent().basename() == "modded":
            is_modded = True
        if "-" in path.basename():
            pkg_name = path.basename().split("-")[-1]

        use_pkg_name_for_folder = bool(pkg_name)

        name = path.get_file_name().split("-")[0]
        country_code_str = name[-2:]
        if country_code_str not in tbcml.CountryCode.get_all_str():
            return None, tbcml.Result(
                False,
                error=f"{country_code_str} is recognised as a valid country code: { tbcml.CountryCode.get_all_str()}",
            )
        cc = tbcml.CountryCode.from_code(country_code_str)
        game_version_str = name[:-2]

        gv = tbcml.GameVersion.from_string_latest(game_version_str, cc)
        pkg = clzz(
            gv,
            cc,
            is_modded=is_modded,
            use_pkg_name_for_folder=use_pkg_name_for_folder,
            pkg_name=pkg_name,
        )
        if pkg.is_downloaded():
            return pkg, tbcml.Result(True)
        return None, tbcml.Result.file_not_found(pkg.pkg_path)

    @staticmethod
    def get_all_downloaded_pkgs(
        clzz: type[Pkg],
        all_pkg_dir: tbcml.Path | None = None,
        cleanup: bool = False,
    ) -> list[Any]:
        """
        Get all downloaded Pkgs

        Returns:
            list[Pkg]: List of APKs
        """
        if all_pkg_dir is None:
            all_pkg_dir = clzz.get_default_pkg_folder()

        pkgs: list[clzz] = []
        all_apk_folders = all_pkg_dir.get_dirs()
        all_apk_folders.extend(all_pkg_dir.add("modded").generate_dirs().get_dirs())
        for apk_folder in all_apk_folders:
            is_modded = False
            pkg_name = None
            if apk_folder.basename() == "modded":
                continue
            if apk_folder.parent().basename() == "modded":
                is_modded = True
            if "-" in apk_folder.basename():
                pkg_name = apk_folder.basename().split("-")[-1]

            use_pkg_name_for_folder = bool(pkg_name)

            name = apk_folder.get_file_name().split("-")[0]
            country_code_str = name[-2:]
            if country_code_str not in tbcml.CountryCode.get_all_str():
                if cleanup:
                    apk_folder.remove(in_thread=True)
                continue
            cc = tbcml.CountryCode.from_code(country_code_str)
            game_version_str = name[:-2]
            gv = tbcml.GameVersion.from_string_latest(game_version_str, cc)
            pkg = clzz(
                gv,
                cc,
                is_modded=is_modded,
                use_pkg_name_for_folder=use_pkg_name_for_folder,
                pkg_name=pkg_name,
            )
            if pkg.is_downloaded():
                pkgs.append(pkg)
            else:
                if cleanup:
                    apk_folder.remove(in_thread=True)

        pkgs.sort(key=lambda pkg: pkg.game_version.game_version, reverse=True)

        return pkgs

    @staticmethod
    def get_all_pkgs_cc_pkgs(
        cc: tbcml.CountryCode,
        pkg_folder: tbcml.Path | None = None,
        clzz: type[Pkg] | None = None,
    ) -> list[Any]:
        """
        Get all Pkgs for a country code

        Args:
            cc (country_code.CountryCode): Country code
            pkg_folder (tbcml.Path | None, optional): Pkg folder, defaults to default Pkg folder

        Returns:
            list[Pkg]: List of Pkgs
        """
        if clzz is None:
            clzz = Pkg

        pkgs = clzz.get_all_downloaded_pkgs(clzz, pkg_folder)
        pkgs_cc: list[Pkg] = []
        for pkg in pkgs:
            if pkg.country_code == cc:
                pkgs_cc.append(pkg)
        return pkgs_cc

    def create_key(self, key: str, length_override: int | None = None) -> str:
        if length_override is None:
            if self.game_version < tbcml.GameVersion.from_string("8.9.0"):
                length_override = 8
            else:
                length_override = 16
        key += "tbcml_encryption_key"  # makes it harder to do a hash lookup to find original key string
        return (
            tbcml.Hash(tbcml.HashAlgorithm.SHA256)
            .get_hash(tbcml.Data(key), length_override)
            .to_hex()
        )

    def create_iv(self, iv: str, length_override: int | None = None) -> str | None:
        if length_override is None:
            if self.game_version < tbcml.GameVersion.from_string("8.9.0"):
                return None
            else:
                length_override = 16
        iv += (
            "tbcml_encryption_iv"  # makes it harder to tell if iv and key are the same
        )
        return (
            tbcml.Hash(tbcml.HashAlgorithm.SHA256)
            .get_hash(tbcml.Data(iv), length_override)
            .to_hex()
        )

    def is_downloaded(self) -> bool:
        return self.pkg_path.exists()

    def delete(self, in_thread: bool = False):
        self.output_path.remove(in_thread=in_thread)

    def download_server_files(
        self,
        display: bool = False,
        force: bool = False,
        lang: tbcml.Language | None = None,
    ) -> tbcml.Result:
        try:
            sfh = tbcml.ServerFileHandler(self, lang=lang)
        except tbcml.GameVersionSearchError as e:
            return tbcml.Result(False, error=str(e))
        return sfh.extract_all(display=display, force=force)

    def get_download_tsvs(self, lang: tbcml.Language | None = None) -> list[tbcml.Path]:
        if lang is None:
            base_name = "download_%s.tsv"
        else:
            base_name = f"download{lang.value}_%s.tsv"
        files: list[tbcml.Path] = []
        counter = 0
        while True:
            name = base_name % counter
            file = self.get_asset(name)
            if not file.exists():
                if lang is None:
                    new_name = f"en/{name}"
                else:
                    new_name = f"{lang.value}/{name}"
                file = self.get_asset(new_name)
                if not file.exists():
                    break
            files.append(file)
            counter += 1
        return files

    def get_asset(self, asset_name: tbcml.PathStr) -> tbcml.Path:
        raise NotImplementedError

    def get_all_download_tsvs(self) -> list[list[tbcml.Path]]:
        langs = tbcml.Language.get_all()
        langs = [None] + langs
        files: list[list[tbcml.Path]] = []
        for lang in langs:
            files.append(self.get_download_tsvs(lang))
        return files

    def get_architectures(self) -> list[str]:
        raise NotImplementedError

    def get_64_bit_arcs(self) -> list[str]:
        architectures: list[str] = []
        bit_64 = tbcml.Lib.get_64_bit_arcs()
        for arc in self.get_architectures():
            if arc in bit_64:
                architectures.append(arc)
        return architectures

    def get_32_bit_arcs(self) -> list[str]:
        architectures: list[str] = []
        bit_32 = tbcml.Lib.get_32_bit_arcs()
        for arc in self.get_architectures():
            if arc in bit_32:
                architectures.append(arc)
        return architectures

    def __str__(self):
        return self.get_display_string()

    def __repr__(self):
        return self.get_display_string()

    def get_display_string(self) -> str:
        return f"{self.game_version.format()} ({self.country_code})"

    def parse_native_lib(self, architecture: str) -> tbcml.Lib | None:
        path = self.get_native_lib_path(architecture)
        if path is None or not path.exists():
            return None
        return tbcml.Lib(architecture, path)

    def add_library(
        self,
        architecture: str,
        library_path: tbcml.Path,
        inject_native_lib: bool = True,
        inject_smali: bool = False,
    ):
        if inject_native_lib == inject_smali:
            print("You must choose only 1 injection method")
            return
        if inject_smali:
            self.inject_smali(library_path.basename())
            self.add_to_lib_folder(architecture, library_path)
        if inject_native_lib:
            self.add_native_library(architecture, library_path)

    def inject_smali(self, library_name: str) -> None:
        raise NotImplementedError

    def add_native_library(
        self,
        architecture: str,
        library_path: tbcml.Path,
    ):
        libnative = self.get_libs().get(architecture)
        if libnative is None:
            print(f"Could not find libnative for {architecture}")
            return
        libnative.add_library(library_path)
        libnative.write()
        self.add_to_lib_folder(architecture, library_path)

    def get_lib_path(self, architecture: str) -> tbcml.Path:
        raise NotImplementedError

    def get_libs(self) -> dict[str, tbcml.Lib]:
        if self.libs is not None:
            return self.libs
        libs: dict[str, tbcml.Lib] = {}
        for architecture in self.get_architectures():
            libnative = self.parse_native_lib(architecture)
            if libnative is None:
                continue
            libs[architecture] = libnative
        self.libs = libs
        return libs

    def add_patch(self, patch: tbcml.LibPatch):
        arcs = self.get_architectures_subset(patch.architectures)

        for arc in arcs:
            lib = self.parse_native_lib(arc)
            if lib is None:
                return
            lib.apply_patch(patch)
            lib.write()

    def get_architectures_subset(self, arcs: tbcml.ARCS) -> Sequence[str]:
        if arcs == "all":
            return self.get_architectures()
        elif arcs == "32":
            return self.get_32_bit_arcs()
        elif arcs == "64":
            return self.get_64_bit_arcs()

        all_arcs = self.get_architectures()
        return [arc for arc in arcs if arc in all_arcs]

    def add_patches(self, patches: tbcml.LibPatches):
        for patch in patches.lib_patches:
            self.add_patch(patch)

    def is_allowed_script_mods(self) -> bool:
        return self.allowed_script_mods

    def set_allowed_script_mods(self, allowed: bool):
        self.allowed_script_mods = allowed

    def import_libraries(self, lib_folder: tbcml.Path):
        for architecture in self.get_architectures():
            libs_path = lib_folder.add(architecture)
            if not libs_path.exists():
                continue
            for lib in libs_path.get_files():
                self.add_native_library(architecture, lib)

    def add_to_lib_folder(self, architecture: str, library_path: tbcml.Path) -> None:
        raise NotImplementedError

    def create_libgadget_config(self) -> tbcml.JsonFile:
        json_data = {
            "interaction": {
                "type": "script",
                "path": self.get_libgadget_script_path().to_str_forwards(),
                "on_change": "reload",
            }
        }
        json = tbcml.JsonFile.from_object(json_data)
        return json

    def add_libgadget_config(self, used_arcs: list[str]):
        config = self.create_libgadget_config()
        with tbcml.TempFile(
            name=self.get_libgadget_config_path().basename()
        ) as temp_file:
            config.to_data().to_file(temp_file)
            for architecture in used_arcs:
                self.add_to_lib_folder(architecture, temp_file)

    def get_libgadget_script_path(self) -> tbcml.Path:
        raise NotImplementedError

    def get_libgadget_config_path(self) -> tbcml.Path:
        raise NotImplementedError

    def add_libgadget_scripts(self, scripts: dict[str, str]):
        with tbcml.TempFile(
            name=self.get_libgadget_script_path().basename()
        ) as script_path:
            for architecture, script_str in scripts.items():
                tbcml.Data(script_str).to_file(script_path)
                self.add_to_lib_folder(architecture, script_path)

    @staticmethod
    def get_libgadgets_path(
        lib_gadgets_folder: tbcml.Path | None = None,
    ) -> tbcml.Path:
        if lib_gadgets_folder is None:
            lib_gadgets_folder = Pkg.get_defualt_libgadgets_folder()
        lib_gadgets_folder.generate_dirs()
        arcs = ["arm64-v8a", "armeabi-v7a", "x86", "x86_64"]
        for arc in arcs:
            lib_gadgets_folder.add(arc).generate_dirs()
        return lib_gadgets_folder

    @staticmethod
    def download_libgadgets():
        tbcml.FridaGadgetHelper().download_gadgets()

    def get_libgadgets(self) -> dict[str, tbcml.Path]:
        folder = Pkg.get_libgadgets_path(self.lib_gadgets_folder)
        Pkg.download_libgadgets()
        arcs = folder.get_dirs()
        libgadgets: dict[str, tbcml.Path] = {}
        for arc in arcs:
            so_regex = ".*\\.so"
            files = arc.get_files(regex=so_regex)
            if len(files) == 0:
                continue
            files[0] = files[0].rename("libfrida-gadget.so")
            libgadgets[arc.basename()] = files[0]
        return libgadgets

    def add_libgadget_sos(
        self,
        used_arcs: list[str],
        inject_native_lib: bool = True,
        inject_smali: bool = False,
    ):
        for architecture, libgadget in self.get_libgadgets().items():
            if architecture not in used_arcs:
                continue
            self.add_library(architecture, libgadget, inject_native_lib, inject_smali)
            inject_smali = False  # only inject smali code once

    def add_frida_scripts(
        self,
        scripts: dict[str, str],
        inject_native_lib: bool = True,
        inject_smali: bool = False,
    ):
        used_arcs = list(scripts.keys())
        self.add_libgadget_config(used_arcs)
        self.add_libgadget_scripts(scripts)
        self.add_libgadget_sos(used_arcs, inject_native_lib, inject_smali)

    def add_script_mods(self, bc_mods: list[tbcml.Mod], add_base_script: bool = True):
        if not bc_mods:
            return
        if not self.is_allowed_script_mods():
            return
        scripts: dict[str, str] = {}
        inject_smali: bool = False
        for mod in bc_mods:
            scripts_str, inj = mod.get_scripts_str(self)
            if inj:
                inject_smali = True
            for arc, string in scripts_str.items():
                if arc not in scripts:
                    scripts[arc] = ""
                scripts[arc] += string + "\n"

        if add_base_script:
            base_script = tbcml.FridaScript.get_base_script()
            for arc in scripts.keys():
                scripts[arc] = base_script.replace("// {{SCRIPTS}}", scripts[arc])

        if scripts:
            self.add_frida_scripts(
                scripts, inject_smali=inject_smali, inject_native_lib=not inject_smali
            )

    def add_modded_html(self, mods: list[tbcml.Mod]):
        transfer_screen_path = tbcml.Path.get_asset_file_path(
            tbcml.Path("html").add("kisyuhen_01_top_en.html")  # TODO: different locales
        )
        modlist_path = tbcml.Path.get_asset_file_path(
            tbcml.Path("html").add("modlist.html")
        )

        self.add_asset(transfer_screen_path)

        mod_str = ""
        for i, mod in enumerate(mods):
            html = mod.get_custom_html()
            mod_path = f"mod_{i}.html"
            mod_str += (
                f'<br><a href="{mod_path}" class="Buttonbig">{mod.name}</a><br><br>'
            )
            self.add_asset_data(tbcml.Path(mod_path), tbcml.Data(html))

        modlist_html = modlist_path.read().to_str()
        modlist_html = modlist_html.replace("{{MODS_LIST}}", mod_str)

        self.add_asset_data(tbcml.Path("modlist.html"), tbcml.Data(modlist_html))

    def add_asset(self, asset_path: tbcml.Path):
        asset_path.copy(self.extracted_path.add("assets").add(asset_path.basename()))

    def add_asset_data(self, asset_path: tbcml.Path, asset_data: tbcml.Data):
        self.extracted_path.add("assets").add(asset_path).write(asset_data)

    def remove_arcs(self, arcs: list[str]):
        for arc in arcs:
            self.get_lib_path(arc).remove()

    def remove_asset(self, asset_path: tbcml.PathStr):
        asset_path = self.get_asset(asset_path)
        asset_path.remove()

    def add_assets(self, asset_folder: tbcml.Path):
        for asset in asset_folder.get_files():
            self.add_asset(asset)

    def add_assets_from_pack(self, pack: tbcml.PackFile):
        if pack.is_server_pack(pack.pack_name):
            return
        with tbcml.TempFolder() as temp_dir:
            dir = pack.extract(temp_dir, encrypt=True)
            self.add_assets(dir)
        pack.clear_files()
        pack.add_file(
            tbcml.GameFile(
                tbcml.Data(pack.pack_name),
                f"empty_file_{pack.pack_name}",
                pack.pack_name,
                pack.country_code,
                pack.gv,
            )
        )
        pack.set_modified(True)

    def add_assets_from_game_packs(self, packs: tbcml.GamePacks):
        for pack in packs.packs.values():
            self.add_assets_from_pack(pack)

    def add_file(self, file_path: tbcml.Path):
        file_path.copy(self.extracted_path)

    def add_patch_mods(self, bc_mods: list[tbcml.Mod]):
        if not bc_mods:
            return
        if not self.is_allowed_script_mods():
            return
        patches = tbcml.LibPatches.create_empty()
        for mod in bc_mods:
            patches.add_patches(mod.patches)

        patches.validate_patches(self.country_code, self.game_version)
        if not patches.is_empty():
            self.add_patches(patches)

    def add_audio(
        self,
        audio_file: tbcml.AudioFile,
    ):
        filename = audio_file.get_apk_file_name()
        audio_file.caf_to_little_endian().data.to_file(self.get_asset(filename))

    def get_audio_extensions(self) -> list[str]:
        raise NotImplementedError

    def audio_file_startswith_snd(self) -> bool:
        raise NotImplementedError

    def get_all_audio(self) -> dict[int, tbcml.Path]:
        audio_files: dict[int, tbcml.Path] = {}
        for file in self.get_assets_folder_path().get_files():
            if file.get_extension() not in self.get_audio_extensions():
                continue
            base_name = file.get_file_name_without_extension()
            if not base_name.startswith("snd") and self.audio_file_startswith_snd():
                continue
            id_str = base_name.strip("snd")
            if not id_str.isdigit():
                continue
            audio_files[int(id_str)] = file

        server_files = self.get_all_server_audio()
        for id, file in server_files.items():
            audio_files[id] = file
        return audio_files

    def get_all_server_audio(self):
        audio_files: dict[int, tbcml.Path] = {}
        for file in self.get_server_path().get_files():
            if file.get_extension() not in self.get_audio_extensions():
                continue
            id_str = file.get_file_name_without_extension().strip("snd")
            if not id_str.isdigit():
                continue
            audio_files[int(id_str)] = file
        return audio_files

    def get_free_audio_id(self, all_audio: dict[int, tbcml.Path] | None = None):
        if all_audio is None:
            all_audio = self.get_all_audio()

        i = 0
        while True:
            if i not in all_audio:
                return i
            i += 1

    def get_asset_decrypt(self, asset_name: tbcml.PathStr) -> tbcml.Data:
        path = self.get_asset(asset_name)
        return tbcml.GameFile.decrypt_apk_file(path.read())

    def add_asset_encrypt(self, asset_name: tbcml.PathStr, data: tbcml.Data):
        path = self.get_asset(asset_name)
        path.parent().generate_dirs()
        data_enc = tbcml.GameFile.encrypt_apk_file(data)
        data_enc.to_file(path)

    def set_string(
        self,
        name: str,
        value: str,
        include_lang: bool,
        lang: str | None = None,
    ) -> bool:
        raise NotImplementedError

    def get_string(
        self, name: str, include_lang: bool, lang: str | None = None
    ) -> str | None:
        raise NotImplementedError

    def apply_app_name(self, name: str) -> bool:
        return self.set_string("app_name", name, include_lang=False)

    def set_app_name(self, name: str) -> bool:
        success = self.apply_app_name(name)
        if success:
            self.__app_name = name
        return success

    def read_app_name(self) -> str | None:
        app_name = self.get_string("app_name", include_lang=False)
        return app_name

    def get_app_name(self) -> str | None:
        if self.__app_name is not None:
            return self.__app_name
        app_name = self.read_app_name()
        if app_name is not None:
            self.__app_name = app_name
        return app_name

    def get_mod_html_files(self) -> list[tbcml.Path]:
        files = self.get_assets_folder_path().get_files(
            regex=r"kisyuhen_01_top_..\.html"
        )
        return files

    def add_mods_files(self, mods: list[tbcml.Mod], lang: str | None = None):
        for mod in mods:
            mod.apply_to_pkg(self, lang)

    def load_mods(
        self,
        mods: list[tbcml.Mod],
        game_packs: tbcml.GamePacks | None,
        lang: tbcml.Language | None = None,
        key: str | None = None,
        iv: str | None = None,
        add_modded_html: bool = True,
        save_in_modded_pkgs: bool = False,
        progress_callback: (
            Callable[[tbcml.PKGProgressSignal], bool | None] | None
        ) = None,
        do_final_pkg_actions: bool = True,
    ) -> tbcml.Result:
        raise NotImplementedError

    def is_apk(self) -> bool:
        raise NotImplementedError

    @staticmethod
    def progress(
        progress: float,
        current: int,
        total: int,
        is_file_size: bool = False,
    ):
        total_bar_length = 50
        if is_file_size:
            current_str = tbcml.FileSize(current).format()
            total_str = tbcml.FileSize(total).format()
        else:
            current_str = str(current)
            total_str = str(total)
        bar_length = int(total_bar_length * progress)
        bar = "#" * bar_length + "-" * (total_bar_length - bar_length)
        print(
            f"\r[{bar}] {int(progress * 100)}% ({current_str}/{total_str})    ",
            end="",
        )
