from __future__ import annotations

from typing import Any, Callable
import plistlib
import tbcml

from tbcml.io.pkg import Pkg, PkgType


class Ipa(Pkg):
    pkg_extension = ".ipa"
    pkg_type = PkgType.APK

    def __init__(
        self,
        game_version: tbcml.GV,
        country_code: tbcml.CC,
        ipa_folder: tbcml.PathStr | None = None,
        allowed_script_mods: bool = True,
        is_modded: bool = False,
        use_pkg_name_for_folder: bool = False,
        pkg_name: str | None = None,
        create_dirs: bool = True,
    ):
        super().__init__(
            game_version,
            country_code,
            ipa_folder,
            allowed_script_mods,
            is_modded,
            use_pkg_name_for_folder,
            pkg_name,
            create_dirs,
        )

    @staticmethod
    def clean_up(ipa_folder: tbcml.Path | None = None):
        Ipa.get_all_downloaded(ipa_folder, cleanup=True)

    @staticmethod
    def get_default_pkg_folder() -> tbcml.Path:
        return tbcml.Path.get_documents_folder().add("IPAs").generate_dirs()

    def is_apk(self) -> bool:
        return False

    @staticmethod
    def try_get_pkg_from_path(
        path: tbcml.Path,
        all_pkg_dir: tbcml.Path | None = None,
    ) -> tuple[Ipa | None, tbcml.Result]:
        return Ipa.try_get_pkg_from_path_pkg(path, all_pkg_dir=all_pkg_dir, clzz=Ipa)

    @staticmethod
    def get_app_folder_from_zip(zip: tbcml.Zip):
        payload_path = tbcml.Path("Payload")
        paths = zip.get_paths_in_folder(payload_path)
        if not paths:
            return None
        for path in paths:
            parts = path.to_str_forwards().split("/")
            for part in parts:
                if part.endswith(".app"):
                    return payload_path.add(part)
        return None

    @staticmethod
    def get_package_name_version_from_ipa(path: tbcml.Path):
        zipfile = tbcml.Zip(path.read())
        app_folder = Ipa.get_app_folder_from_zip(zipfile)
        if app_folder is None:
            return None, None

        info_plist = app_folder.add("Info.plist")
        data = zipfile.get_file(info_plist)
        if data is None:
            return None, None
        plist_data = plistlib.loads(data.to_bytes(), fmt=plistlib.FMT_BINARY)
        package_name = plist_data["CFBundleIdentifier"]
        game_version = plist_data["CFBundleShortVersionString"]
        return package_name, game_version

    def get_plist(self) -> dict[str, Any]:
        path = self.get_asset("Info.plist")
        plist = plistlib.loads(path.read().to_bytes(), fmt=plistlib.FMT_BINARY)
        return plist

    def set_plist(self, data: dict[str, Any]):
        path = self.get_asset("Info.plist")
        plist = plistlib.dumps(data, fmt=plistlib.FMT_BINARY)
        path.write(tbcml.Data(plist))

    @staticmethod
    def from_pkg_path(
        ipa_path: tbcml.Path,
        cc_overwrite: tbcml.CountryCode | None = None,
        gv_overwrite: tbcml.GameVersion | None = None,
        pkg_folder: tbcml.Path | None = None,
        allowed_script_mods: bool = True,
        overwrite_pkg: bool = True,
    ) -> tuple[Ipa | None, tbcml.Result]:
        if not ipa_path.exists():
            return None, tbcml.Result.file_not_found(ipa_path)
        pkg_name, gv = Ipa.get_package_name_version_from_ipa(ipa_path)
        if pkg_name is not None:
            cc = tbcml.CountryCode.from_package_name(pkg_name)
        else:
            cc = cc_overwrite

        if gv is None:
            gv = gv_overwrite

        if gv is None or cc is None:
            return None, tbcml.Result(
                False, error="Failed to get country code or game version from ipa."
            )

        ipa = Ipa(
            gv, cc, ipa_folder=pkg_folder, allowed_script_mods=allowed_script_mods
        )

        if overwrite_pkg:
            ipa_path.copy(ipa.pkg_path)
            ipa.original_extracted_path.remove_tree().generate_dirs()
        return ipa, tbcml.Result(True)

    def extract(self, force: bool = False) -> tbcml.Result:
        if self.original_extracted_path.has_files() and not force:
            self.copy_extracted()
            return tbcml.Result(True)
        if not self.pkg_path.exists():
            return tbcml.Result.file_not_found(self.pkg_path)

        return self.extract_zip()

    def extract_zip(self) -> tbcml.Result:
        if not self.pkg_path.exists():
            return tbcml.Result.file_not_found(self.pkg_path)
        with tbcml.TempFolder() as path:
            zip_file = tbcml.Zip(self.pkg_path.read())
            zip_file.extract(path)
            self.original_extracted_path.remove().generate_dirs()
            path.copy(self.original_extracted_path)

        self.copy_extracted(force=True)
        return tbcml.Result(True)

    def get_assets_folder_path(self) -> tbcml.Path:
        payload_path = self.extracted_path.add("Payload")
        dirs = payload_path.get_dirs()
        if not dirs:
            raise ValueError("No dirs found in ipa!")
        return dirs[0]

    def get_assets_path_orig(self) -> tbcml.Path:
        payload_path = self.original_extracted_path.add("Payload")
        dirs = payload_path.get_dirs()
        if not dirs:
            raise ValueError("No dirs found in ipa!")
        return dirs[0]

    def add_to_lib_folder(self, architecture: str, library_path: tbcml.Path) -> None:
        pass

    def get_libgadget_script_path(self) -> tbcml.Path:
        return tbcml.Path("bc_script.js")

    def get_libgadget_config_path(self) -> tbcml.Path:
        return tbcml.Path("frida-gadget.config")

    def get_audio_extensions(self) -> list[str]:
        return ["caf", "mp3"]

    def audio_file_startswith_snd(self) -> bool:
        return False

    def get_pack_location(self) -> tbcml.Path:
        return self.get_assets_folder_path()

    def get_original_pack_location(self) -> tbcml.Path:
        return self.get_assets_path_orig()

    def is_java(self) -> bool:
        return False  # TODO: check if there are any changes with older ipa versions

    def get_architectures(self) -> list[str]:
        return ["arm64-v8a"]

    def inject_smali(self, library_name: str): ...

    def get_native_lib_path(self, architecture: str) -> tbcml.Path | None:
        if architecture not in self.get_architectures():
            return None

        return self.get_bc_lib_path()

    def get_lib_path(self, architecture: str) -> tbcml.Path:
        return self.get_assets_folder_path()

    def get_bc_lib_path(self):
        key = "CFBundleExecutable"
        name = self.get_plist_val(key)
        if name is None:
            name = f"battlecats{self.country_code.get_patching_code()}"
        return self.get_asset(name)

    def set_string(
        self, name: str, value: str, include_lang: bool, lang: str | None = None
    ) -> bool:
        if lang is None or include_lang:
            lang = self.country_code.get_language()
        localizable_strings_path = self.get_asset(
            tbcml.Path(f"{lang}.lproj").add("Localizable.strings")
        )
        localizable_strings = plistlib.loads(
            localizable_strings_path.read().to_bytes(), fmt=plistlib.FMT_BINARY
        )
        localizable_strings[name] = value
        localizable_strings_path.write(tbcml.Data(plistlib.dumps(localizable_strings)))
        return True

    def get_string(
        self,
        name: str,
        include_lang: bool,
        lang: str | None = None,
    ) -> str | None:
        if lang is None or include_lang:
            lang = self.country_code.get_language()
        localizable_strings_path = self.get_asset(
            tbcml.Path(f"{lang}.lproj").add("Localizable.strings")
        )
        if not localizable_strings_path.exists():
            return None
        localizable_strings = plistlib.loads(
            localizable_strings_path.read().to_bytes(), fmt=plistlib.FMT_BINARY
        )
        return localizable_strings.get(name)

    def load_mods(
        self,
        mods: list[tbcml.Mod],
        game_packs: tbcml.GamePacks | None = None,
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
        if progress_callback is None:
            progress_callback = lambda x: None

        if progress_callback(tbcml.PKGProgressSignal.START) is False:
            return tbcml.Result(False)

        if progress_callback(tbcml.PKGProgressSignal.LOAD_GAME_PACKS) is False:
            return tbcml.Result(False)

        if game_packs is None:
            game_packs = tbcml.GamePacks.from_pkg(self, lang=lang)

        if progress_callback(tbcml.PKGProgressSignal.APPLY_MODS) is False:
            return tbcml.Result(False)
        game_packs.apply_mods(mods)

        if key is not None:
            self.set_key(key)
        if iv is not None:
            self.set_iv(iv)

        if do_final_pkg_actions:
            if add_modded_html:
                progress_callback(tbcml.PKGProgressSignal.ADD_MODDED_HTML)
                self.add_modded_html(mods)

        if progress_callback(tbcml.PKGProgressSignal.ADD_MODDED_FILES) is False:
            return tbcml.Result(False)
        lang_str = None if lang is None else lang.value
        self.add_mods_files(mods, lang_str)

        if do_final_pkg_actions:
            if progress_callback(tbcml.PKGProgressSignal.LOAD_PACKS_INTO_GAME) is False:
                return tbcml.Result(False)
            if not (
                res := self.load_packs_into_game(
                    game_packs,
                    save_in_modded_pkgs=save_in_modded_pkgs,
                    progress_callback=progress_callback,
                )
            ):
                return res
        else:
            if progress_callback(tbcml.PKGProgressSignal.DONE) is False:
                return tbcml.Result(False)
        return tbcml.Result(True)

    def pack(self) -> tbcml.Result:
        tbcml.Zip.compress_directory(self.extracted_path, self.final_pkg_path)
        return tbcml.Result(True)

    def set_plist_key(self, key: str, val: Any):
        plist = self.get_plist()
        plist[key] = val
        self.set_plist(plist)
        return True

    def get_plist_val(self, key: str) -> Any | None:
        return self.get_plist().get(key)

    def enable_access_internalfile(self) -> bool:
        # Enables Internal File Sharing to User(File App, iTunes)
        # So user can access directly to savedata, eventdata, metadata and modify it.
        self.set_plist_key("UIFileSharingEnabled", True)
        self.set_plist_key("LSSupportsOpeningDocumentsInPlace", True)
        return True

    def apply_pkg_name(self, package_name: str) -> bool:
        return self.set_plist_key("CFBundleIdentifier", package_name)

    def read_pkg_name(self) -> str | None:
        return self.get_plist_val("CFBundleIdentifier")

    def apply_app_name(self, name: str) -> bool:
        return self.set_plist_key(
            "CFBundleDisplayName", name.strip(" ")
        )  # strip spaces due to Altstore/Sidestore issue

    def read_app_name(self) -> str | None:
        return self.get_plist_val("CFBundleDisplayName")

    def sign(self) -> tbcml.Result:  # TODO: impliment signing
        # Comment: ipa does not require signing, user must sign the INSTALLATION PROCESS with certificates(enterprise, free apple dev acc, apple dev account)
        # So we dont have to presign the ipa.
        return tbcml.Result(True)

    def load_packs_into_game(
        self,
        packs: tbcml.GamePacks,
        copy_path: tbcml.Path | None = None,
        save_in_modded_pkgs: bool = False,
        progress_callback: (
            Callable[[tbcml.PKGProgressSignal], bool | None] | None
        ) = None,
    ) -> tbcml.Result:
        if progress_callback is None:
            progress_callback = lambda x: None

        if progress_callback(tbcml.PKGProgressSignal.ADD_PACKS_LISTS) is False:
            return tbcml.Result(False)
        self.add_packs_lists(packs)

        if progress_callback(tbcml.PKGProgressSignal.PATCH_LIBS) is False:
            return tbcml.Result(False)
        tbcml.LibFiles(self).patch()

        if progress_callback(tbcml.PKGProgressSignal.COPY_MODDED_PACKS) is False:
            return tbcml.Result(False)
        self.copy_modded_packs()

        if progress_callback(tbcml.PKGProgressSignal.PACK) is False:
            return tbcml.Result(False)
        if not (res := self.pack()):
            return res

        if progress_callback(tbcml.PKGProgressSignal.SIGN) is False:
            return tbcml.Result(False)
        if not (res := self.sign()):
            return res

        if progress_callback(tbcml.PKGProgressSignal.FINISH_UP) is False:
            return tbcml.Result(False)

        if copy_path is not None:
            self.copy_final_pkg(copy_path)
        if save_in_modded_pkgs:
            self.save_in_modded_pkgs()
        if progress_callback(tbcml.PKGProgressSignal.DONE) is False:
            return tbcml.Result(False)

        return tbcml.Result(True)

    def get_lib_paths(self) -> dict[str, tbcml.Path]:
        return {"arm64-v8a": self.get_bc_lib_path()}

    def get_asset(self, asset_name: tbcml.PathStr):
        path = tbcml.Path(asset_name)
        return self.get_assets_folder_path().add(path)

    @staticmethod
    def get_all_pkgs_cc(
        cc: tbcml.CountryCode, pkg_folder: tbcml.Path | None = None
    ) -> list["Ipa"]:
        """
        Get all IPAs for a country code

        Args:
            cc (country_code.CountryCode): Country code

        Returns:
            list[IPA]: List of IPAs
        """
        return tbcml.Pkg.get_all_pkgs_cc_pkgs(cc, pkg_folder, Ipa)

    @staticmethod
    def get_all_downloaded(
        all_pkg_dir: tbcml.Path | None = None, cleanup: bool = False
    ) -> list["Ipa"]:
        """
        Get all downloaded IPAs

        Returns:
            list[Ipa]: List of IPAs
        """
        return tbcml.Pkg.get_all_downloaded_pkgs(Ipa, all_pkg_dir, cleanup)
