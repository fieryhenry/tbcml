import filecmp
from typing import Any, Optional
import plistlib
import tbcml


class Ipa:
    def __init__(
        self,
        game_version: "tbcml.GV",
        country_code: "tbcml.CC",
        ipa_folder: Optional["tbcml.PathStr"] = None,
        # allowed_script_mods: bool = True, # TODO: impliment scripting
    ):
        self.game_version = tbcml.GameVersion.from_gv(game_version)
        self.country_code = tbcml.CountryCode.from_cc(country_code)
        self.package_name = self.get_package_name()

        if ipa_folder is None:
            self.ipa_folder = Ipa.get_default_ipa_folder().get_absolute_path()
        else:
            self.ipa_folder = tbcml.Path(ipa_folder).get_absolute_path()

        self.init_paths()

        self.key = None
        self.iv = None

        self.lib: Optional[dict[str, tbcml.Lib]] = None
        # self.allowed_script_mods = allowed_script_mods

    def init_paths(self):
        self.ipa_folder.generate_dirs()
        self.output_path = self.ipa_folder.add(
            f"{self.game_version}{self.country_code.get_code()}"
        )

        self.final_ipa_path = self.output_path.add(f"{self.package_name}-modded.ipa")
        self.ipa_path = self.output_path.add(f"{self.package_name}-original.ipa")

        self.extracted_path = self.output_path.add("extracted").generate_dirs()
        self.decrypted_path = self.output_path.add("decrypted").generate_dirs()
        self.modified_packs_path = (
            self.output_path.add("modified_packs").remove_tree().generate_dirs()
        )
        self.original_extracted_path = self.output_path.add(
            "original_extracted"
        ).generate_dirs()

        self.temp_path = self.output_path.add("temp").remove_tree().generate_dirs()

    def get_package_name(self) -> str:
        return f"jp.co.ponos.battlecats{self.country_code.get_patching_code()}"

    @staticmethod
    def get_default_ipa_folder() -> "tbcml.Path":
        return tbcml.Path.get_documents_folder().add("IPAs").generate_dirs()

    @staticmethod
    def get_app_folder_from_zip(zip: "tbcml.Zip"):
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
    def get_package_name_version_from_ipa(path: "tbcml.Path"):
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

    def get_plist_val(self, key: str) -> Optional[Any]:
        return self.get_plist().get(key)

    @staticmethod
    def from_ipa_path(
        ipa_path: "tbcml.Path",
        cc_overwrite: Optional["tbcml.CountryCode"] = None,
        gv_overwrite: Optional["tbcml.GameVersion"] = None,
        ipa_folder: Optional["tbcml.Path"] = None,
    ):
        pkg_name, gv = Ipa.get_package_name_version_from_ipa(ipa_path)
        if pkg_name is not None:
            cc = tbcml.CountryCode.from_package_name(pkg_name)
        else:
            cc = cc_overwrite

        if gv is None:
            gv = gv_overwrite

        if gv is None or cc is None:
            raise ValueError("Failed to get cc or gv from ipa.")

        ipa = Ipa(gv, cc, ipa_folder=ipa_folder)
        ipa_path.copy(ipa.ipa_path)
        ipa.original_extracted_path.remove_tree().generate_dirs()
        return ipa

    def extract(self, force: bool = False):
        if self.original_extracted_path.has_files() and not force:
            self.copy_extracted()
            return True

        return self.extract_zip()

    def extract_zip(self):
        if not self.ipa_path.exists():
            return False
        temp_path = self.temp_path.add("extraction")
        with tbcml.TempFolder(path=temp_path) as path:
            zip_file = tbcml.Zip(self.ipa_path.read())
            zip_file.extract(path)
            self.original_extracted_path.remove().generate_dirs()
            path.copy(self.original_extracted_path)

        self.copy_extracted(force=True)
        return True

    def get_original_extracted_path(self, extracted_path: "tbcml.Path") -> "tbcml.Path":
        return self.original_extracted_path.add(
            extracted_path.replace(self.extracted_path.path, "").strip_leading_slash()
        )

    def get_extracted_path(self, original_extracted_path: "tbcml.Path") -> "tbcml.Path":
        return self.extracted_path.add(
            original_extracted_path.replace(
                self.original_extracted_path.path, ""
            ).strip_leading_slash()
        )

    def copy_extracted(self, force: bool = False):
        if force:
            self.extracted_path.remove_tree().generate_dirs()
            self.original_extracted_path.copy(self.extracted_path)
            return
        for original_file in self.original_extracted_path.get_files_recursive():
            extracted_file = self.get_extracted_path(original_file)
            if not extracted_file.parent().exists():
                extracted_file.parent().generate_dirs()
            if not extracted_file.exists():
                original_file.copy(extracted_file)
                continue
            if not filecmp.cmp(extracted_file.path, original_file.path):
                original_file.copy(extracted_file)

        for extracted_file in self.extracted_path.get_files_recursive():
            original_file = self.get_original_extracted_path(extracted_file)
            if not original_file.exists():
                extracted_file.remove()

        for extracted_dir in self.extracted_path.get_dirs_recursive():
            orignal_dir = self.get_original_extracted_path(extracted_dir)
            if not orignal_dir.exists():
                extracted_dir.remove()

    def get_assets_path(self) -> "tbcml.Path":
        payload_path = self.extracted_path.add("Payload")
        dirs = payload_path.get_dirs()
        if not dirs:
            raise ValueError("No dirs found in ipa!")
        return dirs[0]

    def get_assets_path_orig(self) -> "tbcml.Path":
        payload_path = self.original_extracted_path.add("Payload")
        dirs = payload_path.get_dirs()
        if not dirs:
            raise ValueError("No dirs found in ipa!")
        return dirs[0]

    def get_asset(self, asset_name: "tbcml.PathStr") -> "tbcml.Path":
        return self.get_assets_path().add(asset_name)

    def get_pack_location(self) -> "tbcml.Path":
        return self.get_assets_path()

    def get_original_pack_location(self) -> "tbcml.Path":
        return self.get_assets_path_orig()

    def get_server_path(self):
        return tbcml.Apk.get_server_path_static(self.country_code, None)

    def get_packs_from_dir(self) -> list["tbcml.Path"]:
        return self.get_pack_location().get_files() + self.get_server_path().get_files()

    def is_java(self) -> bool:
        return False  # TODO: check if there are any changes with older ipa versions

    def get_packs_lists(self) -> list[tuple["tbcml.Path", "tbcml.Path"]]:
        files: list[tuple[tbcml.Path, tbcml.Path]] = []
        for file in self.get_packs_from_dir():
            if file.get_extension() != "pack":
                continue
            list_file = file.change_extension("list")
            if self.is_java() and "local" in file.basename().lower():
                list_file = list_file.change_name(
                    f"{file.get_file_name_without_extension()[:-1]}1.list"
                )
            if list_file.exists():
                files.append((file, list_file))
        return files

    def get_game_packs(
        self, lang: Optional["tbcml.Language"] = None, all_langs: bool = False
    ) -> "tbcml.GamePacks":
        packs: dict[str, tbcml.PackFile] = {}

        for pack_file, list_file in self.get_packs_lists():
            pack_name = list_file.get_file_name_without_extension()
            pack_lang = tbcml.PackFile.get_lang(pack_name)
            if pack_lang is not None and pack_lang != lang and not all_langs:
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

    def download_server_files(
        self,
        display: bool = False,
        force: bool = False,
        lang: Optional["tbcml.Language"] = None,
    ):
        sfh = tbcml.ServerFileHandler(self, lang=lang)
        sfh.extract_all(display=display, force=force)

    def get_all_download_tsvs(self) -> list[list["tbcml.Path"]]:
        langs = tbcml.Language.get_all()
        langs = [None] + langs
        files: list[list["tbcml.Path"]] = []
        for lang in langs:
            files.append(self.get_download_tsvs(lang))
        return files

    def get_download_tsvs(
        self, lang: Optional["tbcml.Language"] = None
    ) -> list["tbcml.Path"]:
        if lang is None:
            base_name = "download_%s.tsv"
        else:
            base_name = f"download{lang.value}_%s.tsv"
        files: list["tbcml.Path"] = []
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

    def get_architectures(self) -> list[str]:
        return ["arm64-v8a"]

    def get_libnative_path(self, arc: str) -> Optional["tbcml.Path"]:
        if arc not in self.get_architectures():
            return None

        return self.get_bc_lib_path()

    def get_bc_lib_path(self):
        key = "CFBundleExecutable"
        name = self.get_plist_val(key)
        if name is None:
            name = f"battlecats{self.country_code.get_patching_code()}"
        return self.get_asset(name)

    def set_key(self, key: Optional[str]):
        self.key = key

    def set_iv(self, iv: Optional[str]):
        self.iv = iv

    def add_asset(self, local_path: "tbcml.Path", pkg_path: "tbcml.Path"):
        local_path.copy(self.get_asset(pkg_path))

    def add_asset_data(self, asset_path: "tbcml.Path", asset_data: "tbcml.Data"):
        self.get_asset(asset_path).write(asset_data)

    def remove_asset(self, asset_path: "tbcml.Path"):
        self.get_asset(asset_path).remove()

    def add_assets(self, asset_folder: "tbcml.Path", apk_path: "tbcml.Path"):
        for asset in asset_folder.get_files():
            self.add_asset(asset, asset.replace(asset_folder.path, apk_path.path))

    def add_modded_html(self, mods: list["tbcml.Mod"]):
        transfer_screen_path = tbcml.Path.get_asset_file_path(
            tbcml.Path("html").add("kisyuhen_01_top_en.html")  # TODO: different locales
        )
        modlist_path = tbcml.Path.get_asset_file_path(
            tbcml.Path("html").add("modlist.html")
        )

        self.add_asset(transfer_screen_path, tbcml.Path("kisyuhen_01_top_en.html"))

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

    def add_mods_files(self, mods: list["tbcml.Mod"]):
        for mod in mods:
            mod.apply_to_ipa(self)

    def add_audio(
        self,
        audio_file: "tbcml.AudioFile",
    ):
        filename = audio_file.get_ipa_file_name()
        audio_file.caf_to_little_endian().data.to_file(self.get_asset(filename))

    def load_mods(
        self,
        mods: list["tbcml.Mod"],
        game_packs: Optional["tbcml.GamePacks"] = None,
        lang: Optional["tbcml.Language"] = None,
        key: Optional[str] = None,
        iv: Optional[str] = None,
        add_modded_html: bool = True,
    ) -> bool:
        if game_packs is None:
            game_packs = tbcml.GamePacks.from_pkg(self, lang=lang)

        if key is not None:
            self.set_key(key)
        if iv is not None:
            self.set_iv(iv)

        game_packs.apply_mods(mods)

        if add_modded_html:
            self.add_modded_html(mods)

        self.add_mods_files(mods)

        if not self.load_packs_into_game(game_packs):
            return False
        return True

    def add_packs_lists(
        self,
        packs: "tbcml.GamePacks",
    ):
        files = packs.to_packs_lists(self.key, self.iv)
        for pack_name, pack_data, list_data in files:
            self.add_pack_list(pack_name, pack_data, list_data)

    def add_pack_list(
        self, pack_name: str, pack_data: "tbcml.Data", list_data: "tbcml.Data"
    ):
        pack_path = self.modified_packs_path.add(pack_name + ".pack")
        list_path = self.modified_packs_path.add(pack_name + ".list")
        pack_data.to_file(pack_path)
        list_data.to_file(list_path)

    def copy_modded_packs(self):
        for file in self.modified_packs_path.get_files():
            if self.is_java() and file.basename().endswith("1.pack"):
                file.copy(
                    self.get_pack_location().add(
                        file.basename().replace("1.pack", "2.pack")
                    )
                )
            else:
                file.copy(self.get_pack_location().add(file.basename()))

    def pack(self) -> bool:
        tbcml.Zip.compress_directory(self.extracted_path, self.final_ipa_path)
        return True

    def set_plist_key(self, key: str, val: str):
        plist = self.get_plist()
        plist[key] = val
        self.set_plist(plist)
        return True

    def set_package_name(self, package_name: str) -> bool:
        self.set_plist_key("CFBundleIdentifier", package_name)
        self.package_name = package_name
        return True

    def set_app_name(self, app_name: str) -> bool:
        self.set_plist_key("CFBundleDisplayName", app_name)
        return True

    def sign(self) -> bool:  # TODO: impliment signing
        return True
        pass

    def load_packs_into_game(
        self,
        packs: "tbcml.GamePacks",
        copy_path: Optional["tbcml.Path"] = None,
    ) -> bool:
        self.add_packs_lists(packs)
        tbcml.LibFiles(self).patch()
        self.copy_modded_packs()
        if not self.pack():
            return False
        if not self.sign():
            return False
        if copy_path is not None:
            self.copy_final_ipa(copy_path)
        return True

    def get_lib_paths(self) -> dict[str, "tbcml.Path"]:
        return {"arm64-v8a": self.get_bc_lib_path()}

    def copy_final_ipa(self, path: "tbcml.Path"):
        if path == self.final_ipa_path:
            return
        self.final_ipa_path.copy(path)
