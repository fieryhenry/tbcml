from __future__ import annotations
import enum
from typing import Any, Callable

import bs4
import cloudscraper  # type: ignore
import requests

import tbcml

from tbcml.io.pkg import Pkg, PkgType


class PKGProgressSignal(enum.Enum):
    """Progress Signal Enum"""

    START = 0
    LOAD_GAME_PACKS = 1
    APPLY_MODS = 2
    ADD_SMALI_MODS = 3
    ADD_SCRIPT_MODS = 4
    ADD_PATCH_MODS = 5
    SET_MANIFEST_VALUES = 6
    ADD_MODDED_HTML = 7
    ADD_MODDED_FILES = 8
    LOAD_PACKS_INTO_GAME = 9
    ADD_PACKS_LISTS = 10
    PATCH_LIBS = 11
    COPY_MODDED_PACKS = 12
    PACK = 13
    SIGN = 14
    FINISH_UP = 15
    DONE = 16


class Apk(Pkg):
    pkg_extension = ".apk"
    pkg_type = PkgType.APK

    def __init__(
        self,
        game_version: tbcml.GV,
        country_code: tbcml.CC,
        apk_folder: tbcml.PathStr | None = None,
        allowed_script_mods: bool = True,
        is_modded: bool = False,
        use_pkg_name_for_folder: bool = False,
        pkg_name: str | None = None,
        create_dirs: bool = True,
    ):
        super().__init__(
            game_version,
            country_code,
            apk_folder,
            allowed_script_mods,
            is_modded,
            use_pkg_name_for_folder,
            pkg_name,
            create_dirs,
        )
        self.smali_handler: tbcml.SmaliHandler | None = None

    def is_apk(self) -> bool:
        return True

    def init_paths(self, create_dirs: bool = True):
        super().init_paths(create_dirs)
        self.smali_original_path = self.output_path.add("smali-original")

        self.smali_non_original_path = self.output_path.add("smali-new")

        self.smali_non_original_path.remove_tree()

    @staticmethod
    def run_apktool(command: str) -> tbcml.CommandResult:
        apktool_path = tbcml.Path.get_lib("apktool.jar")
        if not apktool_path.is_valid():
            raise ValueError("Apktool path is not valid")
        return tbcml.Command(f"java -jar '{apktool_path}' {command}").run()

    @staticmethod
    def is_apktool_installed() -> tbcml.Result:
        res = Apk.run_apktool("-version")
        if res.exit_code == 0:
            return tbcml.Result(True)

        return tbcml.Result.program_not_installed(
            prog_name="java",
        )

    @staticmethod
    def is_jarsigner_installed() -> tbcml.Result:
        cmd = tbcml.Command("jarsigner")
        res = cmd.run()
        if res.exit_code == 0:
            return tbcml.Result(True)

        return tbcml.Result.program_not_installed(
            prog_name="Jarsigner or java",
        )

    @staticmethod
    def is_apksigner_installed() -> tbcml.Result:
        cmd = tbcml.Command("apksigner")
        res = cmd.run()
        if res.exit_code == 0:
            return tbcml.Result(True)

        return tbcml.Result.program_not_installed(
            prog_name="apksigner or java",
        )

    @staticmethod
    def is_zipalign_installed() -> tbcml.Result:
        cmd = tbcml.Command("zipalign")
        res = cmd.run()
        if res.exit_code == 2:
            return tbcml.Result(True)

        return tbcml.Result.program_not_installed(
            prog_name="zipalign or android sdk",
        )

    @staticmethod
    def is_keytool_installed() -> tbcml.Result:
        cmd = tbcml.Command("keytool")
        res = cmd.run()
        if res.exit_code == 0:
            return tbcml.Result(True)

        return tbcml.Result.program_not_installed(prog_name="keytool or java")

    def did_use_apktool(self, base_path: tbcml.Path | None = None) -> bool:
        if base_path is None:
            base_path = self.get_xapk_path("base")
        return base_path.add("apktool.yml").exists()

    def has_decoded_resources(self) -> bool:
        manifest_path = self.get_manifest_path()
        if not manifest_path.exists():
            return False
        return manifest_path.readable()

    def extract(
        self,
        force: bool = False,
        decode_resources: bool = True,
        use_apktool: bool = True,
    ) -> tbcml.Result:
        if self.original_extracted_path.generate_dirs().has_files() and not force:
            if (
                self.has_decoded_resources() == decode_resources
                and use_apktool == self.did_use_apktool()
            ):
                self.copy_extracted()

                return tbcml.Result(True)

        if not self.pkg_path.exists():
            return tbcml.Result.file_not_found(self.pkg_path)

        res = self.extract_apk(decode_resources, use_apktool)
        if not res:
            return res

        if self.is_xapk():
            return self.extract_xapk(decode_resources, use_apktool)
        return res

    def extract_apk(
        self,
        decode_resources: bool = True,
        use_apktool: bool = True,
        apk_path: tbcml.Path | None = None,
        output_path: tbcml.Path | None = None,
    ):
        if use_apktool:
            return self.extract_apktool(decode_resources, apk_path, output_path)
        else:
            return self.extract_zip(
                apk_path, output_path
            )  # TODO: decode resources without apktool

    def extract_zip(
        self,
        apk_path: tbcml.Path | None = None,
        output_path: tbcml.Path | None = None,
    ) -> tbcml.Result:

        if apk_path is None:
            apk_path = self.pkg_path

        if not apk_path.exists():
            return tbcml.Result.file_not_found(apk_path)

        copy_extracted = False

        if output_path is None:
            output_path = self.original_extracted_path
            self.original_extracted_path.remove().generate_dirs()
            copy_extracted = True

        with tbcml.TempFolder() as path:
            zip_file = tbcml.Zip(apk_path.read())
            zip_file.extract(path)
            path.copy(output_path)

        if copy_extracted:
            self.copy_extracted(force=True)
        return tbcml.Result(True)

    def extract_apktool(
        self,
        decode_resources: bool = True,
        apk_path: tbcml.Path | None = None,
        output_path: tbcml.Path | None = None,
    ) -> tbcml.Result:
        if not (res := self.is_apktool_installed()):
            return res

        if apk_path is None:
            apk_path = self.pkg_path

        copy_extracted = False

        if output_path is None:
            output_path = self.original_extracted_path
            self.original_extracted_path.remove().generate_dirs()
            copy_extracted = True

        decode_resources_str = "-r" if not decode_resources else ""
        with (
            tbcml.TempFolder() as path
        ):  # extract to temp folder so if user cancels mid-extraction nothing bad happens
            cmd = f"d -f -s {decode_resources_str} '{apk_path}' -o '{path}'"
            res = self.run_apktool(cmd)
            if res.exit_code != 0:
                return tbcml.Result(
                    False,
                    error=f"Failed to extract APK: {res.result}. Command: apktool {cmd}",
                )

            path.copy(output_path)

        if copy_extracted:
            self.copy_extracted(force=True)
        return tbcml.Result(True)

    def extract_smali(
        self,
        decode_resources: bool = True,
    ) -> tbcml.Result:

        # TODO: support xapk

        if not (res := self.is_apktool_installed()):
            return res

        decode_resources_str = "-r" if not decode_resources else ""

        with tbcml.TempFolder() as temp_folder:
            cmd = f"d -f {decode_resources_str} '{self.pkg_path}' -o '{temp_folder}'"
            res = self.run_apktool(cmd)
            if res.exit_code != 0:
                return tbcml.Result(
                    False,
                    error=f"Failed to extract APK: {res.result}. Command: apktool {cmd}",
                )

            folders = temp_folder.glob("smali*")
            for folder in folders:
                new_folder = self.extracted_path.add(folder.basename())
                folder.copy(new_folder)
            apktool_yml = temp_folder.add("apktool.yml")
            apktool_yml.copy(self.extracted_path)

            dex_files = self.extracted_path.glob("*.dex")
            for dex_file in dex_files:
                dex_file.remove()

        return tbcml.Result(True)

    def pack(
        self,
        use_apktool: bool | None = None,
    ) -> tbcml.Result:
        if use_apktool is None:
            use_apktool = self.did_use_apktool()
        else:
            if self.did_use_apktool() != use_apktool:
                if self.did_use_apktool():
                    print(
                        "WARNING: apktool was used when extracting, but you have specified to not use it to pack the apk"
                    )
                else:
                    print(
                        "WARNING: apktool was not used when extracting, but you have specified to use it to pack the apk"
                    )
        if self.is_xapk():
            return self.pack_xapk(use_apktool)
        else:
            return self.pack_apk(use_apktool)

    def pack_apk(
        self,
        use_apktool: bool | None = None,
        extracted_path: tbcml.Path | None = None,
        output_path: tbcml.Path | None = None,
    ):
        if use_apktool:
            return self.pack_apktool(extracted_path, output_path)
        return self.pack_zip(extracted_path, output_path)

    def _xapk_pack(
        self, dir: tbcml.Path, apk_path: tbcml.Path, use_apktool: bool | None = None
    ):
        res = self.pack_apk(
            use_apktool,
            dir,
            apk_path,
        )
        if not res:
            return res
        res = self.sign(apk_path=apk_path)
        return res

    def pack_xapk(self, use_apktool: bool | None = None):
        split_apks_dir = self.output_path.add("split_apks").remove().generate_dirs()
        funcs: list[Callable[..., Any]] = []
        args: list[tuple[tbcml.Path, tbcml.Path, bool | None]] = []
        for path in self.get_xapk_id_dirs():
            file_name = path.basename() + ".apk"
            funcs.append(self._xapk_pack)
            args.append((path, split_apks_dir.add(file_name), use_apktool))

        ress = tbcml.run_in_threads(funcs, args)
        for res in ress:
            if not res:
                return res

        return self.pack_zip(split_apks_dir, final_xapk_pack=True)

    def pack_zip(
        self,
        extracted_path: tbcml.Path | None = None,
        output_path: tbcml.Path | None = None,
        final_xapk_pack: bool = False,
    ) -> tbcml.Result:
        if self.has_decoded_resources() and not final_xapk_pack:
            print(
                "WARNING: The resources for the apk seem to be decoded, this will cause issues as they will not be encoded atm."
            )

        if extracted_path is None:
            extracted_path = self.extracted_path

        if output_path is None:
            output_path = self.final_pkg_path

        tbcml.Zip.compress_directory(
            extracted_path, output_path, extensions_to_store=["so", "arsc"]
        )
        return tbcml.Result(True)

    def pack_apktool(
        self,
        extracted_path: tbcml.Path | None = None,
        output_path: tbcml.Path | None = None,
    ) -> tbcml.Result:
        if not (res := self.is_apktool_installed()):
            return res

        if extracted_path is None:
            extracted_path = self.extracted_path

        if output_path is None:
            output_path = self.final_pkg_path

        cmd = f"b '{extracted_path}' -o '{output_path}'"
        res = self.run_apktool(cmd)
        if res.exit_code != 0:
            return tbcml.Result(
                False, error=f"Failed to pack APK: {res.result}. Command: {cmd}"
            )
        return tbcml.Result(True)

    def sign(
        self,
        use_jarsigner: bool = False,
        zip_align: bool = True,
        password: str = "TBCML_CUSTOM_APK",
        apk_path: tbcml.Path | None = None,
        is_final_xapk: bool = False,
    ) -> tbcml.Result:
        if is_final_xapk:
            return tbcml.Result(True)
        if not tbcml.Path(password).is_valid():
            return tbcml.Result(False, error=f"Password: {password} is not valid")
        if zip_align:
            if not (res := self.zip_align(apk_path)):
                return res
        if use_jarsigner:
            if not (res := self.is_jarsigner_installed()):
                return res
        else:
            if not (res := self.is_apksigner_installed()):
                return res
        if not (res := self.is_keytool_installed()):
            return res

        if apk_path is None:
            apk_path = self.final_pkg_path

        key_store_name = "tbcml.keystore"
        key_store_path = tbcml.Path.get_documents_folder().add(key_store_name)
        if not key_store_path.is_valid():
            return tbcml.Result(
                False, error=f"Key store path is not valid: {key_store_path}"
            )
        if not key_store_path.exists():
            cmd = tbcml.Command(
                f"keytool -genkey -v -keystore '{key_store_path}' -alias tbcml -keyalg RSA -keysize 2048 -validity 10000 -storepass '{password}' -keypass '{password}' -dname 'CN=, OU=, O=, L=, S=, C='",
            )
            res = cmd.run()
            if res.exit_code != 0:
                return tbcml.Result(
                    False,
                    error=f"Failed to generate keystore: {res.result}. Command: {cmd.cwd}",
                )

        if use_jarsigner:
            cmd = tbcml.Command(
                f"jarsigner -verbose -sigalg SHA256withRSA -digestalg SHA-256 -keystore '{key_store_path}' '{apk_path}' tbcml",
            )
            res = cmd.run(password)
        else:
            cmd_txt = f"apksigner sign --ks '{key_store_path}' --ks-key-alias tbcml --ks-pass 'pass:{password}' --key-pass 'pass:{password}'"
            cmd_txt += f" '{apk_path}'"
            cmd = tbcml.Command(cmd_txt)
            res = cmd.run()
        if res.exit_code != 0:
            return tbcml.Result(
                False, error=f"Failed to sign apk: {res.result}. Command: {cmd.cwd}"
            )
        return tbcml.Result(True)

    def get_xapk_id_dirs(self) -> list[tbcml.Path]:
        if self.is_xapk():
            return self.extracted_path.get_dirs()
        return [self.extracted_path]

    def get_lib_paths(self) -> dict[str, tbcml.Path]:
        paths: dict[str, tbcml.Path] = {}
        to_check = self.get_xapk_id_dirs()

        for dir1 in to_check:
            for dir in dir1.add("lib").get_dirs():
                arc = dir.basename()
                paths[arc] = dir
        return paths

    def zip_align(self, output_path: tbcml.Path | None = None) -> tbcml.Result:
        if output_path is None:
            output_path = self.final_pkg_path
        if not (res := self.is_zipalign_installed()):
            return res
        apk_path = output_path.change_name(
            output_path.get_file_name_without_extension() + "-aligned.apk"
        )
        cmd = tbcml.Command(f"zipalign -f -p 4 '{output_path}' '{apk_path}'")
        cmd.run()
        apk_path.copy(output_path)
        cmd.run()
        apk_path.copy(output_path)
        apk_path.remove()
        return tbcml.Result(True)

    def load_packs_into_game(
        self,
        packs: tbcml.GamePacks,
        copy_path: tbcml.Path | None = None,
        save_in_modded_pkgs: bool = False,
        progress_callback: (
            Callable[[tbcml.PKGProgressSignal], bool | None] | None
        ) = None,
        use_apktool: bool | None = None,
        sign_password: str | None = None,
    ) -> tbcml.Result:
        if progress_callback is None:
            progress_callback = lambda _: None

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

        if not (res := self.pack(use_apktool=use_apktool)):
            return res

        if progress_callback(tbcml.PKGProgressSignal.SIGN) is False:
            return tbcml.Result(False)

        if sign_password is None:
            if not (res := self.sign(is_final_xapk=self.is_xapk())):
                return res
        else:
            if not (
                res := self.sign(password=sign_password, is_final_xapk=self.is_xapk())
            ):
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

    @staticmethod
    def get_default_pkg_folder() -> tbcml.Path:
        return tbcml.Path.get_documents_folder().add("APKs").generate_dirs()

    @staticmethod
    def get_all_downloaded(
        all_pkg_dir: tbcml.Path | None = None, cleanup: bool = False
    ) -> list["Apk"]:
        """
        Get all downloaded APKs

        Returns:
            list[APK]: List of APKs
        """
        return tbcml.Pkg.get_all_downloaded_pkgs(Apk, all_pkg_dir, cleanup)

    @staticmethod
    def get_all_pkgs_cc(
        cc: tbcml.CountryCode, pkg_folder: tbcml.Path | None = None
    ) -> list["Apk"]:
        """
        Get all APKs for a country code

        Args:
            cc (country_code.CountryCode): Country code
            pkg_folder (tbcml.Path | None, optional): APK folder, defaults to default APK folder

        Returns:
            list[APK]: List of APKs
        """
        return tbcml.Pkg.get_all_pkgs_cc_pkgs(cc, pkg_folder, Apk)

    @staticmethod
    def get_all_versions_v2(
        cc: tbcml.CountryCode,
        apk_list_url: str = "https://raw.githubusercontent.com/fieryhenry/BCData/master/apk_list.json",
    ) -> list[tbcml.GameVersion]:
        response = tbcml.RequestHandler(apk_list_url).get()
        json = response.json()
        versions: list[tbcml.GameVersion] = []
        cc_versions = json.get(cc.get_code())
        if cc_versions is None:
            return []
        for version in cc_versions:
            versions.append(tbcml.GameVersion.from_string(version))
        return versions

    @staticmethod
    def get_all_versions(cc: tbcml.CountryCode):
        versions: set[int] = set()
        versions.update([gv.game_version for gv in Apk.get_all_versions_v1(cc)])
        versions.update([gv.game_version for gv in Apk.get_all_versions_uptodown(cc)])
        versions.update([gv.game_version for gv in Apk.get_all_versions_v2(cc)])

        versions_ls: list[int] = list(versions)
        versions_ls.sort()

        versions_obj: list[tbcml.GameVersion] = []

        for v in versions_ls:
            versions_obj.append(tbcml.GameVersion(v))

        return versions_obj

    @staticmethod
    def get_all_versions_v1(
        cc: tbcml.CountryCode,
    ) -> list[tbcml.GameVersion]:
        """
        Get all APK versions

        Args:
            cc (country_code.CountryCode): Country code

        Returns:
            game_version.GameVersion: List of APK versions
        """

        url = Apk.get_apk_version_url(cc)
        scraper = cloudscraper.create_scraper()  # type: ignore
        resp = scraper.get(url)
        soup = bs4.BeautifulSoup(resp.text, "html.parser")
        versionwrapp = soup.find("ul", {"class": "ver-wrap"})
        if not isinstance(versionwrapp, bs4.element.Tag):
            return []
        versions: list[tbcml.GameVersion] = []
        for version in versionwrapp.find_all("li"):
            if not isinstance(version, bs4.element.Tag):
                continue
            version_anchor = version.find("a")
            if not isinstance(version_anchor, bs4.element.Tag):
                continue
            version = version_anchor.get_attribute_list("data-dt-versioncode")[0]
            versions.append(tbcml.GameVersion(int(version[:-1])))
        return versions

    @staticmethod
    def get_latest_version_v1(cc: tbcml.CountryCode):
        versions = Apk.get_all_versions_v1(cc)
        new_versions = Apk.get_all_versions_uptodown(cc)
        for version in new_versions:
            if version not in versions:
                versions.append(version)
        if not versions:
            return None
        versions.sort(key=lambda version: version.game_version, reverse=True)

        return versions[0]

    @staticmethod
    def get_latest_version_v2(cc: tbcml.CountryCode):
        versions = Apk.get_all_versions_v2(cc)
        if len(versions) == 0:
            return None
        versions.sort(key=lambda version: version.game_version, reverse=True)
        return versions[0]

    @staticmethod
    def get_latest_version(cc: tbcml.CountryCode, v2: bool = True, v1: bool = True):
        version_v1 = None
        version_v2 = None
        if v1:
            version_v1 = Apk.get_latest_version_v1(cc)
        if v2:
            version_v2 = Apk.get_latest_version_v2(cc)

        if version_v1 is None:
            return version_v2
        if version_v2 is None:
            return version_v1
        if version_v1.game_version > version_v2.game_version:
            return version_v1
        return version_v2

    def get_download_stream(
        self,
        scraper: cloudscraper.CloudScraper,
        url: str,
    ) -> requests.Response | None:
        try:
            stream = scraper.get(url, stream=True, timeout=10)
        except requests.RequestException:
            return None
        if stream.headers.get("content-length") is None:
            return None
        return stream

    def download_v2(
        self,
        progress: Callable[[float, int, int, bool], bool | None] | None = Pkg.progress,
        force: bool = False,
        apk_list_url: str = "https://raw.githubusercontent.com/fieryhenry/BCData/master/apk_list.json",
    ) -> tbcml.Result:
        if self.pkg_path.exists() and not force:
            return tbcml.Result(True)

        response = tbcml.RequestHandler(apk_list_url).get()
        json = response.json()
        cc_versions = json.get(self.country_code.get_code())
        if cc_versions is None:
            return tbcml.Result(
                False,
                error=f"Could not find apk urls for country code: {self.country_code}",
            )
        url = cc_versions.get(self.game_version.to_string())
        if url is None:
            return tbcml.Result(
                False, error=f"Could not find apk download url for {self.game_version}"
            )

        stream = tbcml.RequestHandler(url).get_stream()
        if stream.status_code == 404:
            return tbcml.Result(False, error=f"Download url returned 404: {url}")
        _total_length = int(stream.headers.get("content-length"))  # type: ignore

        dl = 0
        chunk_size = 1024
        buffer: list[bytes] = []
        for d in stream.iter_content(chunk_size=chunk_size):
            dl += len(d)
            buffer.append(d)
            if progress is not None:
                res = progress(dl / _total_length, dl, _total_length, True)
                if res is not None and not res:
                    return tbcml.Result(
                        False, error="Download stopped by download callback"
                    )

        apk = tbcml.Data(b"".join(buffer))
        apk.to_file(self.pkg_path)
        return tbcml.Result(True)

    def download(
        self,
        progress: Callable[[float, int, int, bool], bool | None] | None = Pkg.progress,
        force: bool = False,
        skip_signature_check: bool = False,
    ) -> tbcml.Result:
        if self.pkg_path.exists() and not force:
            return tbcml.Result(True)

        if not self.is_apksigner_installed():
            skip_signature_check = True

        sig_failed = False
        if res := self.download_v1(progress, force):
            if skip_signature_check:
                return tbcml.Result(True)
            if self.is_original(self.pkg_path):
                return tbcml.Result(True)
            sig_failed = True

        if res := self.download_v2(progress, force):
            if skip_signature_check:
                return tbcml.Result(True)
            if self.is_original(self.pkg_path):
                return tbcml.Result(True)
            sig_failed = True

        if sig_failed and not skip_signature_check:
            print(
                "WARNING: APK signature is not valid. You may have downloaded a non-ponos battle cats apk. To disable this warning pass `skip_signature_check = True` to the download function. If the apk is an xapk, then the signature is not checked at the moment"
            )
            return tbcml.Result(True)

        return res

    def download_v1(
        self,
        progress: Callable[[float, int, int, bool], bool | None] | None = Pkg.progress,
        force: bool = False,
    ) -> tbcml.Result:
        if self.pkg_path.exists() and not force:
            return tbcml.Result(True)
        if self.download_v1_all(progress):
            return tbcml.Result(True)
        return self.download_apk_uptodown(
            progress,
        )

    def download_v1_all(
        self,
        progress: Callable[[float, int, int, bool], bool | None] | None = Pkg.progress,
    ) -> tbcml.Result:
        url = self.get_download_url()
        scraper = cloudscraper.create_scraper()  # type: ignore
        scraper.headers.update(
            {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36"
            }
        )
        stream = self.get_download_stream(scraper, url)
        if stream is None:
            stream = self.get_download_stream(scraper, url[:-1] + "1")
        # if stream is None:
        #    stream = self.get_download_stream(scraper, url.replace("APK", "XAPK"))
        # sif stream is None:
        # stream = self.get_download_stream(
        #    scraper, url.replace("APK", "XAPK")[:-1] + "1"
        # )
        if stream is None:
            return tbcml.Result(
                False, error=f"Failed to get download stream for url: {url}"
            )

        content_length = stream.headers.get("content-length")
        if content_length is None:
            return tbcml.Result(
                False, error=f"Failed to get content-length header for url: {url}"
            )

        _total_length = int(content_length)

        dl = 0
        chunk_size = 1024
        buffer: list[bytes] = []
        for d in stream.iter_content(chunk_size=chunk_size):
            dl += len(d)
            buffer.append(d)
            if progress is not None:
                res = progress(dl / _total_length, dl, _total_length, True)
                if res is not None and not res:
                    return tbcml.Result(
                        False, error="Download was stopped by progress callback"
                    )

        apk = tbcml.Data(b"".join(buffer))
        apk.to_file(self.pkg_path)
        return tbcml.Result(True)

    @staticmethod
    def get_uptodown_pkg_name(country_code: tbcml.CountryCode) -> str:
        if country_code == tbcml.CountryCode.EN:
            return "the-battle-cats"
        elif country_code == tbcml.CountryCode.JP:
            return "the-battle-cats-jp"
        elif country_code == tbcml.CountryCode.KR:
            return "jp-co-ponos-battlecatskr"
        elif country_code == tbcml.CountryCode.TW:
            return "jp-co-ponos-battlecatstw"

    def download_apk_uptodown(
        self,
        progress: Callable[[float, int, int, bool], bool | None] | None = Pkg.progress,
    ) -> tbcml.Result:
        urls = Apk.get_uptodown_apk_urls(self.country_code)
        if not urls:
            return tbcml.Result(
                False,
                error=f"Failed to get APK URLs for country_code: {self.country_code}",
            )

        url: str | None = urls.get(self.game_version.to_string())
        if not url:
            return tbcml.Result(
                False,
                error=f"The download url for {self.game_version} could not be found.",
            )

        response = tbcml.RequestHandler(url, Apk.get_uptdown_headers()).get()
        soup = bs4.BeautifulSoup(response.text, "html.parser")
        post_download_class = soup.find("button", {"id": "detail-download-button"})
        if not isinstance(post_download_class, bs4.element.Tag):
            return tbcml.Result(
                False,
                error="Could not locate download button button when looking for apk download url.",
            )
        data_url = post_download_class.get_attribute_list("data-url")[0]
        url = "https://dw.uptodown.com/dwn/" + data_url
        headers = Apk.get_uptdown_headers()
        stream = tbcml.RequestHandler(url, headers).get_stream()
        content_length = stream.headers.get("content-length")
        if content_length is None:
            return tbcml.Result(
                False, error="Could not get content-length header when downloading apk"
            )
        _total_length = int(content_length)

        dl = 0
        chunk_size = 1024
        buffer: list[bytes] = []
        for d in stream.iter_content(chunk_size=chunk_size):
            dl += len(d)
            buffer.append(d)
            if progress is not None:
                res = progress(dl / _total_length, dl, _total_length, True)
                if res is not None and not res:
                    return tbcml.Result(
                        False, error="Download stopped by progress callback"
                    )

        apk = tbcml.Data(b"".join(buffer))
        apk.to_file(self.pkg_path)
        return tbcml.Result(True)

    def get_uptodown_apk_url(self, apk_url: str):
        resp = tbcml.RequestHandler(apk_url).get()
        soup = bs4.BeautifulSoup(resp.text, "html.parser")
        download_button = soup.find("button", {"class": "button download"})
        if not isinstance(download_button, bs4.element.Tag):
            return None
        return str(download_button.get_attribute_list("data-url")[0])

    @staticmethod
    def get_uptdown_headers() -> dict[str, Any]:
        return {"User-Agent": "A"}

    @staticmethod
    def get_uptodown_app_id(country_code: tbcml.CountryCode) -> str | None:
        package_name = Apk.get_uptodown_pkg_name(country_code)
        url = f"https://{package_name}.en.uptodown.com/android/versions"
        try:
            resp = tbcml.RequestHandler(url, Apk.get_uptdown_headers()).get()
        except requests.RequestException:
            return None
        soup = bs4.BeautifulSoup(resp.text, "html.parser")
        app_details = soup.find("h1", {"id": "detail-app-name"})
        if not isinstance(app_details, bs4.element.Tag):
            return None
        app_id = app_details.get_attribute_list("code")[0]
        return app_id

    @staticmethod
    def get_uptodown_apk_json(country_code: tbcml.CountryCode) -> list[dict[str, Any]]:
        package_name = Apk.get_uptodown_pkg_name(country_code)
        app_id = Apk.get_uptodown_app_id(country_code)
        if app_id is None:
            return []
        counter = 0
        versions: list[dict[str, Any]] = []
        while True:
            url = f"https://{package_name}.en.uptodown.com/android/apps/{app_id}/versions/{counter}"
            resp = tbcml.RequestHandler(url, Apk.get_uptdown_headers()).get()
            versions_data = resp.json().get("data")
            if versions_data is None:
                break
            if len(versions_data) == 0:
                break
            for version_data in versions_data:
                versions.append(version_data)
            counter += 1
        return versions

    @staticmethod
    def get_uptodown_apk_urls(country_code: tbcml.CountryCode) -> dict[str, Any] | None:
        json_data = Apk.get_uptodown_apk_json(country_code)
        versions: list[str] = []
        urls: list[str] = []
        for data in json_data:
            versions.append(data["version"])
            urls.append(data["versionURL"])
        return dict(zip(versions, urls))

    def get_download_url(self) -> str:
        return f"https://d.apkpure.com/b/APK/jp.co.ponos.battlecats{self.country_code.get_patching_code()}?versionCode={self.game_version.game_version}0"

    @staticmethod
    def get_all_versions_uptodown(
        cc: tbcml.CountryCode,
    ) -> list[tbcml.GameVersion]:
        apk_urls = Apk.get_uptodown_apk_urls(cc)
        if apk_urls is None:
            return []
        versions: list[tbcml.GameVersion] = []
        for version in apk_urls.keys():
            versions.append(tbcml.GameVersion.from_string(version))
        return versions

    @staticmethod
    def get_apk_version_url(cc: tbcml.CountryCode) -> str:
        if cc == tbcml.CountryCode.JP:
            url = "https://apkpure.com/%E3%81%AB%E3%82%83%E3%82%93%E3%81%93%E5%A4%A7%E6%88%A6%E4%BA%89/jp.co.ponos.battlecats/versions"
        elif cc == tbcml.CountryCode.KR:
            url = "https://apkpure.com/%EB%83%A5%EC%BD%94-%EB%8C%80%EC%A0%84%EC%9F%81/jp.co.ponos.battlecatskr/versions"
        elif cc == tbcml.CountryCode.TW:
            url = "https://apkpure.com/%E8%B2%93%E5%92%AA%E5%A4%A7%E6%88%B0%E7%88%AD/jp.co.ponos.battlecatstw/versions"
        elif cc == tbcml.CountryCode.EN:
            url = (
                "https://apkpure.com/the-battle-cats/jp.co.ponos.battlecatsen/versions"
            )
        return url

    @staticmethod
    def clean_up(apk_folder: tbcml.Path | None = None):
        Apk.get_all_downloaded_pkgs(Apk, apk_folder, cleanup=True)

    @staticmethod
    def get_package_name_version_from_apk(apk_path: tbcml.Path):
        if not apk_path.is_valid():
            raise ValueError("APK path is not valid")
        cmd = f"aapt dump badging '{apk_path}'"
        result = tbcml.Command(cmd).run()
        if not result.success:
            return None, None
        output = result.result
        package_name = ""
        version_name = ""
        for line in output.splitlines():
            if "versionName" in line:
                version_name = line.split("versionName='")[1].split("'")[0]
            if "package: name=" in line:
                package_name = line.split("name='")[1].split("'")[0]

        cc_str = package_name.replace("jp.co.ponos.battlecats", "")
        cc = tbcml.CountryCode.from_patching_code(cc_str)
        gv = tbcml.GameVersion.from_string(version_name)

        return cc, gv

    @staticmethod
    def get_sha256_cert_hash(path: tbcml.PathStr) -> str | None:
        path = tbcml.Path(path)
        if not path.is_valid():
            raise ValueError("APK path is not valid")
        cmd = f"apksigner verify --print-certs '{path}'"
        result = tbcml.Command(cmd).run()
        if not result.success:
            return None
        output = result.result
        for line in output.splitlines():
            type, hash = line.split(":", 1)
            type = type.split(" ")[-2].strip().upper()
            hash = hash.strip().lower()
            if type != "SHA-256":
                continue
            return hash
        return None

    def get_sha256_cert_hash_cls(self) -> str | None:
        return Apk.get_sha256_cert_hash(self.pkg_path)

    @staticmethod
    def is_original(
        apk_path: tbcml.PathStr | None = None, hash: str | None = None
    ) -> bool:
        if hash is None and apk_path is not None:
            hash = Apk.get_sha256_cert_hash(apk_path)
            if hash is None:
                return False
        return (
            hash == "baf876d554213331c6fe5f6bbf9ae9af2f95c20e82b14bc232b0ac3a77680cb1"
        )

    def is_original_cls(self) -> bool:
        return Apk.is_original(self.pkg_path)

    @staticmethod
    def from_pkg_path(
        pkg_path: tbcml.Path,
        cc_overwrite: tbcml.CountryCode | None = None,
        gv_overwrite: tbcml.GameVersion | None = None,
        pkg_folder: tbcml.Path | None = None,
        allowed_script_mods: bool = True,
        skip_signature_check: bool = False,
        overwrite_pkg: bool = True,
    ) -> tuple[Apk | None, tbcml.Result]:
        is_modded = False

        if not pkg_path.exists():
            return None, tbcml.Result.file_not_found(pkg_path)

        if not Apk.is_apksigner_installed():
            skip_signature_check = True
            is_modded = False

        cc, gv = Apk.get_package_name_version_from_apk(pkg_path)

        if cc is None:
            cc = cc_overwrite
        if gv is None:
            gv = gv_overwrite

        if gv is None or cc is None:
            return None, tbcml.Result(
                False, error="Failed to get country code or game version from apk."
            )

        if not skip_signature_check:
            is_modded = not Apk.is_original(pkg_path)

        apk = Apk(
            gv,
            cc,
            apk_folder=pkg_folder,
            allowed_script_mods=allowed_script_mods,
            is_modded=is_modded,
        )
        if overwrite_pkg:
            pkg_path.copy(apk.pkg_path)
            apk.original_extracted_path.remove_tree().generate_dirs()
        return apk, tbcml.Result(True)

    def get_architectures(self) -> list[str]:
        return list(self.get_lib_paths().keys())

    def get_native_lib_path(self, architecture: str) -> tbcml.Path | None:
        arc_path = self.get_lib_path(architecture)
        if arc_path is None:
            return None
        bin_1 = arc_path.add("libnative-lib.so")
        if bin_1.exists():
            return bin_1
        else:
            return arc_path.add("libbattlecats-jni.so")

    def is_java(self):
        for arc in self.get_architectures():
            path = self.get_lib_path(arc)
            if path is not None:
                return path.add("libbattlecats-jni.so").exists()
        return True

    def get_smali_handler(self) -> tbcml.SmaliHandler:
        if self.smali_handler is None:
            self.smali_handler = tbcml.SmaliHandler(self)
        return self.smali_handler

    def inject_smali(self, library_name: str):
        self.get_smali_handler().inject_load_library(library_name)

    def get_lib_path(self, architecture: str) -> tbcml.Path | None:
        return self.get_lib_paths().get(architecture)

    def add_to_lib_folder(
        self, architecture: str, library_path: tbcml.Path
    ) -> tbcml.Result:
        lib_folder_path = self.get_lib_path(architecture)
        if lib_folder_path is None:
            return tbcml.Result(
                False, error=f"Could not find lib folder for {architecture}"
            )
        library_path.copy(lib_folder_path)
        new_name = library_path.basename()
        if not library_path.basename().startswith("lib"):
            new_name = f"lib{library_path.basename()}"
        if library_path.get_extension() != "so":
            new_name = f"{new_name}.so"
        curr_path = lib_folder_path.add(library_path.basename())
        curr_path.rename(new_name, overwrite=True)
        return tbcml.Result(True)

    def get_libgadget_script_path(self):
        return tbcml.Path("libbc_script.js.so")

    def get_libgadget_config_path(self):
        return tbcml.Path("libfrida-gadget.config.so")

    def get_manifest_path(self) -> tbcml.Path:
        return self.get_xapk_path("base").add("AndroidManifest.xml")

    def parse_manifest(self) -> tbcml.XML | None:
        return self.parse_xml(self.get_manifest_path())

    def parse_xml(self, path: tbcml.Path) -> tbcml.XML | None:
        try:
            return tbcml.XML(path.read())
        except Exception:
            return None

    def set_manifest(self, manifest: tbcml.XML):
        manifest.to_file(self.get_manifest_path())

    def get_pack_location(self) -> tbcml.Path:
        base_path = self.get_xapk_path("InstallPack")
        if self.is_java():
            return base_path.add("res").add("raw")
        return base_path.add("assets")

    def get_original_pack_location(self) -> tbcml.Path:
        base_path = self.get_xapk_path("InstallPack", original=True)
        if self.is_java():
            return base_path.add("res").add("raw")
        return base_path.add("assets")

    def get_audio_extensions(self) -> list[str]:
        return ["caf", "ogg"]

    def audio_file_startswith_snd(self) -> bool:
        return True

    def get_xapk_path(self, id: str, original: bool = False):
        base_path = (
            self.extracted_path if not original else self.original_extracted_path
        )

        if self.is_xapk():
            if id == "base":
                id = self.get_base_xapk_package()
            return base_path.add(id)
        return base_path

    def get_assets_folder_path(self) -> tbcml.Path:
        return self.get_xapk_path("InstallPack").add("assets")

    def get_asset(self, asset_name: tbcml.PathStr) -> tbcml.Path:
        return self.get_assets_folder_path().add(asset_name)

    def apply_mod_smali(self, mod: tbcml.Mod):
        if mod.smali.is_empty():
            return
        self.get_smali_handler().inject_into_on_create(mod.smali.get_list())

    def set_allow_backup(self, allow_backup: bool):
        manifest = self.parse_manifest()
        if manifest is None:
            return
        path = "application"
        if allow_backup:
            manifest.set_attribute(path, "android:allowBackup", "true")
        else:
            manifest.set_attribute(path, "android:allowBackup", "false")
        self.set_manifest(manifest)

    def add_frida_scripts(
        self,
        scripts: dict[str, str],
        inject_native_lib: bool = True,
        inject_smali: bool = False,
    ):
        super().add_frida_scripts(scripts, inject_native_lib, inject_smali)
        self.set_extract_native_libs(True)

    def set_extract_native_libs(self, extract: bool):
        manifest = self.parse_manifest()
        if manifest is None:
            return
        path = "application"
        if extract:
            manifest.set_attribute(path, "android:extractNativeLibs", "true")
        else:
            manifest.set_attribute(path, "android:extractNativeLibs", "false")

        self.set_manifest(manifest)

    def set_debuggable(self, debuggable: bool):
        manifest = self.parse_manifest()
        if manifest is None:
            return
        path = "application"
        if debuggable:
            manifest.set_attribute(path, "android:debuggable", "true")
        else:
            manifest.set_attribute(path, "android:debuggable", "false")
        self.set_manifest(manifest)

    def get_values_xml_path(self, name: str):
        return self.get_xapk_path("base").add("res").add("values").add(f"{name}.xml")

    def load_xml(self, name: str) -> tbcml.XML | None:
        strings_xml = self.get_values_xml_path(name)
        if not strings_xml.exists():
            return None
        return tbcml.XML(strings_xml.read())

    def save_xml(self, name: str, xml: tbcml.XML):
        xml.to_file(self.get_values_xml_path(name))

    def set_string(
        self, name: str, value: str, include_lang: bool, lang: str | None = None
    ):
        if self.country_code == tbcml.CountryCode.EN and include_lang:
            if lang is None:
                lang = "en"
            name = f"{name}_{lang}"

        return self.edit_xml_string(name, value)

    def get_string(self, name: str, include_lang: bool, lang: str | None = None):
        if self.country_code == tbcml.CountryCode.EN and include_lang:
            if lang is None:
                lang = "en"
            name = f"{name}_{lang}"

        return self.get_xml_string(name)

    def edit_xml_string(self, name: str, value: str) -> bool:
        strings_xml = self.load_xml("strings")
        if strings_xml is None:
            return False
        strings = strings_xml.get_elements("string")
        for string in strings:
            if string.get("name") == name:
                string.text = value
                break
        self.save_xml("strings", strings_xml)
        return True

    def get_xml_string(self, name: str) -> str | None:
        strings_xml = self.load_xml("strings")
        if strings_xml is None:
            return None
        strings = strings_xml.get_elements("string")
        for string in strings:
            if string.get("name") == name:
                return string.text
        return None

    def replace_str_manifest(self, old: str, new: str):
        manifest = self.get_manifest_path()
        manifest_str = manifest.read().to_str()
        manifest_str = manifest_str.replace(old, new)
        manifest.write(tbcml.Data(manifest_str))

    def apply_pkg_name(self, package_name: str) -> bool:
        manifest = self.parse_manifest()
        if manifest is None:
            return False

        current_package = manifest.get_attribute("manifest", "package")

        if current_package is not None:
            self.replace_str_manifest(current_package, package_name)

        manifest.set_attribute("manifest", "package", package_name)

        path = "application/provider"
        for provider in manifest.get_elements(path):
            attribute = manifest.get_attribute_name("android:authorities")
            name = provider.get(attribute)
            if name is None:
                continue

            parts = name.split(".")
            if len(parts) < 2:
                continue
            end = parts[-1]

            provider.set(attribute, package_name + "." + end)

        self.set_manifest(manifest)

        if not self.edit_xml_string("package_name", package_name):
            return False

        return True

    def read_pkg_name(self) -> str | None:
        manifest = self.parse_manifest()
        if manifest is None:
            return None
        name = manifest.get_attribute("manifest", "package")
        if name is None:
            return None
        return name

    def copy_to_android_download_folder(self):
        download_path = tbcml.Path.get_root().add(
            "sdcard", "Download", self.final_pkg_path.basename()
        )
        download_path.parent().generate_dirs()
        self.final_pkg_path.copy(download_path)

    def set_clear_text_traffic(self, clear_text_traffic: bool):
        manifest = self.parse_manifest()
        if manifest is None:
            return
        path = "application"
        if clear_text_traffic:
            manifest.set_attribute(path, "android:usesCleartextTraffic", "true")
        else:
            manifest.set_attribute(path, "android:usesCleartextTraffic", "false")
        self.set_manifest(manifest)

    def get_risky_extensions(self) -> list[str]:
        """Get extensions that if modified could contain malware.

        Returns:
            list[str]: List of risky extensions.
        """
        return [
            "so",
            "dex",
            "jar",
        ]

    def is_xapk(self) -> bool:
        return (
            self.extracted_path.add("InstallPack").exists()
            or self.extracted_path.add("unknown").add("InstallPack.apk").exists()
            or self.extracted_path.add("InstallPack.apk").exists()
        )

    def get_xapk_base_path(self, base_path: tbcml.Path | None = None) -> tbcml.Path:
        if base_path is None:
            base_path = self.extracted_path
        if base_path.add("unknown").exists():
            return base_path.add("unknown")
        return base_path

    def get_base_xapk_package(self) -> str:
        for path in self.get_xapk_id_dirs():
            id = path.basename()
            if id.startswith("config."):
                continue
            if id == "InstallPack":
                continue
            return id
        return "base"

    def extract_xapk(
        self, decode_resources: bool = True, use_apktool: bool = True
    ) -> tbcml.Result:
        self.original_extracted_path.copy(
            self.output_path.add("xapk_original").remove().generate_dirs()
        )

        self.original_extracted_path.remove()

        with tbcml.TempFolder(
            "xapk_extraction", path=self.output_path.add("xapk_extraction")
        ) as temp:
            extracted_path = temp.add("extracted")
            funcs: list[Callable[..., Any]] = []
            args: list[tuple[bool, bool, tbcml.Path, tbcml.Path]] = []
            for apk in self.get_xapk_base_path(
                self.output_path.add("xapk_original")
            ).get_files(r"\.apk$"):
                file_name = apk.get_file_name_without_extension()
                temp_path = extracted_path.add(file_name)
                funcs.append(self.extract_apk)
                args.append(
                    (
                        decode_resources,
                        use_apktool,
                        apk,
                        temp_path,
                    )
                )

            ress = tbcml.run_in_threads(funcs, args)
            for res in ress:
                if not res:
                    return res

            extracted_path.copy(self.original_extracted_path)

        self.copy_extracted()
        return tbcml.Result(True)

    @staticmethod
    def try_get_pkg_from_path(
        path: tbcml.Path,
        all_pkg_dir: tbcml.Path | None = None,
    ) -> tuple[Apk | None, tbcml.Result]:
        return Apk.try_get_pkg_from_path_pkg(path, all_pkg_dir=all_pkg_dir, clzz=Apk)

    def add_smali_mods(self, mods: list[tbcml.Mod]):
        if not self.is_allowed_script_mods():
            return
        for mod in mods:
            self.apply_mod_smali(mod)

    def prevent_so_compression(self):
        for dir in self.get_xapk_id_dirs():
            self._prevent_so_compression(dir)

    def _prevent_so_compression(self, base_path: tbcml.Path | None = None):
        if base_path is None:
            base_path = self.extracted_path
        if not self.did_use_apktool(base_path):
            return

        apktoolyml = base_path.add("apktool.yml")
        yamlo = tbcml.Yaml.from_file(apktoolyml)
        yaml = yamlo.yaml
        do_not_compress = yaml.get("doNotCompress", [])
        if "so" not in do_not_compress:
            do_not_compress.append("so")
        yaml["doNotCompress"] = do_not_compress

        yamlo.to_file(apktoolyml)

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
        use_apktool: bool | None = None,
        sign_password: str | None = None,
    ) -> tbcml.Result:
        if progress_callback is None:
            progress_callback = lambda _: None

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
            if progress_callback(tbcml.PKGProgressSignal.ADD_SMALI_MODS) is False:
                return tbcml.Result(False)
            self.add_smali_mods(mods)

            if progress_callback(tbcml.PKGProgressSignal.ADD_SCRIPT_MODS) is False:
                return tbcml.Result(False)
            self.add_script_mods(mods)

            if progress_callback(tbcml.PKGProgressSignal.ADD_PATCH_MODS) is False:
                return tbcml.Result(False)
            self.add_patch_mods(mods)

            self.prevent_so_compression()

            if progress_callback(tbcml.PKGProgressSignal.SET_MANIFEST_VALUES) is False:
                return tbcml.Result(False)

            self.set_allow_backup(True)
            self.set_debuggable(True)

            if add_modded_html:
                if progress_callback(tbcml.PKGProgressSignal.ADD_MODDED_HTML) is False:
                    return tbcml.Result(False)
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
                    use_apktool=use_apktool,
                    save_in_modded_pkgs=save_in_modded_pkgs,
                    progress_callback=progress_callback,
                    sign_password=sign_password,
                )
            ):
                return res
        else:
            if progress_callback(tbcml.PKGProgressSignal.DONE) is False:
                return tbcml.Result(False)

        return tbcml.Result(True)
