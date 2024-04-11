import enum
from typing import Any, Callable, Optional

import bs4
import cloudscraper  # type: ignore
import requests

import tbcml

from tbcml.io.pkg import Pkg, PkgType


class PKGProgressSignal(enum.Enum):
    """Progress Signal Enum"""

    START = 0
    LOAD_GAME_PACKS = 1
    ADD_SMALI_MODS = 2
    ADD_SCRIPT_MODS = 3
    ADD_PATCH_MODS = 4
    APPLY_MODS = 5
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
        game_version: "tbcml.GV",
        country_code: "tbcml.CC",
        apk_folder: Optional["tbcml.PathStr"] = None,
        allowed_script_mods: bool = True,
        is_modded: bool = False,
        use_pkg_name_for_folder: bool = False,
        pkg_name: Optional[str] = None,
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
        self.smali_handler: Optional[tbcml.SmaliHandler] = None

    def is_apk(self) -> bool:
        return True

    def init_paths(self, create_dirs: bool = True):
        super().init_paths(create_dirs)
        self.smali_original_path = self.output_path.add("smali-original")

        self.smali_non_original_path = self.output_path.add("smali-new")

        self.smali_non_original_path.remove_tree()

    @staticmethod
    def run_apktool(command: str) -> "tbcml.CommandResult":
        apktool_path = tbcml.Path.get_lib("apktool.jar")
        return tbcml.Command(f"java -jar {apktool_path} {command}").run()

    @staticmethod
    def check_apktool_installed() -> bool:
        res = Apk.run_apktool("-version")
        return res.exit_code == 0

    @staticmethod
    def check_jarsigner_installed() -> bool:
        cmd = tbcml.Command("jarsigner")
        res = cmd.run()
        return res.exit_code == 0

    @staticmethod
    def check_apksigner_installed() -> bool:
        cmd = tbcml.Command("apksigner")
        res = cmd.run()
        return res.exit_code == 0

    @staticmethod
    def check_zipalign_installed() -> bool:
        cmd = tbcml.Command("zipalign")
        res = cmd.run()
        return res.exit_code == 2

    @staticmethod
    def check_keytool_installed() -> bool:
        cmd = tbcml.Command("keytool")
        res = cmd.run()
        return res.exit_code == 0

    def check_display_apktool_error(self) -> bool:
        if self.check_apktool_installed():
            return True
        message = "Apktool or java is not installed. Please install it and add it to your PATH. You can download it from https://ibotpeaches.github.io/Apktool/install/"
        print(message)
        return False

    def check_display_jarsigner_error(self) -> bool:
        if self.check_jarsigner_installed():
            return True
        message = "Jarsigner or java is not installed. Please install it and add it to your PATH."
        print(message)
        return False

    @staticmethod
    def check_display_apk_signer_error() -> bool:
        if Apk.check_apksigner_installed():
            return True
        message = "Apksigner or android sdk is not installed. Please install it and add it to your PATH."
        print(message)
        return False

    def check_display_zipalign_error(self) -> bool:
        if self.check_zipalign_installed():
            return True
        message = "Zipalign or android sdk is not installed. Please install it and add it to your PATH."
        print(message)
        return False

    def check_display_keytool_error(self) -> bool:
        if self.check_keytool_installed():
            return True
        message = "Keytool or java is not installed. Please install it and add it to your PATH."
        print(message)
        return False

    def did_use_apktool(self) -> bool:
        return self.original_extracted_path.add("apktool.yml").exists()

    def has_decoded_resources(self) -> bool:
        manifest_path = self.original_extracted_path.add("AndroidManifest.xml")
        if not manifest_path.exists():
            return False
        return manifest_path.readable()

    def extract(
        self,
        force: bool = False,
        decode_resources: bool = True,
        use_apktool: bool = True,
    ) -> bool:
        if self.original_extracted_path.generate_dirs().has_files() and not force:
            if (
                self.has_decoded_resources() == decode_resources
                and use_apktool == self.did_use_apktool()
            ):
                self.copy_extracted()
                return True

        if not self.pkg_path.exists():
            print("APK file does not exist")
            return False

        if use_apktool:
            return self.extract_apktool(decode_resources)
        else:
            return self.extract_zip()  # TODO: decode resources without apktool

    def extract_zip(self):
        if not self.pkg_path.exists():
            return False
        with tbcml.TempFolder() as path:
            zip_file = tbcml.Zip(self.pkg_path.read())
            zip_file.extract(path)
            self.original_extracted_path.remove().generate_dirs()
            path.copy(self.original_extracted_path)

        self.copy_extracted(force=True)
        return True

    def extract_apktool(self, decode_resources: bool = True):
        if not self.check_display_apktool_error():
            return False
        decode_resources_str = "-r" if not decode_resources else ""
        with (
            tbcml.TempFolder() as path
        ):  # extract to temp folder so if user cancels mid-extraction nothing bad happens
            cmd = f"d -f -s {decode_resources_str} '{self.pkg_path}' -o '{path}'"
            res = self.run_apktool(cmd)
            if res.exit_code != 0:
                print(f"Failed to extract APK: {res.result}. Command: apktool {cmd}")
                return False
            self.original_extracted_path.remove().generate_dirs()
            path.copy(self.original_extracted_path)
        self.copy_extracted(force=True)
        return True

    def extract_smali(
        self,
        decode_resources: bool = True,
    ):

        if not self.check_display_apktool_error():
            return

        decode_resources_str = "-r" if not decode_resources else ""

        with tbcml.TempFolder() as temp_folder:
            res = self.run_apktool(
                f"d -f {decode_resources_str} '{self.pkg_path}' -o '{temp_folder}'"
            )
            if res.exit_code != 0:
                print(f"Failed to extract APK: {res.result}")
                return
            folders = temp_folder.glob("smali*")
            for folder in folders:
                new_folder = self.extracted_path.add(folder.basename())
                folder.copy(new_folder)
            apktool_yml = temp_folder.add("apktool.yml")
            apktool_yml.copy(self.extracted_path)

            dex_files = self.extracted_path.glob("*.dex")
            for dex_file in dex_files:
                dex_file.remove()

    def pack(
        self,
        use_apktool: Optional[bool] = None,
    ):
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
        if use_apktool:
            return self.pack_apktool()
        return self.pack_zip()

    def pack_zip(self):
        if self.has_decoded_resources():
            print(
                "WARNING: The resources for the apk seem to be decoded, this will cause issues as they will not be encoded atm."
            )
        tbcml.Zip.compress_directory(
            self.extracted_path, self.final_pkg_path, extensions_to_store=["so"]
        )
        return True

    def pack_apktool(self):
        if not self.check_display_apktool_error():
            return False
        res = self.run_apktool(f"b '{self.extracted_path}' -o '{self.final_pkg_path}'")
        if res.exit_code != 0:
            print(f"Failed to pack APK: {res.result}")
            return False
        return True

    def sign(
        self,
        use_jarsigner: bool = False,
        zip_align: bool = True,
        password: str = "TBCML_CUSTOM_APK",
    ):
        if zip_align:
            self.zip_align()
        if use_jarsigner:
            if not self.check_display_jarsigner_error():
                return False
        else:
            if not self.check_display_apk_signer_error():
                return False
        if not self.check_display_keytool_error():
            return False
        key_store_name = "tbcml.keystore"
        key_store_path = tbcml.Path.get_documents_folder().add(key_store_name)
        if not key_store_path.exists():
            cmd = tbcml.Command(
                f'keytool -genkey -v -keystore {key_store_path} -alias tbcml -keyalg RSA -keysize 2048 -validity 10000 -storepass {password} -keypass {password} -dname "CN=, OU=, O=, L=, S=, C="',
            )
            res = cmd.run()
            if res.exit_code != 0:
                print(f"Failed to generate keystore: {res.result}")
                return False

        if use_jarsigner:
            cmd = tbcml.Command(
                f"jarsigner -verbose -sigalg SHA256withRSA -digestalg SHA-256 -keystore {key_store_path} {self.final_pkg_path} tbcml",
            )
            res = cmd.run(password)
        else:
            cmd = tbcml.Command(
                f"apksigner sign --ks {key_store_path} --ks-key-alias tbcml --ks-pass pass:{password} --key-pass pass:{password} {self.final_pkg_path}"
            )
            res = cmd.run()
        if res.exit_code != 0:
            print(f"Failed to sign APK: {res.result}")
            return False
        return True

    def get_lib_paths(self) -> dict[str, "tbcml.Path"]:
        paths: dict[str, "tbcml.Path"] = {}
        for dir in self.extracted_path.add("lib").get_dirs():
            arc = dir.basename()
            path = self.get_native_lib_path(arc)
            paths[arc] = path
        return paths

    def zip_align(self):
        if not self.check_display_zipalign_error():
            return
        apk_path = self.final_pkg_path.change_name(
            self.final_pkg_path.get_file_name_without_extension() + "-aligned.apk"
        )
        cmd = tbcml.Command(f"zipalign -f -p 4 {self.final_pkg_path} {apk_path}")
        cmd.run()
        apk_path.copy(self.final_pkg_path)
        cmd.run()
        apk_path.copy(self.final_pkg_path)
        apk_path.remove()

    def load_packs_into_game(
        self,
        packs: "tbcml.GamePacks",
        copy_path: Optional["tbcml.Path"] = None,
        save_in_modded_pkgs: bool = False,
        progress_callback: Optional[
            Callable[["tbcml.PKGProgressSignal"], Optional[bool]]
        ] = None,
        use_apktool: Optional[bool] = None,
    ) -> bool:
        if progress_callback is None:
            progress_callback = lambda _: None

        if progress_callback(tbcml.PKGProgressSignal.ADD_PACKS_LISTS) is False:
            return False
        self.add_packs_lists(packs)

        if progress_callback(tbcml.PKGProgressSignal.PATCH_LIBS) is False:
            return False
        tbcml.LibFiles(self).patch()

        if progress_callback(tbcml.PKGProgressSignal.COPY_MODDED_PACKS) is False:
            return False
        self.copy_modded_packs()

        if progress_callback(tbcml.PKGProgressSignal.PACK) is False:
            return False
        if not self.pack(use_apktool=use_apktool):
            return False

        if progress_callback(tbcml.PKGProgressSignal.SIGN) is False:
            return False
        if not self.sign():
            return False

        if progress_callback(tbcml.PKGProgressSignal.FINISH_UP) is False:
            return False

        if copy_path is not None:
            self.copy_final_pkg(copy_path)
        if save_in_modded_pkgs:
            self.save_in_modded_pkgs()

        if progress_callback(tbcml.PKGProgressSignal.DONE) is False:
            return False
        return True

    @staticmethod
    def get_default_pkg_folder() -> "tbcml.Path":
        return tbcml.Path.get_documents_folder().add("APKs").generate_dirs()

    @staticmethod
    def get_all_downloaded(
        all_pkg_dir: Optional["tbcml.Path"] = None, cleanup: bool = False
    ) -> list["Apk"]:
        """
        Get all downloaded APKs

        Returns:
            list[APK]: List of APKs
        """
        return tbcml.Pkg.get_all_downloaded_pkgs(all_pkg_dir, cleanup, Apk)

    @staticmethod
    def get_all_pkgs_cc(
        cc: "tbcml.CountryCode", pkg_folder: Optional["tbcml.Path"] = None
    ) -> list["Apk"]:
        """
        Get all APKs for a country code

        Args:
            cc (country_code.CountryCode): Country code
            pkg_folder (Optional[tbcml.Path], optional): APK folder, defaults to default APK folder

        Returns:
            list[APK]: List of APKs
        """
        return tbcml.Pkg.get_all_pkgs_cc_pkgs(cc, pkg_folder, Apk)

    @staticmethod
    def get_all_versions_v2(
        cc: "tbcml.CountryCode",
        apk_list_url: str = "https://raw.githubusercontent.com/fieryhenry/BCData/master/apk_list.json",
    ) -> list["tbcml.GameVersion"]:
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
    def get_all_versions(cc: "tbcml.CountryCode"):
        versions: set[int] = set()
        versions.update([gv.game_version for gv in Apk.get_all_versions_v1(cc)])
        if cc == tbcml.CountryCode.EN or cc == tbcml.CountryCode.JP:
            versions.update([gv.game_version for gv in Apk.get_all_versions_en(cc)])
        versions.update([gv.game_version for gv in Apk.get_all_versions_v2(cc)])

        versions_ls: list[int] = list(versions)
        versions_ls.sort()

        versions_obj: list[tbcml.GameVersion] = []

        for v in versions_ls:
            versions_obj.append(tbcml.GameVersion(v))

        return versions_obj

    @staticmethod
    def get_all_versions_v1(
        cc: "tbcml.CountryCode",
    ) -> list["tbcml.GameVersion"]:
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
    def get_latest_version_v1(cc: "tbcml.CountryCode"):
        versions = Apk.get_all_versions_v1(cc)
        if cc == tbcml.CountryCode.EN or cc == tbcml.CountryCode.JP:
            new_versions = Apk.get_all_versions_en(cc)
            for version in new_versions:
                if version not in versions:
                    versions.append(version)
        if not versions:
            return None
        versions.sort(key=lambda version: version.game_version, reverse=True)

        return versions[0]

    @staticmethod
    def get_latest_version_v2(cc: "tbcml.CountryCode"):
        versions = Apk.get_all_versions_v2(cc)
        if len(versions) == 0:
            return None
        versions.sort(key=lambda version: version.game_version, reverse=True)
        return versions[0]

    @staticmethod
    def get_latest_version(cc: "tbcml.CountryCode", v2: bool = True, v1: bool = True):
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
        scraper: "cloudscraper.CloudScraper",
        url: str,
    ) -> Optional[requests.Response]:
        try:
            stream = scraper.get(url, stream=True, timeout=10)
        except requests.RequestException:
            return None
        if stream.headers.get("content-length") is None:
            return None
        return stream

    def download_v2(
        self,
        progress: Optional[
            Callable[[float, int, int, bool], Optional[bool]]
        ] = Pkg.progress,
        force: bool = False,
        apk_list_url: str = "https://raw.githubusercontent.com/fieryhenry/BCData/master/apk_list.json",
    ) -> bool:
        if self.pkg_path.exists() and not force:
            return True

        response = tbcml.RequestHandler(apk_list_url).get()
        json = response.json()
        cc_versions = json.get(self.country_code.get_code())
        if cc_versions is None:
            return False
        url = cc_versions.get(self.game_version.to_string())
        if url is None:
            return False

        stream = tbcml.RequestHandler(url).get_stream()
        if stream.status_code == 404:
            return False
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
                    return False

        apk = tbcml.Data(b"".join(buffer))
        apk.to_file(self.pkg_path)
        return True

    def download(
        self,
        progress: Optional[
            Callable[[float, int, int, bool], Optional[bool]]
        ] = Pkg.progress,
        force: bool = False,
        skip_signature_check: bool = False,
    ) -> bool:
        if self.pkg_path.exists() and not force:
            return True

        if not self.check_apksigner_installed():
            skip_signature_check = True

        sig_failed = False
        if self.download_v1(progress, force):
            if skip_signature_check:
                return True
            if self.is_original(self.pkg_path):
                return True
            sig_failed = True

        if self.download_v2(progress, force):
            if skip_signature_check:
                return True
            if self.is_original(self.pkg_path):
                return True
            sig_failed = True

        if sig_failed and not skip_signature_check:
            raise ValueError(
                "APK signature check failed. The downloaded APK is not original. If you are sure that the APK is original, set skip_signature_check to True."
            )

        return False

    def download_v1(
        self,
        progress: Optional[
            Callable[[float, int, int, bool], Optional[bool]]
        ] = Pkg.progress,
        force: bool = False,
    ) -> bool:
        if self.pkg_path.exists() and not force:
            return True
        if self.download_v1_all(progress):
            return True
        if (
            self.country_code == tbcml.CountryCode.EN
            or self.country_code == tbcml.CountryCode.JP
        ):
            return self.download_apk_en(
                self.country_code == tbcml.CountryCode.EN,
                progress,
            )
        return False

    def download_v1_all(
        self,
        progress: Optional[
            Callable[[float, int, int, bool], Optional[bool]]
        ] = Pkg.progress,
    ) -> bool:
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
            return False

        content_length = stream.headers.get("content-length")
        if content_length is None:
            return False

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
                    return False

        apk = tbcml.Data(b"".join(buffer))
        apk.to_file(self.pkg_path)
        return True

    def download_apk_en(
        self,
        is_en: bool = True,
        progress: Optional[
            Callable[[float, int, int, bool], Optional[bool]]
        ] = Pkg.progress,
    ) -> bool:
        urls = Apk.get_en_apk_urls("the-battle-cats" if is_en else "the-battle-cats-jp")
        if not urls:
            print("Failed to get APK URLs")
            return False
        url: str = urls[self.game_version.to_string()]
        if not url:
            print(f"Failed to get APK URL: {self.game_version.to_string()}")
            return False
        url = url.replace("/android/download/", "/android/post-download/")

        response = tbcml.RequestHandler(url, Apk.get_uptdown_headers()).get()
        soup = bs4.BeautifulSoup(response.text, "html.parser")
        post_download_class = soup.find("div", {"class": "post-download"})
        if not isinstance(post_download_class, bs4.element.Tag):
            return False
        data_url = post_download_class.get_attribute_list("data-url")[0]
        url = "https://dw.uptodown.com/dwn/" + data_url
        headers = {
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
            "accept-encoding": "gzip, deflate, br",
            "accept-language": "en-GB,en;q=0.9",
            "connection": "keep-alive",
            "sec-ch-ua": '"Google Chrome"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": "Widnows",
            "sec-fetch-dest": "document",
            "sec-fetch-mode": "navigate",
            "sec-fetch-site": "none",
            "sec-fetch-user": "?1",
            "upgrade-insecure-requests": "1",
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36",
        }
        stream = tbcml.RequestHandler(url, headers).get_stream()
        content_length = stream.headers.get("content-length")
        if content_length is None:
            return False
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
                    return False

        apk = tbcml.Data(b"".join(buffer))
        apk.to_file(self.pkg_path)
        return True

    def get_en_apk_url(self, apk_url: str):
        resp = tbcml.RequestHandler(apk_url).get()
        soup = bs4.BeautifulSoup(resp.text, "html.parser")
        download_button = soup.find("button", {"class": "button download"})
        if not isinstance(download_button, bs4.element.Tag):
            return None
        return str(download_button.get_attribute_list("data-url")[0])

    @staticmethod
    def get_uptdown_headers() -> dict[str, Any]:
        return {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }

    @staticmethod
    def get_en_app_id(package_name: str) -> Optional[str]:
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
    def get_en_apk_json(package_name: str) -> list[dict[str, Any]]:
        app_id = Apk.get_en_app_id(package_name)
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
    def get_en_apk_urls(package_name: str) -> Optional[dict[str, Any]]:
        json_data = Apk.get_en_apk_json(package_name)
        versions: list[str] = []
        urls: list[str] = []
        for data in json_data:
            versions.append(data["version"])
            urls.append(data["versionURL"])
        return dict(zip(versions, urls))

    def get_download_url(self) -> str:
        return f"https://d.apkpure.net/b/APK/jp.co.ponos.battlecats{self.country_code.get_patching_code()}?versionCode={self.game_version.game_version}0"

    @staticmethod
    def get_all_versions_en(
        cc: "tbcml.CountryCode",
    ) -> list["tbcml.GameVersion"]:
        apk_urls = Apk.get_en_apk_urls(
            "the-battle-cats-jp" if cc == tbcml.CountryCode.JP else "the-battle-cats"
        )
        if apk_urls is None:
            return []
        versions: list[tbcml.GameVersion] = []
        for version in apk_urls.keys():
            versions.append(tbcml.GameVersion.from_string(version))
        return versions

    @staticmethod
    def get_apk_version_url(cc: "tbcml.CountryCode") -> str:
        if cc == tbcml.CountryCode.JP:
            url = "https://apkpure.net/%E3%81%AB%E3%82%83%E3%82%93%E3%81%93%E5%A4%A7%E6%88%A6%E4%BA%89/jp.co.ponos.battlecats/versions"
        elif cc == tbcml.CountryCode.KR:
            url = "https://apkpure.net/%EB%83%A5%EC%BD%94-%EB%8C%80%EC%A0%84%EC%9F%81/jp.co.ponos.battlecatskr/versions"
        elif cc == tbcml.CountryCode.TW:
            url = "https://apkpure.net/%E8%B2%93%E5%92%AA%E5%A4%A7%E6%88%B0%E7%88%AD/jp.co.ponos.battlecatstw/versions"
        elif cc == tbcml.CountryCode.EN:
            url = (
                "https://apkpure.net/the-battle-cats/jp.co.ponos.battlecatsen/versions"
            )
        else:
            raise ValueError(f"Country code {cc} not supported")
        return url

    @staticmethod
    def clean_up(apk_folder: Optional["tbcml.Path"] = None):
        Apk.get_all_downloaded_pkgs(apk_folder, cleanup=True, clzz=Apk)

    @staticmethod
    def get_package_name_version_from_apk(apk_path: "tbcml.Path"):
        cmd = f'aapt dump badging "{apk_path}"'
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
    def get_sha256_cert_hash(path: "tbcml.PathStr") -> Optional[str]:
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

    def get_sha256_cert_hash_cls(self) -> Optional[str]:
        return Apk.get_sha256_cert_hash(self.pkg_path)

    @staticmethod
    def is_original(
        apk_path: Optional["tbcml.PathStr"] = None, hash: Optional[str] = None
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
        pkg_path: "tbcml.Path",
        cc_overwrite: Optional["tbcml.CountryCode"] = None,
        gv_overwrite: Optional["tbcml.GameVersion"] = None,
        pkg_folder: Optional["tbcml.Path"] = None,
        allowed_script_mods: bool = True,
        skip_signature_check: bool = False,
        overwrite_pkg: bool = True,
    ) -> "Apk":
        is_modded = False

        if not pkg_path.exists():
            raise ValueError(f"APK path {pkg_path} does not exist.")

        if not Apk.check_apksigner_installed():
            skip_signature_check = True
            is_modded = False

        cc, gv = Apk.get_package_name_version_from_apk(pkg_path)

        if cc is None:
            cc = cc_overwrite
        if gv is None:
            gv = gv_overwrite

        if gv is None or cc is None:
            raise ValueError("Failed to get cc or gv from apk.")

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
        return apk

    def get_architectures(self) -> list[str]:
        architectures: list[str] = []
        for folder in self.extracted_path.add("lib").get_dirs():
            arc = folder.basename()
            architectures.append(arc)
        return architectures

    def get_native_lib_path(self, architecture: str) -> "tbcml.Path":
        if not self.is_java():
            return self.get_lib_path(architecture).add("libnative-lib.so")
        return self.get_lib_path(architecture).add("libbattlecats-jni.so")

    def is_java(self):
        return self.get_lib_path("x86").add("libbattlecats-jni.so").exists()

    def get_smali_handler(self) -> "tbcml.SmaliHandler":
        if self.smali_handler is None:
            self.smali_handler = tbcml.SmaliHandler(self)
        return self.smali_handler

    def inject_smali(self, library_name: str):
        self.get_smali_handler().inject_load_library(library_name)

    def get_lib_path(self, architecture: str) -> "tbcml.Path":
        return self.extracted_path.add("lib").add(architecture)

    def add_to_lib_folder(self, architecture: str, library_path: "tbcml.Path"):
        lib_folder_path = self.get_lib_path(architecture)
        library_path.copy(lib_folder_path)
        new_name = library_path.basename()
        if not library_path.basename().startswith("lib"):
            new_name = f"lib{library_path.basename()}"
        if library_path.get_extension() != "so":
            new_name = f"{new_name}.so"
        curr_path = lib_folder_path.add(library_path.basename())
        curr_path.rename(new_name, overwrite=True)

    def get_libgadget_script_path(self):
        return tbcml.Path("libbc_script.js.so")

    def get_libgadget_config_path(self):
        return tbcml.Path("libfrida-gadget.config.so")

    def get_manifest_path(self) -> "tbcml.Path":
        return self.extracted_path.add("AndroidManifest.xml")

    def parse_manifest(self) -> Optional["tbcml.XML"]:
        return self.parse_xml(self.get_manifest_path())

    def parse_xml(self, path: "tbcml.Path") -> Optional["tbcml.XML"]:
        try:
            return tbcml.XML(path.read())
        except Exception:
            return None

    def set_manifest(self, manifest: "tbcml.XML"):
        manifest.to_file(self.get_manifest_path())

    def get_pack_location(self) -> "tbcml.Path":
        if self.is_java():
            return self.extracted_path.add("res").add("raw")
        return self.extracted_path.add("assets")

    def get_original_pack_location(self) -> "tbcml.Path":
        if self.is_java():
            return self.original_extracted_path.add("res").add("raw")
        return self.original_extracted_path.add("assets")

    def get_audio_extensions(self) -> list[str]:
        return ["caf", "ogg"]

    def audio_file_startswith_snd(self) -> bool:
        return True

    def get_asset(self, asset_name: "tbcml.PathStr") -> "tbcml.Path":
        return self.extracted_path.add("assets").add(asset_name)

    def apply_mod_smali(self, mod: "tbcml.Mod"):
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
        return self.extracted_path.add("res").add("values").add(f"{name}.xml")

    def load_xml(self, name: str) -> Optional["tbcml.XML"]:
        strings_xml = self.get_values_xml_path(name)
        if not strings_xml.exists():
            return None
        return tbcml.XML(strings_xml.read())

    def save_xml(self, name: str, xml: "tbcml.XML"):
        xml.to_file(self.get_values_xml_path(name))

    def set_string(
        self, name: str, value: str, include_lang: bool, lang: Optional[str] = None
    ):
        if self.country_code == tbcml.CountryCode.EN and include_lang:
            if lang is None:
                lang = "en"
            name = f"{name}_{lang}"

        return self.edit_xml_string(name, value)

    def get_string(self, name: str, include_lang: bool, lang: Optional[str] = None):
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

    def get_xml_string(self, name: str) -> Optional[str]:
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

    def read_pkg_name(self) -> Optional[str]:
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

    @staticmethod
    def try_get_pkg_from_path(
        path: "tbcml.Path",
        all_pkg_dir: Optional["tbcml.Path"] = None,
    ) -> Optional["Apk"]:
        return Apk.try_get_pkg_from_path_pkg(path, all_pkg_dir=all_pkg_dir, clzz=Apk)

    def add_smali_mods(self, mods: list["tbcml.Mod"]):
        if not self.is_allowed_script_mods():
            return
        for mod in mods:
            self.apply_mod_smali(mod)

    def prevent_so_compression(self):
        if not self.did_use_apktool():
            return

        apktoolyml = self.extracted_path.add("apktool.yml")
        yamlo = tbcml.Yaml.from_file(apktoolyml)
        yaml = yamlo.yaml
        do_not_compress = yaml.get("doNotCompress", [])
        if "so" not in do_not_compress:
            do_not_compress.append("so")
        yaml["doNotCompress"] = do_not_compress

        yamlo.to_file(apktoolyml)

    def load_mods(
        self,
        mods: list["tbcml.Mod"],
        game_packs: Optional["tbcml.GamePacks"] = None,
        lang: Optional["tbcml.Language"] = None,
        key: Optional[str] = None,
        iv: Optional[str] = None,
        add_modded_html: bool = True,
        save_in_modded_pkgs: bool = False,
        progress_callback: Optional[
            Callable[["tbcml.PKGProgressSignal"], Optional[bool]]
        ] = None,
        do_final_pkg_actions: bool = True,
        use_apktool: Optional[bool] = None,
    ) -> bool:
        if progress_callback is None:
            progress_callback = lambda x: None

        if progress_callback(tbcml.PKGProgressSignal.START) is False:
            return False

        if progress_callback(tbcml.PKGProgressSignal.LOAD_GAME_PACKS) is False:
            return False

        if game_packs is None:
            game_packs = tbcml.GamePacks.from_pkg(self, lang=lang)

        if key is not None:
            self.set_key(key)
        if iv is not None:
            self.set_iv(iv)

        if progress_callback(tbcml.PKGProgressSignal.ADD_SMALI_MODS) is False:
            return False
        self.add_smali_mods(mods)

        if progress_callback(tbcml.PKGProgressSignal.ADD_SCRIPT_MODS) is False:
            return False
        self.add_script_mods(mods)

        if progress_callback(tbcml.PKGProgressSignal.ADD_PATCH_MODS) is False:
            return False
        self.add_patch_mods(mods)

        self.prevent_so_compression()

        if progress_callback(tbcml.PKGProgressSignal.APPLY_MODS) is False:
            return False
        game_packs.apply_mods(mods)

        if do_final_pkg_actions:
            if progress_callback(tbcml.PKGProgressSignal.SET_MANIFEST_VALUES) is False:
                return False
            self.set_allow_backup(True)
            self.set_debuggable(True)

            if add_modded_html:
                if progress_callback(tbcml.PKGProgressSignal.ADD_MODDED_HTML) is False:
                    return False
                self.add_modded_html(mods)

        if progress_callback(tbcml.PKGProgressSignal.ADD_MODDED_FILES) is False:
            return False
        lang_str = None if lang is None else lang.value
        self.add_mods_files(mods, lang_str)

        if do_final_pkg_actions:
            if progress_callback(tbcml.PKGProgressSignal.LOAD_PACKS_INTO_GAME) is False:
                return False
            if not self.load_packs_into_game(
                game_packs,
                use_apktool=use_apktool,
                save_in_modded_pkgs=save_in_modded_pkgs,
                progress_callback=progress_callback,
            ):
                return False
        else:
            if progress_callback(tbcml.PKGProgressSignal.DONE) is False:
                return False

        return True
