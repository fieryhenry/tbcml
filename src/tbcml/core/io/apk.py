from typing import Any, Callable, Optional

import bs4
import cloudscraper  # type: ignore
import requests

from tbcml import core


class Apk:
    def __init__(
        self,
        game_version: "core.GameVersion",
        country_code: "core.CountryCode",
        apk_folder: Optional["core.Path"] = None,
    ):
        self.game_version = game_version
        self.country_code = country_code
        self.package_name = self.get_package_name()

        if apk_folder is None:
            apk_folder = self.get_default_apk_folder()
        self.apk_folder = apk_folder
        self.locale_manager = core.LocalManager.from_config()

        self.smali_handler: Optional[core.SmaliHandler] = None

        self.init_paths()

        self.key = None
        self.iv = None

        self.libs: Optional[dict[str, core.Lib]] = None

    def replace_lib_string(self, original: str, new: str, pad: str = "\x00") -> str:
        return core.LibFiles(self).replace_str(original, new, pad)

    @staticmethod
    def from_format_string(
        format_string: str,
        apk_folder: Optional["core.Path"] = None,
    ) -> "Apk":
        cc, gv, _ = format_string.split(" ")
        gv = core.GameVersion.from_string(gv)
        cc = core.CountryCode.from_code(cc)
        return Apk(
            game_version=gv,
            country_code=cc,
            apk_folder=apk_folder,
        )

    def get_id(self) -> str:
        return f"{self.country_code.get_code()} {self.game_version.to_string()}"

    def init_paths(self):
        self.apk_folder.generate_dirs()
        self.output_path = self.apk_folder.add(
            f"{self.game_version}{self.country_code.get_code()}"
        )

        self.final_apk_path = self.output_path.add(f"{self.package_name}-modded.apk")
        self.apk_path = self.output_path.add(f"{self.package_name}-original.apk")

        self.extracted_path = (
            self.output_path.add("extracted").remove_tree().generate_dirs()
        )
        self.decrypted_path = self.output_path.add("decrypted").generate_dirs()
        self.packs_path = self.output_path.add("packs").generate_dirs()
        self.modified_packs_path = (
            self.output_path.add("modified_packs").remove_tree().generate_dirs()
        )
        self.original_extracted_path = self.output_path.add(
            "original_extracted"
        ).generate_dirs()

        self.temp_path = self.output_path.add("temp").remove_tree().generate_dirs()

        self.smali_original_path = self.output_path.add(
            "smali-original"
        ).generate_dirs()

        self.smali_non_original_path = (
            self.output_path.add("smali-new").remove_tree().generate_dirs()
        )

    def get_packs_lists(self) -> list[tuple["core.Path", "core.Path"]]:
        files: list[tuple[core.Path, core.Path]] = []
        for file in self.packs_path.get_files():
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

    def get_packs(self) -> list["core.Path"]:
        packs_list = self.get_packs_lists()
        return [pack[0] for pack in packs_list]

    def copy_packs(self):
        self.packs_path.remove_tree().generate_dirs()
        packs = self.get_pack_location().get_files()
        for pack in packs:
            if pack.get_extension() == "pack" or pack.get_extension() == "list":
                pack.copy(self.packs_path)

    def copy_extracted(self):
        self.extracted_path.remove_tree().generate_dirs()
        self.original_extracted_path.copy(self.extracted_path)

    @staticmethod
    def run_apktool(command: str) -> "core.CommandResult":
        apktool_path = core.Path.get_lib("apktool.jar")
        return core.Command(f"java -jar {apktool_path} {command}").run()

    @staticmethod
    def check_apktool_installed() -> bool:
        res = Apk.run_apktool("-version")
        return res.exit_code == 0

    @staticmethod
    def check_jarsigner_installed() -> bool:
        cmd = core.Command("jarsigner", False)
        res = cmd.run()
        return res.exit_code == 0

    @staticmethod
    def check_keytool_installed() -> bool:
        cmd = core.Command("keytool", False)
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

    def check_display_keytool_error(self) -> bool:
        if self.check_keytool_installed():
            return True
        message = "Keytool or java is not installed. Please install it and add it to your PATH."
        print(message)
        return False

    def extract(self):
        if self.original_extracted_path.has_files():
            self.copy_extracted()
            self.copy_packs()
            return

        if not self.check_display_apktool_error():
            return
        res = self.run_apktool(
            f"d -f -s {self.apk_path} -o {self.original_extracted_path}"
        )
        if res.exit_code != 0:
            print(f"Failed to extract APK: {res.result}")
            return
        self.copy_extracted()
        self.copy_packs()

    def extract_smali(self):
        if not self.check_display_apktool_error():
            return

        with core.TempFolder() as temp_folder:
            res = self.run_apktool(f"d -f {self.apk_path} -o {temp_folder}")
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

    def pack(self):
        if not self.check_display_apktool_error():
            return
        res = self.run_apktool(f"b {self.extracted_path} -o {self.final_apk_path}")
        if res.exit_code != 0:
            print(f"Failed to pack APK: {res.result}")
            return

    def sign(self):
        if not self.check_display_jarsigner_error():
            return
        if not self.check_display_keytool_error():
            return
        password = core.config.get(core.ConfigKey.KEYSTORE_PASSWORD)
        key_store_name = "tbcml.keystore"
        key_store_path = core.Path.get_appdata_folder().add(key_store_name)
        if not key_store_path.exists():
            cmd = core.Command(
                f'keytool -genkey -v -keystore {key_store_path} -alias tbcml -keyalg RSA -keysize 2048 -validity 10000 -storepass {password} -keypass {password} -dname "CN=, OU=, O=, L=, S=, C="',
                False,
            )
            res = cmd.run()
            if res.exit_code != 0:
                print(f"Failed to generate keystore: {res.result}")
                return

        cmd = core.Command(
            f"jarsigner -verbose -sigalg SHA256withRSA -digestalg SHA-256 -keystore {key_store_path} {self.final_apk_path} tbcml",
            True,
        )
        res = cmd.run(password)
        if res.exit_code != 0:
            print(f"Failed to sign APK: {res.result}")
            return

    def set_key(self, key: str):
        self.key = key

    def set_iv(self, iv: str):
        self.iv = iv

    def randomize_key(self):
        key = core.Random().get_hex_string(32)
        self.set_key(key)
        return key

    def randomize_iv(self):
        iv = core.Random().get_hex_string(32)
        self.set_iv(iv)
        return iv

    def add_packs_lists(
        self,
        packs: "core.GamePacks",
    ):
        files = packs.to_packs_lists(self.randomize_key(), self.randomize_iv())
        for pack_name, pack_data, list_data in files:
            if len(pack_name.split("_")) > 1:
                continue
            self.add_pack_list(pack_name, pack_data, list_data)

    def add_pack_list(
        self, pack_name: str, pack_data: "core.Data", list_data: "core.Data"
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

    def load_packs_into_game(
        self,
        packs: "core.GamePacks",
    ):
        self.add_packs_lists(packs)
        core.LibFiles(self).patch()
        self.copy_modded_packs()
        self.pack()
        self.sign()
        self.copy_final_apk()

    def copy_final_apk(self):
        final_path = self.get_final_apk_path()
        if final_path == self.final_apk_path:
            return
        self.final_apk_path.copy(final_path)

    def get_final_apk_path(self) -> "core.Path":
        final_path = core.config.get(core.ConfigKey.APK_COPY_PATH)
        if not final_path:
            return self.final_apk_path
        final_path = core.Path(final_path)
        if final_path.get_extension() == "apk":
            final_path.parent().generate_dirs()
        else:
            final_path.add(self.final_apk_path.basename())
        return final_path

    @staticmethod
    def get_default_apk_folder() -> "core.Path":
        folder = core.Path(core.config.get(core.ConfigKey.APK_FOLDER)).generate_dirs()
        return folder

    def get_package_name(self) -> str:
        return f"jp.co.ponos.battlecats{self.country_code.get_patching_code()}"

    @staticmethod
    def get_all_downloaded() -> list["Apk"]:
        """
        Get all downloaded APKs

        Returns:
            list[APK]: List of APKs
        """
        all_apk_dir = core.Path(core.config.get(core.ConfigKey.APK_FOLDER))
        apks: list[Apk] = []
        for apk_folder in all_apk_dir.get_dirs():
            name = apk_folder.get_file_name()
            country_code_str = name[-2:]
            if country_code_str not in core.CountryCode.get_all_str():
                continue
            cc = core.CountryCode.from_code(country_code_str)
            game_version_str = name[:-2]
            gv = core.GameVersion.from_string_latest(game_version_str, cc)
            apk = Apk(gv, cc)
            if apk.is_downloaded():
                apks.append(apk)

        apks.sort(key=lambda apk: apk.game_version.game_version, reverse=True)

        return apks

    @staticmethod
    def get_all_apks_cc(cc: "core.CountryCode") -> list["Apk"]:
        """
        Get all APKs for a country code

        Args:
            cc (country_code.CountryCode): Country code

        Returns:
            list[APK]: List of APKs
        """
        apks = Apk.get_all_downloaded()
        apks_cc: list[Apk] = []
        for apk in apks:
            if apk.country_code == cc:
                apks_cc.append(apk)
        return apks_cc

    @staticmethod
    def get_latest_downloaded_version_cc(
        cc: "core.CountryCode",
    ) -> "core.GameVersion":
        """
        Get latest downloaded APK version for a country code

        Args:
            cc (country_code.CountryCode): Country code

        Returns:
            game_version.GameVersion: Latest APK version
        """
        max_version = core.GameVersion(0)
        for apk in Apk.get_all_apks_cc(cc):
            if apk.game_version > max_version:
                max_version = apk.game_version
        return max_version

    @staticmethod
    def get_all_versions(
        cc: "core.CountryCode",
    ) -> list["core.GameVersion"]:
        """
        Get all APK versions

        Args:
            cc (country_code.CountryCode): Country code

        Returns:
            game_version.GameVersion: List of APK versions
        """
        if cc == core.CountryCode.EN or cc == core.CountryCode.JP:
            return Apk.get_all_versions_en(cc)
        url = Apk.get_apk_version_url(cc)
        scraper = cloudscraper.create_scraper()  # type: ignore
        resp = scraper.get(url)
        soup = bs4.BeautifulSoup(resp.text, "html.parser")
        versionwrapp = soup.find("ul", {"class": "ver-wrap"})
        if not isinstance(versionwrapp, bs4.element.Tag):
            return []
        versions: list[core.GameVersion] = []
        for version in versionwrapp.find_all("li"):
            if not isinstance(version, bs4.element.Tag):
                continue
            version_anchor = version.find("a")
            if not isinstance(version_anchor, bs4.element.Tag):
                continue
            version = version_anchor.get_attribute_list("data-dt-versioncode")[0]
            versions.append(core.GameVersion(int(version[:-1])))
        return versions

    @staticmethod
    def get_latest_version(cc: "core.CountryCode"):
        versions = Apk.get_all_versions(cc)
        if len(versions) == 0:
            return None
        return versions[0]

    def format(self):
        return f"{self.country_code.name} {self.game_version.format()} APK"

    @staticmethod
    def progress(
        progress: float,
        current: int,
        total: int,
        is_file_size: bool = False,
    ):
        total_bar_length = 70
        if is_file_size:
            current_str = core.FileSize(current).format()
            total_str = core.FileSize(total).format()
        else:
            current_str = str(current)
            total_str = str(total)
        bar_length = int(total_bar_length * progress)
        bar = "#" * bar_length + "-" * (total_bar_length - bar_length)
        print(
            f"\r[{bar}] {int(progress * 100)}% ({current_str}/{total_str})    ",
            end="",
        )

    def download(
        self, progress: Optional[Callable[[float, int, int, bool], None]] = progress
    ) -> bool:
        if self.apk_path.exists():
            return True
        if (
            self.country_code == core.CountryCode.EN
            or self.country_code == core.CountryCode.JP
        ):
            return self.download_apk_en(
                self.country_code == core.CountryCode.EN,
                progress,
            )
        else:
            url = self.get_download_url()
            scraper = cloudscraper.create_scraper()  # type: ignore
            scraper.headers.update(
                {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36"
                }
            )
            stream = scraper.get(url, stream=True, timeout=10)
            try:
                _total_length = int(stream.headers.get("content-length"))  # type: ignore
            except TypeError:
                url = url[:-1] + "1"
                stream = scraper.get(url, stream=True, timeout=10)
                _total_length = int(stream.headers.get("content-length"))  # type: ignore

            dl = 0
            chunk_size = 1024
            buffer: list[bytes] = []
            for d in stream.iter_content(chunk_size=chunk_size):
                dl += len(d)
                buffer.append(d)
                if progress is not None:
                    progress(dl / _total_length, dl, _total_length, True)

            apk = core.Data(b"".join(buffer))
            apk.to_file(self.apk_path)
            return True

    def download_apk_en(
        self,
        is_en: bool = True,
        progress: Optional[Callable[[float, int, int, bool], None]] = progress,
    ) -> bool:
        urls = Apk.get_en_apk_urls("the-battle-cats" if is_en else "the-battle-cats-jp")
        if not urls:
            print("Failed to get APK URLs")
            return False
        url = self.get_en_apk_url(urls[self.game_version.to_string()])
        if not url:
            print(f"Failed to get APK URL: {self.game_version.to_string()}")
            return False
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
        stream = core.RequestHandler(url, headers).get_stream()
        try:
            _total_length = int(stream.headers.get("content-length"))  # type: ignore
        except TypeError:
            _total_length = 0

        dl = 0
        chunk_size = 1024
        buffer: list[bytes] = []
        for d in stream.iter_content(chunk_size=chunk_size):
            dl += len(d)
            buffer.append(d)
            if progress is not None:
                progress(dl / _total_length, dl, _total_length, True)

        apk = core.Data(b"".join(buffer))
        apk.to_file(self.apk_path)
        return True

    def get_en_apk_url(self, apk_url: str):
        resp = core.RequestHandler(apk_url).get()
        soup = bs4.BeautifulSoup(resp.text, "html.parser")
        download_button = soup.find("button", {"class": "button download"})
        if not isinstance(download_button, bs4.element.Tag):
            return None
        return str(download_button.get_attribute_list("data-url")[0])

    @staticmethod
    def get_en_app_id(package_name: str) -> Optional[str]:
        url = f"https://{package_name}.en.uptodown.com/android/versions"
        try:
            resp = core.RequestHandler(url).get()
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
            resp = core.RequestHandler(url).get()
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
        return f"https://d.apkpure.com/b/APK/jp.co.ponos.battlecats{self.country_code.get_patching_code()}?versionCode={self.game_version.game_version}0"

    @staticmethod
    def get_all_versions_en(
        cc: "core.CountryCode",
    ) -> list["core.GameVersion"]:
        apk_urls = Apk.get_en_apk_urls(
            "the-battle-cats-jp" if cc == core.CountryCode.JP else "the-battle-cats"
        )
        if apk_urls is None:
            return []
        versions: list[core.GameVersion] = []
        for version in apk_urls.keys():
            versions.append(core.GameVersion.from_string(version))
        return versions

    @staticmethod
    def get_apk_version_url(cc: "core.CountryCode") -> str:
        if cc == core.CountryCode.JP:
            url = "https://m.apkpure.com/%E3%81%AB%E3%82%83%E3%82%93%E3%81%93%E5%A4%A7%E6%88%A6%E4%BA%89/jp.co.ponos.battlecats/versions"
        elif cc == core.CountryCode.KR:
            url = "https://m.apkpure.com/%EB%83%A5%EC%BD%94-%EB%8C%80%EC%A0%84%EC%9F%81/jp.co.ponos.battlecatskr/versions"
        elif cc == core.CountryCode.TW:
            url = "https://m.apkpure.com/%E8%B2%93%E5%92%AA%E5%A4%A7%E6%88%B0%E7%88%AD/jp.co.ponos.battlecatstw/versions"
        else:
            raise ValueError(f"Country code {cc} not supported")
        return url

    def is_downloaded(self) -> bool:
        return self.apk_path.exists()

    def delete(self):
        self.output_path.remove_tree()

    @staticmethod
    def clean_up():
        for apk in Apk.get_all_downloaded():
            if apk.is_downloaded():
                continue
            apk.delete()

    def get_display_string(self) -> str:
        return f"{self.game_version.format()} <dark_green>({self.country_code})</>"

    def download_server_files(
        self,
        copy: bool = True,
    ):
        sfh = core.ServerFileHandler(self)
        sfh.extract_all()
        if copy:
            self.copy_server_files()

    def copy_server_files(self):
        server_path = self.get_server_path(self.country_code)
        if not server_path.exists():
            return
        for file in server_path.get_files():
            file.copy(self.packs_path.add(file.basename()))

    @staticmethod
    def get_server_path(cc: "core.CountryCode") -> "core.Path":
        apk_folder = Apk.get_default_apk_folder()
        return apk_folder.parent().add(f"{cc.get_code()}_server")

    @staticmethod
    def from_apk_path(
        apk_path: "core.Path",
        cc: Optional["core.CountryCode"] = None,
        gv: Optional["core.GameVersion"] = None,
    ) -> "Apk":
        cmd = f'aapt dump badging "{apk_path}"'
        result = core.Command(cmd).run()
        output = result.result
        version_name = ""
        package_name = ""
        for line in output.splitlines():
            if "versionName" in line:
                version_name = line.split("versionName='")[1].split("'")[0]
            if "package: name=" in line:
                package_name = line.split("name='")[1].split("'")[0]

        cc_str = package_name.replace("jp.co.ponos.battlecats", "")
        if cc is None:
            cc = core.CountryCode.from_patching_code(cc_str)
        if gv is None:
            gv = core.GameVersion.from_string(version_name)

        apk = Apk(gv, cc)
        apk_path.copy(apk.apk_path)
        apk.original_extracted_path.remove_tree().generate_dirs()
        return apk

    def get_architectures(self):
        architectures: list[str] = []
        for folder in self.extracted_path.add("lib").get_dirs():
            architectures.append(folder.basename())
        return architectures

    def __str__(self):
        return self.get_display_string()

    def __repr__(self):
        return self.get_display_string()

    def get_libnative_path(self, architecture: str) -> "core.Path":
        if not self.is_java():
            return self.get_lib_path(architecture).add("libnative-lib.so")
        return self.get_lib_path(architecture).add("libbattlecats-jni.so")

    def is_java(self):
        return self.game_version.is_java()

    def parse_libnative(self, architecture: str) -> Optional["core.Lib"]:
        path = self.get_libnative_path(architecture)
        if not path.exists():
            return None
        return core.Lib(architecture, path)

    def get_smali_handler(self) -> "core.SmaliHandler":
        if self.smali_handler is None:
            self.smali_handler = core.SmaliHandler(self)
        return self.smali_handler

    def add_library(self, architecture: str, library_path: "core.Path"):
        libnative = self.get_libs().get(architecture)
        if libnative is None:
            print(f"Could not find libnative for {architecture}")
            return
        if not self.is_java():
            libnative.add_library(library_path)
            libnative.write()
        else:
            self.get_smali_handler().inject_load_library(library_path.basename())
        self.add_to_lib_folder(architecture, library_path)

    def get_lib_path(self, architecture: str) -> "core.Path":
        return self.extracted_path.add("lib").add(architecture)

    def import_libraries(self, lib_folder: "core.Path"):
        for architecture in self.get_architectures():
            libs_path = lib_folder.add(architecture)
            if not libs_path.exists():
                continue
            for lib in libs_path.get_files():
                self.add_library(architecture, lib)

    def add_to_lib_folder(self, architecture: str, library_path: "core.Path"):
        lib_folder_path = self.get_lib_path(architecture)
        library_path.copy(lib_folder_path)
        new_name = library_path.basename()
        if not library_path.basename().startswith("lib"):
            new_name = f"lib{library_path.basename()}"
        if library_path.get_extension() != "so":
            new_name = f"{new_name}.so"
        curr_path = lib_folder_path.add(library_path.basename())
        curr_path.rename(new_name, overwrite=True)

    def create_libgadget_config(self):
        json_data = {
            "interaction": {
                "type": "script",
                "path": f"/data/data/{self.package_name}/lib/libbc_script.js.so",
                "on_change": "reload",
            }
        }
        json = core.JsonFile.from_object(json_data)
        return json

    def add_libgadget_config(self, used_arcs: list[str]):
        config = self.create_libgadget_config()
        temp_file = self.temp_path.add("libfrida-gadget.config")
        config.to_data().to_file(temp_file)

        for architecture in used_arcs:
            self.add_to_lib_folder(architecture, temp_file)

        temp_file.remove()

    def add_libgadget_scripts(self, scripts: "core.FridaScripts"):
        for architecture in scripts.get_used_arcs():
            script_str = scripts.combine_scripts(architecture)
            script_path = self.temp_path.add("libbc_script.js.so")
            script_str.to_file(script_path)
            self.add_to_lib_folder(architecture, script_path)
            script_path.remove()

    @staticmethod
    def get_libgadgets_path() -> "core.Path":
        folder = core.Path(core.config.get(core.ConfigKey.LIB_GADGETS_FOLDER))
        folder.generate_dirs()
        arcs = ["arm64-v8a", "armeabi-v7a", "x86", "x86_64"]
        for arc in arcs:
            folder.add(arc).generate_dirs()
        return folder

    @staticmethod
    def download_libgadgets():
        core.FridaGadgetHelper().download_gadgets()

    def get_libgadgets(self) -> dict[str, "core.Path"]:
        folder = Apk.get_libgadgets_path()
        Apk.download_libgadgets()
        arcs = folder.get_dirs()
        libgadgets: dict[str, "core.Path"] = {}
        for arc in arcs:
            so_regex = ".*\\.so"
            files = arc.get_files(regex=so_regex)
            if len(files) == 0:
                continue
            files[0] = files[0].rename("libfrida-gadget.so")
            libgadgets[arc.basename()] = files[0]
        return libgadgets

    def add_libgadget_sos(self, used_arcs: list[str]):
        for architecture, libgadget in self.get_libgadgets().items():
            if architecture not in used_arcs:
                continue
            self.add_library(architecture, libgadget)

    def add_frida_scripts(self, scripts: "core.FridaScripts"):
        used_arcs = scripts.get_used_arcs()
        self.add_libgadget_config(used_arcs)
        self.add_libgadget_scripts(scripts)
        self.add_libgadget_sos(used_arcs)

    def add_patches(self, patches: "core.LibPatches"):
        for patch in patches.lib_patches:
            self.add_patch(patch)

    def add_patch(self, patch: "core.LibPatch"):
        lib = self.parse_libnative(patch.architecture)
        if lib is None:
            return
        lib.apply_patch(patch)
        lib.write()

    def has_script_mods(self, bc_mods: list["core.Mod"]):
        if not bc_mods:
            return False
        scripts = core.FridaScripts([])
        for mod in bc_mods:
            scripts.add_scripts(mod.scripts)

        scripts.validate_scripts(self.country_code, self.game_version)
        return not scripts.is_empty()

    @staticmethod
    def is_allowed_script_mods() -> bool:
        return core.config.get(core.ConfigKey.ALLOW_SCRIPT_MODS)

    def add_script_mods(self, bc_mods: list["core.Mod"]):
        if not bc_mods:
            return
        if not Apk.is_allowed_script_mods():
            return
        scripts = core.FridaScripts([])
        for mod in bc_mods:
            scripts.add_scripts(mod.scripts)

        scripts.validate_scripts(self.country_code, self.game_version)
        if not scripts.is_empty():
            self.add_frida_scripts(scripts)

    def add_patch_mods(self, bc_mods: list["core.Mod"]):
        if not bc_mods:
            return
        if not Apk.is_allowed_script_mods():
            return
        patches = core.LibPatches([])
        for mod in bc_mods:
            patches.add_patches(mod.patches)

        patches.validate_patches(self.country_code, self.game_version)
        if not patches.is_empty():
            self.add_patches(patches)

    def get_libs(self) -> dict[str, "core.Lib"]:
        if self.libs is not None:
            return self.libs
        libs: dict[str, "core.Lib"] = {}
        for architecture in self.get_architectures():
            libnative = self.parse_libnative(architecture)
            if libnative is None:
                continue
            libs[architecture] = libnative
        self.libs = libs
        return libs

    def get_manifest_path(self) -> "core.Path":
        return self.extracted_path.add("AndroidManifest.xml")

    def parse_manifest(self) -> "core.XML":
        return core.XML(self.get_manifest_path().read())

    def set_manifest(self, manifest: "core.XML"):
        manifest.to_file(self.get_manifest_path())

    def remove_arcs(self, arcs: list[str]):
        for arc in arcs:
            self.get_lib_path(arc).remove()

    def add_asset(self, asset_path: "core.Path"):
        asset_path.copy(self.extracted_path.add("assets").add(asset_path.basename()))

    def remove_asset(self, asset_path: "core.Path"):
        self.extracted_path.add("assets").add(asset_path.basename()).remove()

    def add_assets(self, asset_folder: "core.Path"):
        for asset in asset_folder.get_files():
            self.add_asset(asset)

    def add_assets_from_pack(self, pack: "core.PackFile"):
        if pack.is_server_pack(pack.pack_name):
            return
        temp_dir = self.temp_path.add("assets")
        pack.extract(temp_dir, encrypt=True)
        self.add_assets(temp_dir.add(pack.pack_name))
        temp_dir.remove()
        pack.clear_files()
        pack.add_file(
            core.GameFile(
                core.Data(pack.pack_name),
                f"empty_file_{pack.pack_name}",
                pack.pack_name,
                pack.country_code,
                pack.gv,
            )
        )
        pack.set_modified(True)

    def add_assets_from_game_packs(self, packs: "core.GamePacks"):
        for pack in packs.packs.values():
            self.add_assets_from_pack(pack)

    def add_file(self, file_path: "core.Path"):
        file_path.copy(self.extracted_path)

    def get_pack_location(self) -> "core.Path":
        if self.is_java():
            return self.extracted_path.add("res").add("raw")
        return self.extracted_path.add("assets")

    def add_audio(self, audio: "core.AudioFile"):
        audio.caf_to_little_endian().data.to_file(
            self.get_pack_location().add(audio.get_apk_name())
        )

    def add_audio_mods(self, bc_mods: list["core.Mod"]):
        for mod in bc_mods:
            for audio in mod.audio.audio_files.values():
                self.add_audio(audio)

    def get_all_audio(self) -> "core.Audio":
        audio_files: dict[str, "core.AudioFile"] = {}
        for file in self.get_pack_location().get_files():
            if not file.get_extension() == "caf" and not file.get_extension() == "ogg":
                continue
            audio_files[file.basename()] = core.AudioFile.from_file(file)
        for file in self.get_server_path(self.country_code).get_files():
            if not file.get_extension() == "caf" and not file.get_extension() == "ogg":
                continue
            audio_files[file.basename()] = core.AudioFile.from_file(file)

        return core.Audio(audio_files)

    def find_audio_path(self, audio: "core.AudioFile") -> Optional["core.Path"]:
        for file in self.get_pack_location().get_files():
            if not file.get_extension() == "caf" and not file.get_extension() == "ogg":
                continue
            if file.basename() == audio.get_apk_name():
                return file
        for file in self.get_server_path(self.country_code).get_files():
            if not file.get_extension() == "caf" and not file.get_extension() == "ogg":
                continue
            if file.basename() == audio.get_apk_name():
                return file
        return None

    def get_asset(self, asset_name: str) -> "core.Path":
        return self.extracted_path.add("assets").add(asset_name)

    def get_download_tsvs(self) -> list["core.Path"]:
        base_name = "download_%s.tsv"
        files: list["core.Path"] = []
        counter = 0
        while True:
            file = self.get_asset(base_name % counter)
            if not file.exists():
                break
            files.append(file)
            counter += 1
        return files

    def apply_mod_smali(self, mod: "core.Mod"):
        if mod.smali.is_empty():
            return
        self.get_smali_handler().inject_into_on_create(mod.smali.get_list())

    def set_allow_backup(self, allow_backup: bool):
        manifest = self.parse_manifest()
        path = "application"
        if allow_backup:
            manifest.set_attribute(path, "android:allowBackup", "true")
        else:
            manifest.set_attribute(path, "android:allowBackup", "false")
        self.set_manifest(manifest)

    def set_debuggable(self, debuggable: bool):
        manifest = self.parse_manifest()
        path = "application"
        if debuggable:
            manifest.set_attribute(path, "android:debuggable", "true")
        else:
            manifest.set_attribute(path, "android:debuggable", "false")
        self.set_manifest(manifest)

    def load_xml(self, name: str) -> "core.XML":
        strings_xml = self.extracted_path.add("res").add("values").add(f"{name}.xml")
        return core.XML(strings_xml.read())

    def save_xml(self, name: str, xml: "core.XML"):
        xml.to_file(self.extracted_path.add("res").add("values").add(f"{name}.xml"))

    def edit_xml_string(self, name: str, value: str):
        strings_xml = self.load_xml("strings")
        strings = strings_xml.get_elements("string")
        for string in strings:
            if string.get("name") == name:
                string.text = value
                break
        self.save_xml("strings", strings_xml)

    def set_app_name(self, name: str):
        self.edit_xml_string("app_name", name)

    def set_package_name(self, package_name: str):
        self.package_name = package_name
        manifest = self.parse_manifest()
        manifest.set_attribute("manifest", "package", package_name)

        self.edit_xml_string("package_name", package_name)

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

    def set_clear_text_traffic(self, clear_text_traffic: bool):
        manifest = self.parse_manifest()
        path = "application"
        if clear_text_traffic:
            manifest.set_attribute(path, "android:usesCleartextTraffic", "true")
        else:
            manifest.set_attribute(path, "android:usesCleartextTraffic", "false")
        self.set_manifest(manifest)

    def get_mod_html_files(self) -> list["core.Path"]:
        files = self.extracted_path.add("assets").get_files(
            regex=r"kisyuhen_01_top_..\.html"
        )
        return files

    def set_modded_html(self, mods: list["core.Mod"]):
        paths = self.get_mod_html_files()

        mod_html = ""
        for mod in mods:
            mod_url = f"https://tbcml.net/mod/{mod.mod_id}"
            mod_html += f'<a class="Buttonbig" href="{mod_url}">{mod.name}</a><br><br>'

        for path in paths:
            data = path.read().to_str()
            credit_message = core.local_manager.get_key("html_credit_message")
            mods_message = core.local_manager.get_key("mods")
            inject_html = f"""
<span class="midashi2">{credit_message}</span>
<hr noshade width="97%" color="#E2AF27">
<span class="midashi2">{mods_message}</span><br>
<span style="font-size:small">
{{modlist}}
</span>"""
            inject_after = '<img src="img_friend03.png" width="100%"><br>'

            pos = data.find(inject_after)
            if pos == -1:
                return
            pos += len(inject_after)
            new_data = data[:pos] + inject_html + data[pos:]

            template_file = new_data.replace("{{modlist}}", mod_html)
            self.extracted_path.add("assets", path.basename()).write(
                core.Data(template_file)
            )

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

    def add_mod_files(self, mod: "core.Mod") -> bool:
        skipped = False
        risky_extensions = self.get_risky_extensions()
        for file_name, data in mod.apk_files.items():
            if file_name.split(".")[-1] in risky_extensions:
                if not Apk.is_allowed_script_mods():
                    skipped = True
                    continue
            self.extracted_path.add(file_name).write(data)
        return skipped

    def add_mods_files(self, mods: list["core.Mod"]):
        for mod in mods:
            self.add_mod_files(mod)

    def add_smali_mods(self, mods: list["core.Mod"]):
        if not Apk.is_allowed_script_mods():
            return
        for mod in mods:
            self.apply_mod_smali(mod)

    def load_mods(
        self,
        mods: list["core.Mod"],
        game_packs: Optional["core.GamePacks"] = None,
    ):
        if game_packs is None:
            game_packs = core.GamePacks.from_apk(self)
        game_packs.apply_mods(mods)
        self.add_mods_files(mods)
        self.set_allow_backup(True)
        self.set_debuggable(True)
        self.set_modded_html(mods)
        self.add_audio_mods(mods)
        self.add_script_mods(mods)
        self.add_patch_mods(mods)
        self.add_smali_mods(mods)

        self.load_packs_into_game(game_packs)
