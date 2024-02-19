from typing import Any, Callable, Optional, Sequence

import bs4
import cloudscraper  # type: ignore
import requests
import filecmp

import tbcml


class Apk:
    def __init__(
        self,
        game_version: "tbcml.GV",
        country_code: "tbcml.CC",
        apk_folder: Optional["tbcml.PathStr"] = None,
        allowed_script_mods: bool = True,
    ):
        self.game_version = tbcml.GameVersion.from_gv(game_version)
        self.country_code = tbcml.CountryCode.from_cc(country_code)
        self.package_name = self.get_package_name()

        if apk_folder is None:
            self.apk_folder = Apk.get_default_apk_folder().get_absolute_path()
        else:
            self.apk_folder = tbcml.Path(apk_folder).get_absolute_path()

        self.smali_handler: Optional[tbcml.SmaliHandler] = None

        self.init_paths()

        self.key = None
        self.iv = None

        self.libs: Optional[dict[str, tbcml.Lib]] = None

        self.allowed_script_mods = allowed_script_mods

    def replace_lib_string(self, original: str, new: str, pad: str = "\x00") -> str:
        return tbcml.LibFiles(self).replace_str(original, new, pad)

    @staticmethod
    def from_format_string(
        format_string: str,
        apk_folder: Optional["tbcml.Path"] = None,
    ) -> "Apk":
        cc, gv, _ = format_string.split(" ")
        gv = tbcml.GameVersion.from_string(gv)
        cc = tbcml.CountryCode.from_code(cc)
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

        self.extracted_path = self.output_path.add("extracted").generate_dirs()
        self.decrypted_path = self.output_path.add("decrypted").generate_dirs()
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

        self.lib_gadgets_folder = self.get_defualt_libgadgets_folder()

    @staticmethod
    def get_defualt_libgadgets_folder() -> "tbcml.Path":
        return tbcml.Path.get_documents_folder().add("LibGadgets").generate_dirs()

    def get_packs_from_dir(self) -> list["tbcml.Path"]:
        return self.get_pack_location().get_files() + self.get_server_path().get_files()

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

    def get_packs(self) -> list["tbcml.Path"]:
        packs_list = self.get_packs_lists()
        return [pack[0] for pack in packs_list]

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

    def check_display_apk_signer_error(self) -> bool:
        if self.check_apksigner_installed():
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
        decode_resources: bool = True,
        force: bool = False,
        use_apktool: bool = True,
    ):
        if self.original_extracted_path.has_files() and not force:
            if (
                self.has_decoded_resources() == decode_resources
                and use_apktool == self.did_use_apktool()
            ):
                self.copy_extracted()
                return True

        if use_apktool:
            return self.extract_apktool(decode_resources)
        else:
            return self.extract_zip()  # TODO: decode resources without apktool

    def extract_zip(self):
        if not self.apk_path.exists():
            return False
        temp_path = self.temp_path.add("extraction")
        with tbcml.TempFolder(path=temp_path) as path:
            zip_file = tbcml.Zip(self.apk_path.read())
            zip_file.extract(path)
            self.original_extracted_path.remove().generate_dirs()
            path.copy(self.original_extracted_path)

        self.copy_extracted(force=True)
        return True

    def extract_apktool(self, decode_resources: bool = True):
        if not self.check_display_apktool_error():
            return False
        decode_resources_str = "-r" if not decode_resources else ""
        temp_path = self.temp_path.add("extraction")
        with tbcml.TempFolder(
            path=temp_path
        ) as path:  # extract to temp folder so if user cancels mid-extraction nothing bad happens
            res = self.run_apktool(
                f"d -f -s {decode_resources_str} {self.apk_path} -o {path}"
            )
            if res.exit_code != 0:
                print(f"Failed to extract APK: {res.result}")
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

        temp_path = self.temp_path.add("smali_extraction")

        with tbcml.TempFolder(path=temp_path) as temp_folder:
            res = self.run_apktool(
                f"d -f {decode_resources_str} {self.apk_path} -o {temp_folder}"
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

    def pack(self, use_apktool: Optional[bool] = None):
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
        tbcml.Zip.compress_directory(self.extracted_path, self.final_apk_path)
        return True

    def pack_apktool(self):
        if not self.check_display_apktool_error():
            return False
        res = self.run_apktool(f"b {self.extracted_path} -o {self.final_apk_path}")
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
                f"jarsigner -verbose -sigalg SHA256withRSA -digestalg SHA-256 -keystore {key_store_path} {self.final_apk_path} tbcml",
            )
            res = cmd.run(password)
        else:
            cmd = tbcml.Command(
                f"apksigner sign --ks {key_store_path} --ks-key-alias tbcml --ks-pass pass:{password} --key-pass pass:{password} {self.final_apk_path}"
            )
            res = cmd.run()
        if res.exit_code != 0:
            print(f"Failed to sign APK: {res.result}")
            return False
        return True

    def zip_align(self):
        if not self.check_display_zipalign_error():
            return
        apk_path = self.final_apk_path.change_name(
            self.final_apk_path.get_file_name_without_extension() + "-aligned.apk"
        )
        cmd = tbcml.Command(f"zipalign -f -p 4 {self.final_apk_path} {apk_path}")
        cmd.run()
        apk_path.copy(self.final_apk_path)
        cmd.run()
        apk_path.copy(self.final_apk_path)
        apk_path.remove()

    def set_key(self, key: Optional[str]):
        self.key = key

    def set_iv(self, iv: Optional[str]):
        self.iv = iv

    def randomize_key(self):
        key = tbcml.Random().get_hex_string(32)
        self.set_key(key)
        return key

    def randomize_iv(self):
        iv = tbcml.Random().get_hex_string(32)
        self.set_iv(iv)
        return iv

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

    def load_packs_into_game(
        self,
        packs: "tbcml.GamePacks",
        copy_path: Optional["tbcml.Path"] = None,
        use_apktool: Optional[bool] = None,
    ) -> bool:
        self.add_packs_lists(packs)
        tbcml.LibFiles(self).patch()
        self.copy_modded_packs()
        if not self.pack(use_apktool=use_apktool):
            return False
        if not self.sign():
            return False
        if copy_path is not None:
            self.copy_final_apk(copy_path)
        return True

    def copy_final_apk(self, path: "tbcml.Path"):
        if path == self.get_final_apk_path():
            return
        self.final_apk_path.copy(path)

    def get_final_apk_path(self) -> "tbcml.Path":
        return self.final_apk_path

    @staticmethod
    def get_default_apk_folder() -> "tbcml.Path":
        return tbcml.Path.get_documents_folder().add("APKs").generate_dirs()

    def get_package_name(self) -> str:
        return f"jp.co.ponos.battlecats{self.country_code.get_patching_code()}"

    @staticmethod
    def get_all_downloaded(all_apk_dir: Optional["tbcml.Path"] = None) -> list["Apk"]:
        """
        Get all downloaded APKs

        Returns:
            list[APK]: List of APKs
        """
        if all_apk_dir is None:
            all_apk_dir = Apk.get_default_apk_folder()
        apks: list[Apk] = []
        for apk_folder in all_apk_dir.get_dirs():
            name = apk_folder.get_file_name()
            country_code_str = name[-2:]
            if country_code_str not in tbcml.CountryCode.get_all_str():
                continue
            cc = tbcml.CountryCode.from_code(country_code_str)
            game_version_str = name[:-2]
            gv = tbcml.GameVersion.from_string_latest(game_version_str, cc)
            apk = Apk(gv, cc)
            if apk.is_downloaded():
                apks.append(apk)

        apks.sort(key=lambda apk: apk.game_version.game_version, reverse=True)

        return apks

    @staticmethod
    def get_all_apks_cc(
        cc: "tbcml.CountryCode", apk_folder: Optional["tbcml.Path"] = None
    ) -> list["Apk"]:
        """
        Get all APKs for a country code

        Args:
            cc (country_code.CountryCode): Country code

        Returns:
            list[APK]: List of APKs
        """
        apks = Apk.get_all_downloaded(apk_folder)
        apks_cc: list[Apk] = []
        for apk in apks:
            if apk.country_code == cc:
                apks_cc.append(apk)
        return apks_cc

    @staticmethod
    def get_latest_downloaded_version_cc(
        cc: "tbcml.CountryCode", apk_folder: Optional["tbcml.Path"] = None
    ) -> "tbcml.GameVersion":
        """
        Get latest downloaded APK version for a country code

        Args:
            cc (country_code.CountryCode): Country code

        Returns:
            game_version.GameVersion: Latest APK version
        """
        max_version = tbcml.GameVersion(0)
        for apk in Apk.get_all_apks_cc(cc, apk_folder):
            if apk.game_version > max_version:
                max_version = apk.game_version
        return max_version

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

        for v in versions:
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
        if not versions:
            if cc == tbcml.CountryCode.EN or cc == tbcml.CountryCode.JP:
                versions = Apk.get_all_versions_en(cc)
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

    def format(self):
        return f"{self.country_code.name} {self.game_version.format()} APK"

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
        progress: Optional[Callable[[float, int, int, bool], None]] = progress,
        force: bool = False,
        apk_list_url: str = "https://raw.githubusercontent.com/fieryhenry/BCData/master/apk_list.json",
    ) -> bool:
        if self.apk_path.exists() and not force:
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
        _total_length = int(stream.headers.get("content-length"))  # type: ignore

        dl = 0
        chunk_size = 1024
        buffer: list[bytes] = []
        for d in stream.iter_content(chunk_size=chunk_size):
            dl += len(d)
            buffer.append(d)
            if progress is not None:
                progress(dl / _total_length, dl, _total_length, True)

        apk = tbcml.Data(b"".join(buffer))
        apk.to_file(self.apk_path)
        return True

    def download(
        self,
        progress: Optional[Callable[[float, int, int, bool], None]] = progress,
        force: bool = False,
    ) -> bool:
        if self.download_v1(progress, force):
            return True
        if self.download_v2(progress, force):
            return True
        return False

    def download_v1(
        self,
        progress: Optional[Callable[[float, int, int, bool], None]] = progress,
        force: bool = False,
    ) -> bool:
        if self.apk_path.exists() and not force:
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
        self, progress: Optional[Callable[[float, int, int, bool], None]] = progress
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
                progress(dl / _total_length, dl, _total_length, True)

        apk = tbcml.Data(b"".join(buffer))
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
                progress(dl / _total_length, dl, _total_length, True)

        apk = tbcml.Data(b"".join(buffer))
        apk.to_file(self.apk_path)
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

    def create_key(self, key: str, length_override: Optional[int] = None) -> str:
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

    def create_iv(
        self, iv: str, length_override: Optional[int] = None
    ) -> Optional[str]:
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

    def is_downloaded(self) -> bool:
        return self.apk_path.exists()

    def delete(self):
        self.output_path.remove_tree()

    @staticmethod
    def clean_up(apk_folder: Optional["tbcml.Path"] = None):
        for apk in Apk.get_all_downloaded(apk_folder):
            if apk.is_downloaded():
                continue
            apk.delete()

    def get_display_string(self) -> str:
        return f"{self.game_version.format()} <dark_green>({self.country_code})</>"

    def download_server_files(
        self,
        display: bool = False,
        force: bool = False,
        lang: Optional["tbcml.Language"] = None,
    ):
        sfh = tbcml.ServerFileHandler(self, lang=lang)
        sfh.extract_all(display=display, force=force)

    @staticmethod
    def get_server_path_static(
        cc: "tbcml.CountryCode", apk_folder: Optional["tbcml.Path"] = None
    ) -> "tbcml.Path":
        if apk_folder is None:
            apk_folder = Apk.get_default_apk_folder()
        return apk_folder.parent().add(f"{cc.get_code()}_server")

    def get_server_path(self):
        return Apk.get_server_path_static(self.country_code, self.apk_folder)

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
    def from_apk_path(
        apk_path: "tbcml.Path",
        cc_overwrite: Optional["tbcml.CountryCode"] = None,
        gv_overwrite: Optional["tbcml.GameVersion"] = None,
        apk_folder: Optional["tbcml.Path"] = None,
        allowed_script_mods: bool = True,
    ) -> "Apk":
        cc, gv = Apk.get_package_name_version_from_apk(apk_path)

        if cc is None:
            cc = cc_overwrite
        if gv is None:
            gv = gv_overwrite

        if gv is None or cc is None:
            raise ValueError("Failed to get cc or gv from apk.")

        apk = Apk(
            gv, cc, apk_folder=apk_folder, allowed_script_mods=allowed_script_mods
        )
        apk_path.copy(apk.apk_path)
        apk.original_extracted_path.remove_tree().generate_dirs()
        return apk

    def get_architectures(self) -> list[str]:
        architectures: list[str] = []
        for folder in self.extracted_path.add("lib").get_dirs():
            arc = folder.basename()
            architectures.append(arc)
        return architectures

    def get_64_bit_arcs(self) -> list[str]:
        architectures: list[str] = []
        bit_64 = tbcml.Lib.get_64_bit_arcs()
        for folder in self.extracted_path.add("lib").get_dirs():
            arc = folder.basename()
            if arc in bit_64:
                architectures.append(arc)
        return architectures

    def get_32_bit_arcs(self) -> list[str]:
        architectures: list[str] = []
        bit_32 = tbcml.Lib.get_32_bit_arcs()
        for folder in self.extracted_path.add("lib").get_dirs():
            arc = folder.basename()
            if arc in bit_32:
                architectures.append(arc)
        return architectures

    def __str__(self):
        return self.get_display_string()

    def __repr__(self):
        return self.get_display_string()

    def get_libnative_path(self, architecture: str) -> "tbcml.Path":
        if not self.is_java():
            return self.get_lib_path(architecture).add("libnative-lib.so")
        return self.get_lib_path(architecture).add("libbattlecats-jni.so")

    def is_java(self):
        return self.get_lib_path("x86").add("libbattlecats-jni.so").exists()

    def parse_libnative(self, architecture: str) -> Optional["tbcml.Lib"]:
        path = self.get_libnative_path(architecture)
        if not path.exists():
            return None
        return tbcml.Lib(architecture, path)

    def get_smali_handler(self) -> "tbcml.SmaliHandler":
        if self.smali_handler is None:
            self.smali_handler = tbcml.SmaliHandler(self)
        return self.smali_handler

    def add_library(
        self,
        architecture: str,
        library_path: "tbcml.Path",
        inject_native_lib: bool = True,
        inject_smali: bool = False,
    ):
        if inject_smali:
            self.get_smali_handler().inject_load_library(library_path.basename())
        if inject_native_lib:
            libnative = self.get_libs().get(architecture)
            if libnative is None:
                print(f"Could not find libnative for {architecture}")
                return
            libnative.add_library(library_path)
            libnative.write()
        self.add_to_lib_folder(architecture, library_path)

    def get_lib_path(self, architecture: str) -> "tbcml.Path":
        return self.extracted_path.add("lib").add(architecture)

    def import_libraries(self, lib_folder: "tbcml.Path"):
        for architecture in self.get_architectures():
            libs_path = lib_folder.add(architecture)
            if not libs_path.exists():
                continue
            for lib in libs_path.get_files():
                self.add_library(architecture, lib)

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

    def create_libgadget_config(self):
        json_data = {
            "interaction": {
                "type": "script",
                "path": "libbc_script.js.so",
                "on_change": "reload",
            }
        }
        json = tbcml.JsonFile.from_object(json_data)
        return json

    def add_libgadget_config(self, used_arcs: list[str]):
        config = self.create_libgadget_config()
        with tbcml.TempFile(
            path=self.temp_path.add("libfrida-gadget.config")
        ) as temp_file:
            config.to_data().to_file(temp_file)
            for architecture in used_arcs:
                self.add_to_lib_folder(architecture, temp_file)

    def add_libgadget_scripts(self, scripts: dict[str, str]):
        with tbcml.TempFile(
            path=self.temp_path.add("libbc_script.js.so")
        ) as script_path:
            for architecture, script_str in scripts.items():
                tbcml.Data(script_str).to_file(script_path)
                self.add_to_lib_folder(architecture, script_path)

    @staticmethod
    def get_libgadgets_path(
        lib_gadgets_folder: Optional["tbcml.Path"] = None,
    ) -> "tbcml.Path":
        if lib_gadgets_folder is None:
            lib_gadgets_folder = Apk.get_defualt_libgadgets_folder()
        lib_gadgets_folder.generate_dirs()
        arcs = ["arm64-v8a", "armeabi-v7a", "x86", "x86_64"]
        for arc in arcs:
            lib_gadgets_folder.add(arc).generate_dirs()
        return lib_gadgets_folder

    @staticmethod
    def download_libgadgets():
        tbcml.FridaGadgetHelper().download_gadgets()

    def get_libgadgets(self) -> dict[str, "tbcml.Path"]:
        folder = Apk.get_libgadgets_path(self.lib_gadgets_folder)
        Apk.download_libgadgets()
        arcs = folder.get_dirs()
        libgadgets: dict[str, "tbcml.Path"] = {}
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

    def add_patches(self, patches: "tbcml.LibPatches"):
        for patch in patches.lib_patches:
            self.add_patch(patch)

    def add_patch(self, patch: "tbcml.LibPatch"):
        arcs = self.get_architectures_subset(patch.architectures)

        for arc in arcs:
            lib = self.parse_libnative(arc)
            if lib is None:
                return
            lib.apply_patch(patch)
            lib.write()

    def get_architectures_subset(self, arcs: "tbcml.ARCS") -> Sequence[str]:
        if arcs == "all":
            return self.get_architectures()
        elif arcs == "32":
            return self.get_32_bit_arcs()
        elif arcs == "64":
            return self.get_64_bit_arcs()

        all_arcs = self.get_architectures()
        return [arc for arc in arcs if arc in all_arcs]

    def is_allowed_script_mods(self) -> bool:
        return self.allowed_script_mods

    def set_allowed_script_mods(self, allowed: bool):
        self.allowed_script_mods = allowed

    def add_script_mods(self, bc_mods: list["tbcml.Mod"], add_base_script: bool = True):
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

    def add_modded_html(self, mods: list["tbcml.Mod"]):
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

    def add_patch_mods(self, bc_mods: list["tbcml.Mod"]):
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

    def get_libs(self) -> dict[str, "tbcml.Lib"]:
        if self.libs is not None:
            return self.libs
        libs: dict[str, "tbcml.Lib"] = {}
        for architecture in self.get_architectures():
            libnative = self.parse_libnative(architecture)
            if libnative is None:
                continue
            libs[architecture] = libnative
        self.libs = libs
        return libs

    def get_manifest_path(self) -> "tbcml.Path":
        return self.extracted_path.add("AndroidManifest.xml")

    def parse_manifest(self) -> Optional["tbcml.XML"]:
        try:
            return tbcml.XML(self.get_manifest_path().read())
        except Exception:
            return None

    def set_manifest(self, manifest: "tbcml.XML"):
        manifest.to_file(self.get_manifest_path())

    def remove_arcs(self, arcs: list[str]):
        for arc in arcs:
            self.get_lib_path(arc).remove()

    def add_asset(self, asset_path: "tbcml.Path"):
        asset_path.copy(self.extracted_path.add("assets").add(asset_path.basename()))

    def add_asset_data(self, asset_path: "tbcml.Path", asset_data: "tbcml.Data"):
        self.extracted_path.add("assets").add(asset_path).write(asset_data)

    def remove_asset(self, asset_path: "tbcml.Path"):
        self.extracted_path.add("assets").add(asset_path.basename()).remove()

    def add_assets(self, asset_folder: "tbcml.Path"):
        for asset in asset_folder.get_files():
            self.add_asset(asset)

    def add_assets_from_pack(self, pack: "tbcml.PackFile"):
        if pack.is_server_pack(pack.pack_name):
            return
        with tbcml.TempFolder(path=self.temp_path.add("assets")) as temp_dir:
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

    def add_assets_from_game_packs(self, packs: "tbcml.GamePacks"):
        for pack in packs.packs.values():
            self.add_assets_from_pack(pack)

    def add_file(self, file_path: "tbcml.Path"):
        file_path.copy(self.extracted_path)

    def get_pack_location(self) -> "tbcml.Path":
        if self.is_java():
            return self.extracted_path.add("res").add("raw")
        return self.extracted_path.add("assets")

    def add_audio(
        self,
        audio_file: "tbcml.AudioFile",
    ):
        filename = audio_file.get_apk_file_name()
        audio_file.caf_to_little_endian().data.to_file(
            self.extracted_path.add("assets").add(filename)
        )

    def get_all_audio(self) -> dict[int, "tbcml.Path"]:
        audio_files: dict[int, "tbcml.Path"] = {}
        for file in self.extracted_path.get_files():
            if not file.get_extension() == "caf" and not file.get_extension() == "ogg":
                continue
            base_name = file.get_file_name_without_extension()
            if not base_name.startswith("snd"):
                continue
            id_str = base_name.strip("snd")
            if not id_str.isdigit():
                continue
            audio_files[int(id_str)] = file

        for file in self.get_server_path().get_files():
            if not file.get_extension() == "caf" and not file.get_extension() == "ogg":
                continue
            id_str = file.get_file_name_without_extension().strip("snd")
            if not id_str.isdigit():
                continue
            audio_files[int(id_str)] = file
        return audio_files

    def get_free_audio_id(self, all_audio: Optional[dict[int, "tbcml.Path"]] = None):
        if all_audio is None:
            all_audio = self.get_all_audio()

        i = 0
        while True:
            if i not in all_audio:
                return i
            i += 1

    def get_asset(self, asset_name: str) -> "tbcml.Path":
        return self.extracted_path.add("assets").add(asset_name)

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

    def load_xml(self, name: str) -> Optional["tbcml.XML"]:
        strings_xml = self.extracted_path.add("res").add("values").add(f"{name}.xml")
        if not strings_xml.exists():
            return None
        return tbcml.XML(strings_xml.read())

    def save_xml(self, name: str, xml: "tbcml.XML"):
        xml.to_file(self.extracted_path.add("res").add("values").add(f"{name}.xml"))

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

    def set_app_name(self, name: str) -> bool:
        return self.edit_xml_string("app_name", name)

    def replace_str_manifest(self, old: str, new: str):
        manifest = self.get_manifest_path()
        manifest_str = manifest.read().to_str()
        manifest_str = manifest_str.replace(old, new)
        manifest.write(tbcml.Data(manifest_str))

    def set_package_name(self, package_name: str) -> bool:
        manifest = self.parse_manifest()
        if manifest is None:
            return False

        current_package = manifest.get_attribute("manifest", "package")

        manifest.set_attribute("manifest", "package", package_name)

        if not self.edit_xml_string("package_name", package_name):
            return False

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
        self.package_name = package_name

        if current_package is not None:
            self.replace_str_manifest(current_package, package_name)

        return True

    def copy_to_android_download_folder(self):
        download_path = tbcml.Path.get_root().add(
            "sdcard", "Download", self.final_apk_path.basename()
        )
        download_path.parent().generate_dirs()
        self.final_apk_path.copy(download_path)

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

    def get_mod_html_files(self) -> list["tbcml.Path"]:
        files = self.extracted_path.add("assets").get_files(
            regex=r"kisyuhen_01_top_..\.html"
        )
        return files

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

    def add_mods_files(self, mods: list["tbcml.Mod"]):
        for mod in mods:
            mod.apply_to_apk(self)

    def add_smali_mods(self, mods: list["tbcml.Mod"]):
        if not self.is_allowed_script_mods():
            return
        for mod in mods:
            self.apply_mod_smali(mod)

    def load_mods(
        self,
        mods: list["tbcml.Mod"],
        game_packs: Optional["tbcml.GamePacks"] = None,
        lang: Optional["tbcml.Language"] = None,
        key: Optional[str] = None,
        iv: Optional[str] = None,
        add_modded_html: bool = True,
        use_apktool: Optional[bool] = None,
    ) -> bool:
        if game_packs is None:
            game_packs = tbcml.GamePacks.from_apk(self, lang=lang)

        if key is not None:
            self.set_key(key)
        if iv is not None:
            self.set_iv(iv)

        self.add_smali_mods(mods)

        self.add_script_mods(mods)
        self.add_patch_mods(mods)

        game_packs.apply_mods(mods)

        self.set_allow_backup(True)
        self.set_debuggable(True)

        if add_modded_html:
            self.add_modded_html(mods)

        self.add_mods_files(mods)

        if not self.load_packs_into_game(game_packs, use_apktool=use_apktool):
            return False
        return True
