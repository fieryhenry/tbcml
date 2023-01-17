import subprocess
from typing import Any, Callable, Optional

import bs4
import cloudscraper  # type: ignore
import requests

from bcml.core import country_code, game_data, game_version, mods, request
from bcml.core.io import command, config, data, file_handler, json_file, lib, path


class Apk:
    def __init__(
        self,
        game_version: game_version.GameVersion,
        country_code: country_code.CountryCode,
        apk_folder: Optional[path.Path] = None,
    ):
        self.game_version = game_version
        self.country_code = country_code
        self.package_name = self.get_package_name()

        if apk_folder is None:
            apk_folder = self.get_default_apk_folder()
        self.apk_folder = apk_folder

        self.init_paths()

    def init_paths(self):
        self.apk_folder.generate_dirs()
        self.server_path = self.apk_folder.add(
            f"{self.country_code.get_code()}_server_packs"
        )
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

    def get_packs_lists(self) -> list[tuple[path.Path, path.Path]]:
        files: list[tuple[path.Path, path.Path]] = []
        for file in self.packs_path.get_files():
            if file.get_extension() != "pack":
                continue
            list_file = file.change_extension("list")
            if list_file.exists():
                files.append((file, list_file))
        return files

    def get_packs(self) -> list[path.Path]:
        packs_list = self.get_packs_lists()
        return [pack[0] for pack in packs_list]

    def copy_packs(self):
        self.packs_path.remove_tree().generate_dirs()
        packs = self.extracted_path.add("assets").get_files()
        for pack in packs:
            if pack.get_extension() == "pack" or pack.get_extension() == "list":
                pack.copy(self.packs_path)

    def copy_extracted(self):
        self.extracted_path.remove_tree().generate_dirs()
        self.original_extracted_path.copy(self.extracted_path)

    def extract(self):
        if self.original_extracted_path.has_files():
            self.copy_extracted()
            self.copy_packs()
            return
        cmd = command.Command(
            f"apktool d -f -s {self.apk_path} -o {self.original_extracted_path}", False
        )
        cmd.run()
        self.copy_extracted()
        self.copy_packs()
        self.libs = self.get_libs()

    def pack(self):
        cmd = command.Command(
            f"apktool b {self.extracted_path} -o {self.final_apk_path}", False
        )
        cmd.run()

    def sign(self):
        password = config.Config().get(config.Key.KEYSTORE_PASSWORD)
        key_store_name = "bcml.keystore"
        key_store_path = path.Path.get_appdata_folder().add(key_store_name)
        if not key_store_path.exists():
            cmd = command.Command(
                f'keytool -genkey -v -keystore {key_store_path} -alias bcml -keyalg RSA -keysize 2048 -validity 10000 -storepass {password} -keypass {password} -dname "CN=, OU=, O=, L=, S=, C="',
                False,
            )
            cmd.run()
        cmd = command.Command(
            f"jarsigner -verbose -sigalg SHA256withRSA -digestalg SHA-256 -keystore {key_store_path} {self.final_apk_path} bcml",
            False,
        )
        cmd.run(password)

    def add_packs_lists(self, packs: game_data.pack.GamePacks):
        files = packs.to_packs_lists()
        for pack_name, pack_data, list_data in files:
            self.add_pack_list(pack_name, pack_data, list_data)

    def add_pack_list(
        self, pack_name: str, pack_data: "data.Data", list_data: "data.Data"
    ):
        pack_path = self.modified_packs_path.add(pack_name + ".pack")
        list_path = self.modified_packs_path.add(pack_name + ".list")
        pack_data.to_file(pack_path)
        list_data.to_file(list_path)

    def copy_modded_packs(self):
        for file in self.modified_packs_path.get_files():
            file.copy(self.extracted_path.add("assets").add(file.basename()))

    def load_packs_into_game(self, packs: game_data.pack.GamePacks):
        print("Creating pack and list files...")
        self.add_packs_lists(packs)
        print("Patching lib...")
        lib.LibFiles(self).patch()
        print("Copying modded packs...")
        self.copy_modded_packs()
        print("Packing apk...")
        self.pack()
        print("Signing apk...")
        self.sign()
        print("Copying final apk...")
        self.copy_final_apk()

    def copy_final_apk(self):
        final_path = config.Config().get(config.Key.APK_COPY_PATH)
        if final_path is None:
            return
        final_path = path.Path(final_path)
        if final_path.get_extension() == "apk":
            final_path.parent().generate_dirs()
        else:
            final_path.add(self.final_apk_path.basename())
        self.final_apk_path.copy(final_path)

    @staticmethod
    def get_default_apk_folder() -> path.Path:
        folder = path.Path(config.Config().get(config.Key.APK_FOLDER)).generate_dirs()
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
        all_apk_dir = path.Path(config.Config().get(config.Key.APK_FOLDER))
        apks: list[Apk] = []
        for apk_folder in all_apk_dir.get_dirs():
            name = apk_folder.get_file_name()
            country_code_str = name[-2:]
            if country_code_str not in country_code.CountryCode.get_all_str():
                continue
            cc = country_code.CountryCode.from_code(country_code_str)
            game_version_str = name[:-2]
            gv = game_version.GameVersion.from_string_latest(game_version_str, cc)
            apks.append(Apk(gv, cc))

        apks.sort(key=lambda apk: apk.game_version.game_version, reverse=True)

        return apks

    @staticmethod
    def get_all_apks_cc(cc: country_code.CountryCode) -> list["Apk"]:
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
    def get_all_versions(
        cc: country_code.CountryCode,
    ) -> list[game_version.GameVersion]:
        """
        Get all APK versions

        Args:
            cc (country_code.CountryCode): Country code

        Returns:
            game_version.GameVersion: List of APK versions
        """
        if cc == country_code.CountryCode.EN:
            return Apk.get_all_versions_en()
        url = Apk.get_apk_version_url(cc)
        scraper = cloudscraper.create_scraper()  # type: ignore
        resp = scraper.get(url)
        soup = bs4.BeautifulSoup(resp.text, "html.parser")
        versionwrapp = soup.find("ul", {"class": "ver-wrap"})
        if not isinstance(versionwrapp, bs4.element.Tag):
            print("Could not find versionwrapp")
            return []
        versions: list[game_version.GameVersion] = []
        for version in versionwrapp.find_all("li"):
            if not isinstance(version, bs4.element.Tag):
                print("Version is not a tag")
                continue
            version_anchor = version.find("a")
            if not isinstance(version_anchor, bs4.element.Tag):
                print("Version anchor is not a tag")
                continue
            version = version_anchor.get_attribute_list("data-dt-versioncode")[0]
            versions.append(game_version.GameVersion(int(version[:-1])))
        return versions

    @staticmethod
    def get_latest_version(cc: country_code.CountryCode):
        versions = Apk.get_all_versions(cc)
        if len(versions) == 0:
            return None
        return versions[0]

    def format(self):
        return f"{self.country_code.name} {self.game_version.format()} APK"

    @staticmethod
    def progress(progress: float, current: int, total: int, is_file_size: bool = False):
        total_bar_length = 70
        if is_file_size:
            current_str = file_handler.FileSize(current).format()
            total_str = file_handler.FileSize(total).format()
        else:
            current_str = str(current)
            total_str = str(total)
        bar_length = int(total_bar_length * progress)
        bar = "#" * bar_length + "-" * (total_bar_length - bar_length)
        print(
            f"\r[{bar}] {int(progress * 100)}% ({current_str}/{total_str})    ",
            end="",
        )

    def download_apk(
        self,
        progress_callback: Optional[Callable[[float, int, int, bool], None]] = None,
    ) -> bool:
        if progress_callback is None:
            progress_callback = self.progress
        if self.apk_path.exists():
            return True
        if self.country_code == country_code.CountryCode.EN:
            return self.download_apk_en(progress_callback)
        else:
            url = self.get_download_url()
            scraper = cloudscraper.create_scraper()  # type: ignore
            scraper.headers.update(
                {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36"
                }
            )
            stream = scraper.get(url, stream=True, timeout=10)
            total_length = int(stream.headers.get("content-length"))  # type: ignore
            dl = 0
            chunk_size = 1024
            buffer = b""
            for d in stream.iter_content(chunk_size=chunk_size):
                dl += len(d)
                buffer += d
                progress_callback(dl / total_length, dl, total_length, True)
            progress_callback(1, total_length, total_length, True)

            apk = data.Data(stream.content)
            apk.to_file(self.apk_path)
            return True

    def download_apk_en(
        self,
        progress_callback: Optional[Callable[[float, int, int, bool], None]] = None,
    ) -> bool:
        if progress_callback is None:
            progress_callback = self.progress
        urls = Apk.get_en_apk_urls("the-battle-cats")
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
        stream = request.RequestHandler(url, headers).get_stream(progress_callback)
        apk = data.Data(stream.content)
        apk.to_file(self.apk_path)
        return True

    def get_en_apk_url(self, apk_url: str):
        resp = request.RequestHandler(apk_url).get()
        soup = bs4.BeautifulSoup(resp.text, "html.parser")
        download_button = soup.find("button", {"class": "button download"})
        if not isinstance(download_button, bs4.element.Tag):
            return None
        return str(download_button.get_attribute_list("data-url")[0])

    @staticmethod
    def get_en_app_id(package_name: str) -> Optional[str]:
        url = f"https://{package_name}.en.uptodown.com/android/versions"
        try:
            resp = request.RequestHandler(url).get()
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
        url = f"https://{package_name}.en.uptodown.com/android/apps/{app_id}/versions?page[limit]=200&page[offset]=0"
        resp = request.RequestHandler(url).get()
        return resp.json()["data"]

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
    def get_all_versions_en() -> list[game_version.GameVersion]:
        apk_urls = Apk.get_en_apk_urls("the-battle-cats")
        if apk_urls is None:
            return []
        versions: list[game_version.GameVersion] = []
        for version in apk_urls.keys():
            versions.append(game_version.GameVersion.from_string(version))
        return versions

    @staticmethod
    def get_apk_version_url(cc: country_code.CountryCode) -> str:
        if cc == country_code.CountryCode.JP:
            url = "https://m.apkpure.com/%E3%81%AB%E3%82%83%E3%82%93%E3%81%93%E5%A4%A7%E6%88%A6%E4%BA%89/jp.co.ponos.battlecats/versions"
        elif cc == country_code.CountryCode.KR:
            url = "https://m.apkpure.com/%EB%83%A5%EC%BD%94-%EB%8C%80%EC%A0%84%EC%9F%81/jp.co.ponos.battlecatskr/versions"
        elif cc == country_code.CountryCode.TW:
            url = "https://m.apkpure.com/%E8%B2%93%E5%92%AA%E5%A4%A7%E6%88%B0%E7%88%AD/jp.co.ponos.battlecatstw/versions"
        else:
            raise ValueError(f"Country code {cc} not supported")
        return url

    def is_downloaded(self) -> bool:
        return self.apk_path.exists()

    def delete(self):
        self.apk_folder.remove_tree()

    @staticmethod
    def clean_up():
        for apk in Apk.get_all_downloaded():
            if apk.is_downloaded():
                continue
            print(f"Deleting {apk.get_display_string()}")
            # apk.delete()

    def get_display_string(self) -> str:
        return f"{self.game_version.format()} <dark_green>({self.country_code})</>"

    def download_server_files(
        self, progress_callback: Optional[Callable[[float, int, int], None]] = None
    ):
        if progress_callback is None:
            progress_callback = self.progress
        url = f"https://api.github.com/repos/fieryhenry/BCData/git/trees/master?recursive=2"
        resp = request.RequestHandler(url).get()
        json_data = resp.json()
        if "tree" not in json_data:
            self.copy_server_files()
            return
        urls: list[str] = []
        for item in json_data["tree"]:
            if (
                str(item["path"]).split("/")[0]
                == f"{self.country_code.get_code()}_server"
                and len(str(item["path"]).split("/")) == 2
            ):
                url = f"https://raw.githubusercontent.com/fieryhenry/BCData/master/{item['path']}"
                urls.append(url)

        output_dir = (
            self.apk_folder.parent()
            .add(f"{self.country_code.get_code()}_server")
            .generate_dirs()
        )
        new_urls: list[str] = []
        for url in urls:
            file_path = output_dir.add(url.split("/")[-1])
            if file_path.exists():
                continue
            new_urls.append(url)
        total = len(new_urls)
        for i, url in enumerate(new_urls):
            file_path = output_dir.add(url.split("/")[-1])
            res = request.RequestHandler(url).get()
            file_path.write(data.Data(res.content))
            if progress_callback is not None:
                progress_callback(i / total, i, total - 1)
        self.copy_server_files()

    def copy_server_files(self):
        server_path = self.apk_folder.parent().add(
            f"{self.country_code.get_code()}_server"
        )
        if not server_path.exists():
            return
        for file in server_path.get_files():
            file.copy(self.packs_path.add(file.basename()))

    @staticmethod
    def from_apk_path(apk_path: path.Path) -> "Apk":
        command = f"aapt dump badging {apk_path}"
        process = subprocess.Popen(
            command,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.PIPE,
        )
        output = process.communicate()[0].decode("utf-8")
        version_name = ""
        package_name = ""
        for line in output.splitlines():
            if "versionName" in line:
                version_name = line.split("versionName='")[1].split("'")[0]
            if "package: name=" in line:
                package_name = line.split("name='")[1].split("'")[0]
        if version_name == "" or package_name == "":
            raise ValueError(
                f"Could not get version name or package name from {apk_path}"
            )

        cc_str = package_name.replace("jp.co.ponos.battlecats", "")
        cc = country_code.CountryCode.from_patching_code(cc_str)
        gv = game_version.GameVersion.from_string(version_name)
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

    def get_libnative_path(self, architecture: str) -> "path.Path":
        return self.get_lib_path(architecture).add("libnative-lib.so")

    def parse_libnative(self, architecture: str) -> Optional["lib.Lib"]:
        path = self.get_libnative_path(architecture)
        if not path.exists():
            return None
        return lib.Lib(architecture, path)

    def add_library(self, architecture: str, library_path: "path.Path"):
        libnative = self.libs.get(architecture)
        if libnative is None:
            print(f"Could not find libnative for {architecture}")
            return
        libnative.add_library(library_path)  # type: ignore
        libnative.write()  # type: ignore
        self.add_to_lib_folder(architecture, library_path)

    def get_lib_path(self, architecture: str) -> "path.Path":
        return self.extracted_path.add("lib").add(architecture)

    def import_libraries(self, lib_folder: "path.Path"):
        for architecture in self.get_architectures():
            libs_path = lib_folder.add(architecture)
            if not libs_path.exists():
                continue
            for lib in libs_path.get_files():
                self.add_library(architecture, lib)

    def add_to_lib_folder(self, architecture: str, library_path: "path.Path"):
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
        json = json_file.JsonFile.from_json(json_data)
        return json

    def add_libgadget_config(self, used_arcs: list[str]):
        config = self.create_libgadget_config()
        temp_file = self.temp_path.add("libgadget.config")
        config.to_data().to_file(temp_file)

        for architecture in used_arcs:
            self.add_to_lib_folder(architecture, temp_file)

        temp_file.remove()

    def add_libgadget_scripts(self, scripts: "mods.frida_script.Scripts"):
        for architecture in scripts.get_used_arcs():
            script_str = scripts.combine_scripts(architecture)
            script_path = self.temp_path.add(f"libbc_script.js.so")
            script_str.to_file(script_path)
            self.add_to_lib_folder(architecture, script_path)
            script_path.remove()

    def get_libgadgets(self) -> dict[str, "path.Path"]:
        folder = config.Config().get(config.Key.LIB_GADGETS_FOLDER)
        arcs = path.Path(folder).generate_dirs().get_dirs()
        libgadgets: dict[str, "path.Path"] = {}
        for arc in arcs:
            so_regex = ".*\\.so"
            files = arc.get_files(regex=so_regex)
            if len(files) == 0:
                continue
            libgadgets[arc.basename()] = files[0]
        return libgadgets

    def add_libgadget_sos(self, used_arcs: list[str]):
        for architecture, libgadget in self.get_libgadgets().items():
            if architecture not in used_arcs:
                continue
            self.add_library(architecture, libgadget)

    def add_frida_scripts(self, scripts: "mods.frida_script.Scripts"):
        used_arcs = scripts.get_used_arcs()
        self.add_libgadget_config(used_arcs)
        self.add_libgadget_scripts(scripts)
        self.add_libgadget_sos(used_arcs)

    def get_libs(self) -> dict[str, "lib.Lib"]:
        libs: dict[str, "lib.Lib"] = {}
        for architecture in self.get_architectures():
            libnative = self.parse_libnative(architecture)
            if libnative is None:
                continue
            libs[architecture] = libnative
        return libs
