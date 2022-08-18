from multiprocessing import Process
import os
import random
import shutil
import subprocess
from typing import Any, Optional, Union
import requests
import bs4
from . import helper, mod


class BC_APK:
    """
    Class for downloading the apk, extracting files and loading the mods
    """

    def __init__(self, game_version: str, is_jp: bool, output_path: str):
        """
        Initialize the class

        Args:
            game_version (str): The game version to use. Example: 11.7.1 or latest
            is_jp (bool): If the apk is the jp version or not
            output_path (str): The path to the output folder for the apk, extracted files, and packs

        Raises:
            ValueError: If the game version is not valid
        """

        self.is_jp = is_jp
        self.package_name = f"the-battle-cats-{self.get_jp_str()}"
        gv = self.process_version(game_version)
        if gv is None:
            raise ValueError("Invalid game version")
        self.game_version = gv

        self.output_path = os.path.join(
            output_path, f"{self.game_version}{self.get_jp_str()}"
        )
        self.apk_path = os.path.join(self.output_path, f"original.apk")
        self.final_apk_path = os.path.join(self.output_path, f"modded.apk")
        self.extracted_path = os.path.join(self.output_path, f"extracted")
        self.packs_path = os.path.join(self.output_path, f"packs")
        self.decrypted_path = os.path.join(self.output_path, f"decrypted")
        self.wipe()
        self.make_dirs()

    def get_as_mod(self, pack_files: list[str]) -> mod.Mod:
        """
        Get specific pack files as a mod

        Args:
            pack_files (list[str]): What packfiles to include in the mod

        Returns:
            mod.Mod: The mod
        """
        print("Downloading base game files")
        self.download()
        print("Extracting base game files")
        self.extract()
        print("Creating mod")
        return self.create_mod(pack_files)

    def copy_packs_lists(self) -> None:
        """
        Copy the packs and lists from the extracted folder to the packs folder
        """
        path = os.path.join(self.extracted_path, "assets")
        for file in os.listdir(path):
            if file.endswith(".pack") or file.endswith(".list"):
                shutil.copy(os.path.join(path, file), self.packs_path)

    def insert_packs_lists(self) -> None:
        """
        Copy the packs and lists from the packs folder to the extracted folder
        """
        path = os.path.join(self.extracted_path, "assets")
        for file in os.listdir(self.packs_path):
            if file.endswith(".pack") or file.endswith(".list"):
                shutil.copy(os.path.join(self.packs_path, file), path)

    def create_mod(self, pack_files: list[str]) -> mod.Mod:
        """
        Create a mod from the pack files

        Args:
            pack_files (list[str]): What packfiles to include in the mod

        Returns:
            mod.Mod: The mod
        """
        modpack = mod.Mod(
            name=self.package_name,
            author="Ponos",
            description="Base game files",
            game_version=int(helper.str_to_gv(self.game_version)),
            country_code=self.get_jp_str(),
            create_mod_info=False,
        )
        path = os.path.join(self.packs_path)
        for file in os.listdir(path):
            if (
                file.endswith(".pack")
                and os.path.basename(file.strip(".pack")) in pack_files
            ):
                print(f"Adding pack file {file}")
                modpack.import_pack(
                    os.path.join(path, file),
                    True,
                )
        return modpack

    def load_mod(self, bc_mod: Union[mod.Mod, mod.ModPack]) -> None:
        """
        Load the mod into the apk

        Args:
            bc_mod (Union[mod.Mod, mod.ModPack]): The mod to load
        """
        print("Creating .pack and .list files")
        bc_mod.write_game_files(self.packs_path)
        print("Packing apk")
        self.insert_packs_lists()
        self.pack()
        print("Signing apk")
        self.sign_apk()

    def extract(self) -> None:
        """
        Extract the apk to the extracted folder
        """
        process = subprocess.Popen(
            f"apktool d -f -s {self.apk_path} -o {self.extracted_path}",
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.PIPE,
        )
        process.communicate()
        self.copy_packs_lists()

    def pack(self) -> None:
        """
        Turn the extracted folder into an apk
        """
        process = subprocess.Popen(
            f"apktool b {self.extracted_path} -o {self.final_apk_path}",
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.PIPE,
        )
        process.communicate()

    def sign_apk(self) -> None:
        """
        Sign the apk
        """
        password = "".join(
            [random.choice("abcdefghijklmnopqrstuvwxyz") for _ in range(10)]
        )

        # create a key
        process = subprocess.run(
            f'keytool -genkey -v -keystore my-release-key.keystore -alias alias_name -keyalg RSA -keysize 2048 -validity 10000 -keypass {password} -storepass {password} -dname "CN=, OU=, O=, L=, S=, C="',
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        # sign the apk file
        process = subprocess.Popen(
            f"jarsigner -verbose -sigalg SHA1withRSA -digestalg SHA1 -keystore my-release-key.keystore {self.final_apk_path} alias_name",
            stdout=subprocess.PIPE,
            stdin=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=True,
        )
        process.communicate(f"{password}".encode())

        # remove the key
        os.remove("my-release-key.keystore")

    def get_jp_str(self) -> str:
        """
        Get the country code for the game version

        Returns:
            str: The country code
        """
        if self.is_jp:
            return "jp"
        return ""

    def make_dirs(self) -> None:
        """
        Make the directories for the output
        """
        helper.check_dir(self.output_path)
        helper.check_dir(self.extracted_path)
        helper.check_dir(self.packs_path)
        helper.check_dir(self.decrypted_path)

    def download(self) -> bool:
        """
        Download the apk from uptodown

        Returns:
            bool: True if the download was successful
        """
        if os.path.exists(self.apk_path):
            return True
        apk_urls = self.find_urls()
        if apk_urls is None:
            return False
        if self.game_version not in apk_urls:
            print(f"Version {self.game_version} not found")
            return False
        apk_link = self.find_link(apk_urls[self.game_version])
        if apk_link is None:
            print("Could not find apk link")
            return False
        helper.colored_text("Downloading apk...", helper.Color.GREEN)
        self.get_apk(apk_link)
        return True

    def get_apk(self, url: str) -> bool:
        """
        Download the apk from the url

        Args:
            url (str): The url to download the apk from

        Returns:
            bool: True if the download was successful
        """
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

        res = requests.get(url, stream=True, headers=headers)
        total_size = int(res.headers.get("content-length", 0))
        block_size = 1024
        wrote = 0
        with open(self.apk_path, "wb") as f:
            for data in res.iter_content(block_size):
                wrote += len(data)
                f.write(data)
                print("\rDownloaded: {}%".format(int(100 * wrote / total_size)), end="")
        print("\n")
        return True

    def find_link(self, apk_url: str) -> Optional[str]:
        """
        Find the link to the apk from the apk url

        Args:
            apk_url (str): The url to the apk page

        Returns:
            Optional[str]: The link to the apk
        """
        res = requests.get(apk_url)
        soup = bs4.BeautifulSoup(res.text, "html.parser")
        link = soup.find("a", {"class": "button download"})
        if not isinstance(link, bs4.element.Tag):
            return None
        return str(link.get("href"))

    def wipe(self) -> None:
        """
        Wipe the extracted folder
        """
        paths = [self.extracted_path, self.packs_path, self.decrypted_path]
        for path in paths:
            if os.path.exists(path):
                shutil.rmtree(path)

    def process_version(self, version: str) -> str:
        """
        Get the game version from the version string, and get the latest version if it is not specified

        Args:
            version (str): The version string

        Returns:
            str: The game version
        """
        if version.lower() == "latest":
            n_version = self.get_latest_version()
            if n_version is None:
                return ""
            version = n_version
        return version

    def get_latest_version(self) -> Optional[str]:
        """
        Get the latest version from the version page

        Returns:
            Optional[str]: The latest version
        """
        apk_urls = self.find_urls()
        if apk_urls is None:
            return None
        return list(apk_urls.keys())[0]

    def find_urls(self) -> Optional[dict[str, Any]]:
        """
        Find the urls for the game versions

        Returns:
            Optional[dict[str, Any]]: The urls for the game versions
        """
        app_id = self.get_app_id()
        url = f"https://{self.package_name}.en.uptodown.com/android/apps/{app_id}/versions?page[limit]=200&page[offset]=0"
        res = requests.get(url)
        json_data = res.json()["data"]
        versions: list[str] = []
        urls: list[str] = []
        for version in json_data:
            versions.append(version["version"])
            urls.append(version["versionURL"])
        return dict(zip(versions, urls))

    def get_app_id(self) -> Optional[str]:
        """
        Get the app id from the package name

        Returns:
            Optional[str]: The app id
        """
        url = f"https://{self.package_name}.en.uptodown.com/android/versions"
        res = requests.get(url)
        soup = bs4.BeautifulSoup(res.text, "html.parser")
        app_details = soup.find("h1", {"id": "detail-app-name"})
        if not isinstance(app_details, bs4.element.Tag):
            return None
        return app_details.attrs["code"]

    def copy_apk(self, path: str) -> None:
        """
        Copy the apk to the path

        Args:
            path (str): The path to copy the apk to
        """
        print(f"Copying apk file to {path}")
        shutil.copy(self.final_apk_path, path)
    
    def decrypt_pack(self, file_path: str) -> None:
        """
        Decrypt the pack file

        Args:
            file (str): The pack file to decrypt
        """
        helper.colored_text(f"Decrypting pack file &{os.path.basename(file_path)}&", helper.Color.WHITE, helper.Color.GREEN)
        helper.check_dir(file_path)
        helper.check_dir(os.path.join(self.decrypted_path, os.path.basename(file_path)))
        moddata = mod.Mod.load_from_pack(file_path, self.is_jp, "", "", "", 0, "")
        for decrypted_file in moddata.files:
            helper.write_file_bytes(os.path.join(self.decrypted_path, os.path.basename(file_path), decrypted_file), moddata.files[decrypted_file].data)

    def decrypt(self) -> None:
        """
        Decrypt the pack files in the extracted folder
        """        
        functions: list[Process] = []
        for file in os.listdir(os.path.join(self.packs_path)):
            if file.endswith(".pack"):
                file_path = os.path.abspath(os.path.join(self.packs_path, file))
                functions.append(Process(target=self.decrypt_pack, args=(file_path, )))
        helper.run_in_parallel(functions)
    
    @staticmethod
    def get_apk_folder() -> str:
        """
        Get the apk folder

        Returns:
            str: The apk folder
        """        
        folder = os.path.abspath(helper.get_config_value("apk_folder"))
        helper.check_dir(folder)
        return folder
