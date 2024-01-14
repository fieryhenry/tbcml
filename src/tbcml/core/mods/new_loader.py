from tbcml import core
from typing import Callable, List, Optional, Union

from tbcml.core.io.apk import Apk


class NewModLoader:
    """
    The ModLoader class is responsible for loading and managing mods in the game.

    Args:
        country_code (str | CountryCode): The country code for the game.
        game_version (str | GameVersion): The version of the game.
        mod_instance (Mod): An instance of the Mod class.

    Attributes:
        country_code (CountryCode): The country code for the game.
        game_version (GameVersion): The version of the game.
        mod (Mod): An instance of the Mod class.
        game_packs (GamePacks): The game packs loaded from the APK.
        apk (Apk): The APK file used for loading mods.
        mods (List[Mod]): A list of mods.

    Methods:
        initialize(): Initializes the ModLoader by getting the APK file.
        add_cat(cat: Cat): Adds a cat to the mod.
        add_shop(shop: ItemShop): Adds an item shop to the mod.
        add_item(localizable: Localizable): Adds a localizable item to the mod.
        compile(open_path: bool): Compiles the APK with the loaded mods.

    """

    def __init__(
        self,
        country_code: Union[str, "core.CountryCode"],
        game_version: Union[str, "core.GameVersion"],
    ):
        if isinstance(country_code, str):
            self.country_code = core.CountryCode.from_code(country_code)
        else:
            self.country_code = country_code

        if isinstance(game_version, str):
            self.game_version = core.GameVersion.from_string_latest(
                game_version, self.country_code
            )
        else:
            self.game_version = game_version

        # not initialized in constructor
        self.game_packs: Optional[core.GamePacks] = None
        self.apk: Optional[core.Apk] = None
        self.adb_handler: Optional[core.BulkAdbHandler] = None

    def initialize(
        self,
        decode_resources: bool = True,
        print_errors: bool = True,
        allowed_script_mods: bool = True,
        custom_apk_folder: Optional["core.Path"] = None,
    ):
        self.__get_apk(
            decode_resources=decode_resources,
            print_errors=print_errors,
            allowed_script_mods=allowed_script_mods,
            custom_apk_folder=custom_apk_folder,
        )

    def __get_apk(
        self,
        decode_resources: bool = True,
        print_errors: bool = True,
        allowed_script_mods: bool = True,
        custom_apk_folder: Optional["core.Path"] = None,
        download_progress: Optional[
            Callable[[float, int, int, bool], None]
        ] = Apk.progress,
    ):
        self.apk = core.Apk(
            game_version=self.game_version,
            country_code=self.country_code,
            allowed_script_mods=allowed_script_mods,
            apk_folder=custom_apk_folder,
        )
        self.apk.download(download_progress)
        self.apk.extract(decode_resources=decode_resources)
        # older versions don't have server files
        try:
            self.apk.download_server_files()
        except core.GameVersionSearchError:
            if print_errors:
                print(
                    "Please use a newer version of the game to download server files."
                )

        self.game_packs = core.GamePacks.from_apk(self.apk)

    def get_game_packs(self) -> "core.GamePacks":
        if self.game_packs is None:
            raise Exception("Game packs not initialized. Call initialize() first.")
        return self.game_packs

    def apply(
        self,
        mods: Union[List["core.NewMod"], "core.NewMod"],
        custom_enc_key: Optional[str] = None,
        custom_enc_iv: Optional[str] = None,
        open_path: bool = False,
        add_modded_html: bool = True,
    ):
        if self.apk is None:
            raise Exception("APK not initialized. Call initialize() first.")
        if isinstance(mods, core.NewMod):
            mods = [mods]

        self.apk.load_mods_new(
            mods,
            self.game_packs,
            custom_enc_key,
            custom_enc_iv,
            add_modded_html=add_modded_html,
        )

        if open_path:
            self.apk.output_path.open()

    def get_apk(self) -> "core.Apk":
        if self.apk is None:
            raise Exception("APK not initialized. Call initialize() first.")
        return self.apk

    def initialize_adb(self, device_id: Optional[str] = None):
        self.adb_handler = core.BulkAdbHandler(self.get_apk().package_name)
        if device_id is not None:
            self.adb_handler.add_device(device_id)
        else:
            success = self.adb_handler.add_all_connected_devices()
            if not success:
                raise Exception("No devices connected.")

    def install_adb(self, run_game: bool = False) -> list[list["core.CommandResult"]]:
        results = self.get_adb_handler().run_adb_handler_function(
            core.AdbHandler.install_apk, self.get_apk().get_final_apk_path()
        )

        if run_game:
            return [results, self.run_game_adb()]
        return [results]

    def get_adb_handler(self) -> "core.BulkAdbHandler":
        if self.adb_handler is None:
            raise Exception("ADB handler not initialized. Call initialize_adb() first.")
        return self.adb_handler

    def run_game_adb(self) -> list["core.CommandResult"]:
        return self.get_adb_handler().run_adb_handler_function(core.AdbHandler.run_game)

    def close_game_adb(self) -> list["core.CommandResult"]:
        return self.get_adb_handler().run_adb_handler_function(
            core.AdbHandler.close_game
        )

    def push_server_files_adb(self) -> list[list["core.CommandResult"]]:
        apk = self.get_apk()
        return self.get_adb_handler().run_adb_handler_function(
            core.AdbHandler.push_files_to_folder,
            apk.get_server_path(apk.country_code, apk.apk_folder).get_files(),
            core.AdbHandler.get_battlecats_path(apk.package_name).add("files"),
        )
