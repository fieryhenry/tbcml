from tbcml import core
from typing import Callable, List, Optional, Union

from tbcml.core.io.apk import Apk


class ModLoaderUninitializedException(Exception):
    pass


class ModLoader:
    """ModLoader class to handle loading the apk and apply mods to the game

    Basic Usage:
        ```
        loader = ModLoader("en", "12.3.0")
        loader.initialize()

        ... # create mod here

        loader.apply(mod)
        ```

    Methods:
        See individual functions for docs
        initialize(...) Initializes the apk and game packs. Must be called before doing anything really
        initialize_adb(...) Initializes adb handlers. Must be called before doing anything with adb
        get_apk(...) Gets the apk will never be None
        get_game_packs() Gets the game packs will never be None
        get_adb_handler(...) Gets the apk handler will never be None
        apply(...) Applies a mod / mods to the apk to create a modded apk.
        install_adb(...) Install the apk to connected devices
        run_game_adb() Run the game with adb
        close_game_adb() Close the game with adb
        push_server_files_adb() Pushes the downloaded server files to the game.

    """

    def __init__(self, country_code: "core.CC", game_version: "core.GV"):
        """Initialize ModLoader

        Args:
            country_code: (str | core.CountryCode), the country code of the apk ("en", "jp", "kr", "tw")
            game_version: (str | core.GameVersion), the game version of the apk (e.g "12.3.0" or "latest")
        """

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
        """Initializes the mod loader, loads apk + game packs.
        Must be called before doing anything really.

        Args:
            decode_resources (bool, optional): Whether to decode encoded apk resources such as resources.arsc or AndroidManifest.xml. Defaults to True. Should be disabled if apktool fails to pack the apk
            print_errors (bool, optional): Whether to show errors if they occur. Defaults to True.
            allowed_script_mods (bool, optional): If custom scripts / code is able to be loaded into the apk. Defaults to True.
            custom_apk_folder (Optional[core.Path], optional): If you want to specify where the apk is downloaded / extracted to. Defaults to None which means leave as default (Documents/tbcml/APKs).
        """
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
        try:
            self.apk.download_server_files()
        except core.GameVersionSearchError:
            # old versions (<7.0) aren't supported for downloading game files atm + some really old versions don't have any
            if print_errors:
                print(
                    "Please use a newer version of the game to download server files."
                )

        self.game_packs = core.GamePacks.from_apk(self.apk)

    def get_game_packs(self) -> "core.GamePacks":
        """Gets the game packs from a ModLoader instance, will never be None, unlike .game_packs attribute

        Raises:
            ModLoaderUninitializedException: If initialize() hasn't been called and game packs are None

        Returns:
            core.GamePacks: The game packs (files which store the game data e.g stats, anims, strings, etc)
        """
        if self.game_packs is None:
            raise ModLoaderUninitializedException(
                "Game packs not initialized. Call initialize() first."
            )
        return self.game_packs

    def apply(
        self,
        mods: Union[List["core.Mod"], "core.Mod"],
        custom_enc_key: Optional[str] = None,
        custom_enc_iv: Optional[str] = None,
        open_path: bool = False,
        add_modded_html: bool = True,
    ):
        """Applies a mod / mods to the apk to create a modded apk.

        Args:
            mods (Union[List[core.Mod], core.Mod]): Mod / mods to apply to the loaded apk
            custom_enc_key (Optional[str], optional): Custom game pack encryption key. Defaults to None which is default key. Use if you want it to be harder to decrypt your game data. Does not apply to ImageDataLocal + makes applying mods take longer
            custom_enc_iv (Optional[str], optional): Custom game pack encryption iv, same use case / issues as key as shown above. Defaults to None.
            open_path (bool, optional): Whether to open the folder containing the final apk after everything has been loaded. Defaults to False.
            add_modded_html (bool, optional): Whether to modify the transfer screen to display your current mods. Defaults to True.

        Raises:
            ModLoaderUninitializedException: If the apk has not been initialized (didn't call initialize())
        """
        if self.apk is None:
            raise ModLoaderUninitializedException(
                "APK not initialized. Call initialize() first."
            )
        if isinstance(mods, core.Mod):
            mods = [mods]

        self.apk.load_mods(
            mods,
            self.game_packs,
            custom_enc_key,
            custom_enc_iv,
            add_modded_html=add_modded_html,
        )

        if open_path:
            self.apk.output_path.open()

    def get_apk(self) -> "core.Apk":
        """Gets the apk from a ModLoader instance. Will never be None

        Raises:
            ModLoaderUninitializedException: If the apk has not been initialized (didn't call initialize())

        Returns:
            core.Apk: Apk
        """
        if self.apk is None:
            raise ModLoaderUninitializedException(
                "APK not initialized. Call initialize() first."
            )
        return self.apk

    def initialize_adb(self, device_id: Optional[str] = None):
        """Initialize adb handler. Must be called before doing anything with adb

        Args:
            device_id (Optional[str], optional): Device id to use for running commands. Defaults to None which means all connected devices.

        Raises:
            Exception: If no devices are connected
        """
        self.adb_handler = core.BulkAdbHandler(self.get_apk().package_name)
        if device_id is not None:
            self.adb_handler.add_device(device_id)
        else:
            success = self.adb_handler.add_all_connected_devices()
            if not success:
                raise Exception("No devices connected.")

    def install_adb(self, run_game: bool = False) -> list[list["core.CommandResult"]]:
        """Install the apk to connected devices

        Args:
            run_game: (bool). Whether to run the game after installing. Defaults to False.

        Returns:
            list[list["core.CommandResult"]]: Results of the commands, first element is list of install results, second element (if present) is list of run game results
        """
        results = self.get_adb_handler().run_adb_handler_function(
            core.AdbHandler.install_apk, self.get_apk().get_final_apk_path()
        )

        if run_game:
            return [results, self.run_game_adb()]
        return [results]

    def get_adb_handler(self) -> "core.BulkAdbHandler":
        """Gets the apk handler. Will never be None

        Raises:
            ModLoaderUninitializedException: If you haven't initialized adb (adb_handler is None)

        Returns:
            core.BulkAdbHandler: Adb handler
        """
        if self.adb_handler is None:
            raise ModLoaderUninitializedException(
                "ADB handler not initialized. Call initialize_adb() first."
            )
        return self.adb_handler

    def run_game_adb(self) -> list["core.CommandResult"]:
        """Run the game with adb

        Returns:
            list[core.CommandResult]: List of command results
        """
        return self.get_adb_handler().run_adb_handler_function(core.AdbHandler.run_game)

    def close_game_adb(self) -> list["core.CommandResult"]:
        """Close the game with adb

        Returns:
            list[core.CommandResult]: List of command results
        """
        return self.get_adb_handler().run_adb_handler_function(
            core.AdbHandler.close_game
        )

    def push_server_files_adb(self) -> list[list["core.CommandResult"]]:
        """Pushes the downloaded server files to the game.
        WARNING: this should only be run after you have selected a language,
        otherwise the game may glitch and think there is no storage space and so
        will brick your game.

        Returns:
            list[list[core.CommandResult]]: List of command results for each device and file.
        """
        apk = self.get_apk()
        return self.get_adb_handler().run_adb_handler_function(
            core.AdbHandler.push_files_to_folder,
            apk.get_server_path(apk.country_code, apk.apk_folder).get_files(),
            core.AdbHandler.get_battlecats_path(apk.package_name).add("files"),
        )
