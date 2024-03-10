import tbcml
from typing import Callable, List, Optional, Union

from tbcml.io.apk import Apk


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

    def __init__(
        self,
        country_code: "tbcml.CC",
        game_version: "tbcml.GV",
    ):
        """Initialize ModLoader

        Args:
            country_code: (str | tbcml.CountryCode), the country code of the apk ("en", "jp", "kr", "tw")
            game_version: (str | tbcml.GameVersion), the game version of the apk (e.g "12.3.0" or "latest")
        """

        if isinstance(country_code, str):
            self.country_code = tbcml.CountryCode.from_code(country_code)
        else:
            self.country_code = country_code

        if isinstance(game_version, str):
            self.game_version = tbcml.GameVersion.from_string_latest(
                game_version, self.country_code
            )
        else:
            self.game_version = game_version

        self.game_packs: Optional[tbcml.GamePacks] = None
        self.apk: Optional[tbcml.Apk] = None
        self.adb_handler: Optional[tbcml.BulkAdbHandler] = None

    def initialize(
        self,
        decode_resources: bool = True,
        use_apktool: bool = True,
        force_extract: bool = False,
        print_errors: bool = True,
        allowed_script_mods: bool = True,
        custom_apk_folder: Optional["tbcml.Path"] = None,
        lang: Optional["tbcml.LanguageStr"] = None,
        apk_path: Optional["tbcml.PathStr"] = None,
        download_progress: Optional[
            Callable[[float, int, int, bool], None]
        ] = Apk.progress,
        skip_signature_check: bool = False,
    ):
        """Initializes the mod loader, loads apk + game packs.
        Must be called before doing anything really.

        Args:
            decode_resources (bool, optional): Whether to decode encoded apk resources such as resources.arsc or AndroidManifest.xml. Defaults to True. Should be disabled if apktool fails to pack the apk. Will be disabled if use_apktool is False
            use_apktool (bool, optional): Whether to use apktool to extract the apk, disable if apktool isn't supported for your device. If disabled, resources cannot be decoded atm.
            force_extract (bool, optional): Whether to always extract the apk, even if it has already been extracted before.
            print_errors (bool, optional): Whether to show errors if they occur. Defaults to True.
            allowed_script_mods (bool, optional): If custom scripts / code is able to be loaded into the apk. Defaults to True.
            custom_apk_folder (Optional[tbcml.Path], optional): If you want to specify where the apk is downloaded / extracted to. Defaults to None which means leave as default (Documents/tbcml/APKs).
            lang (Optional["fr", "it", "de", "es", "th"], optional): If you are using an en apk, change what language should be used. Defaults to None which is the country code
            apk_path (Optional[tbcml.Path], optional): Path to an apk file if you already have a downloaded apk file. Note that you should probably change the custom_apk_folder if using a non-original tbc apk
            download_progress (Optional[Callable[[float, int, int, bool], None]], optional): Function to call to show download progress. Defaults to Apk.progress which is a default progress function
            skip_signature_check (bool, optional): Whether to skip checking the apk signature. If disabled, this will throw an error if the downloaded apk is not original. Defaults to False
        """
        if isinstance(lang, str):
            lang = tbcml.Language(lang)

        self.__get_apk(
            decode_resources=decode_resources,
            use_apktool=use_apktool,
            force_extract=force_extract,
            print_errors=print_errors,
            allowed_script_mods=allowed_script_mods,
            custom_apk_folder=custom_apk_folder,
            lang=lang,
            apk_path=apk_path,
            download_progress=download_progress,
            skip_signature_check=skip_signature_check,
        )

    def __get_apk(
        self,
        decode_resources: bool = True,
        use_apktool: bool = True,
        force_extract: bool = False,
        lang: Optional["tbcml.Language"] = None,
        print_errors: bool = True,
        allowed_script_mods: bool = True,
        custom_apk_folder: Optional["tbcml.PathStr"] = None,
        download_progress: Optional[
            Callable[[float, int, int, bool], None]
        ] = Apk.progress,
        apk_path: Optional["tbcml.PathStr"] = None,
        skip_signature_check: bool = False,
    ):
        if custom_apk_folder is not None:
            custom_apk_folder = tbcml.Path(custom_apk_folder)

        if apk_path is not None:
            apk_path = tbcml.Path(apk_path)
            self.apk = tbcml.Apk.from_apk_path(
                apk_path,
                cc_overwrite=self.country_code,
                gv_overwrite=self.game_version,
                apk_folder=custom_apk_folder,
                allowed_script_mods=allowed_script_mods,
                skip_signature_check=skip_signature_check,
            )
        else:
            self.apk = tbcml.Apk(
                game_version=self.game_version,
                country_code=self.country_code,
                allowed_script_mods=allowed_script_mods,
                apk_folder=custom_apk_folder,
            )
            if not self.apk.download(
                download_progress, skip_signature_check=skip_signature_check
            ):
                if print_errors:
                    print("Failed to download apk.")
                return
        if not self.apk.extract(
            decode_resources=decode_resources,
            use_apktool=use_apktool,
            force=force_extract,
        ):
            if print_errors:
                print("Failed to extract apk.")
            return
        try:
            self.apk.download_server_files(lang=lang, display=bool(download_progress))
        except tbcml.GameVersionSearchError:
            # old versions (<7.0) aren't supported for downloading game files atm + some really old versions don't have any
            if print_errors:
                print(
                    "Please use a newer version of the game to download server files."
                )

        self.game_packs = tbcml.GamePacks.from_pkg(self.apk, lang=lang)

    def get_game_packs(self) -> "tbcml.GamePacks":
        """Gets the game packs from a ModLoader instance, will never be None, unlike .game_packs attribute

        Raises:
            ModLoaderUninitializedException: If initialize() hasn't been called and game packs are None

        Returns:
            tbcml.GamePacks: The game packs (files which store the game data e.g stats, anims, strings, etc)
        """
        if self.game_packs is None:
            raise ModLoaderUninitializedException(
                "Game packs not initialized. Call initialize() first."
            )
        return self.game_packs

    def apply(
        self,
        mods: Union[List["tbcml.Mod"], "tbcml.Mod"],
        custom_enc_key: Optional[str] = None,
        custom_enc_iv: Optional[str] = None,
        open_path: bool = False,
        add_modded_html: bool = True,
        use_apktool: Optional[bool] = None,
        raise_error: bool = True,
        save_in_modded_apks: bool = False,
    ):
        """Applies a mod / mods to the apk to create a modded apk.

        Args:
            mods (Union[List[tbcml.Mod], tbcml.Mod]): Mod / mods to apply to the loaded apk
            custom_enc_key (Optional[str], optional): Custom game pack encryption key. Defaults to None which is default key. Use if you want it to be harder to decrypt your game data. Does not apply to ImageDataLocal + makes applying mods take longer
            custom_enc_iv (Optional[str], optional): Custom game pack encryption iv, same use case / issues as key as shown above. Defaults to None.
            open_path (bool, optional): Whether to open the folder containing the final apk after everything has been loaded. Defaults to False.
            add_modded_html (bool, optional): Whether to modify the transfer screen to display your current mods. Defaults to True.
            use_apktool (Optional[bool], optional): Whether to use apktool to pack the apk, if False resources will not be encoded. If None, it will autodetect the value based on what you did when you extracted the apk
            raise_error (bool): Whether to raise an error if applying mods fails. Defaults to True
            save_in_modded_apks (bool): Whether to save the modded apk to a separate folder. Defaults to False

        Raises:
            ModLoaderUninitializedException: If the apk has not been initialized (didn't call initialize())
        """
        if self.apk is None:
            raise ModLoaderUninitializedException(
                "APK not initialized. Call initialize() first."
            )
        if isinstance(mods, tbcml.Mod):
            mods = [mods]

        if not self.apk.load_mods(
            mods=mods,
            game_packs=self.game_packs,
            key=custom_enc_key,
            iv=custom_enc_iv,
            add_modded_html=add_modded_html,
            use_apktool=use_apktool,
            save_in_modded_apks=save_in_modded_apks,
        ):
            if raise_error:
                raise ValueError("Failed to load mods.")

        if open_path:
            self.apk.output_path.open()

    def get_apk(self) -> "tbcml.Apk":
        """Gets the apk from a ModLoader instance. Will never be None

        Raises:
            ModLoaderUninitializedException: If the apk has not been initialized (didn't call initialize())

        Returns:
            tbcml.Apk: Apk
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
        self.adb_handler = tbcml.BulkAdbHandler(self.get_apk().get_package_name())
        if device_id is not None:
            self.adb_handler.add_device(device_id)
        else:
            success = self.adb_handler.add_all_connected_devices()
            if not success:
                raise Exception("No devices connected.")

    def install_adb(
        self, run_game: bool = False
    ) -> tuple[list["tbcml.CommandResult"], Optional[list["tbcml.CommandResult"]]]:
        """Install the apk to connected devices

        Args:
            run_game: (bool). Whether to run the game after installing. Defaults to False.

        Returns:
            tuple[list["tbcml.CommandResult"], list["tbcml.CommandResult"]]: Results of the commands, first element is list of install results, second element (if present) is list of run game results
        """
        results = self.get_adb_handler().run_adb_handler_function(
            tbcml.AdbHandler.install_apk, self.get_apk().get_final_apk_path()
        )

        if run_game:
            return (results, self.run_game_adb())
        return (results, None)

    def copy_to_android_download_folder(self):
        """Copies the final apk to the /sdard/Download directory for easier installation"""
        self.get_apk().copy_to_android_download_folder()

    def get_adb_handler(self) -> "tbcml.BulkAdbHandler":
        """Gets the apk handler. Will never be None

        Raises:
            ModLoaderUninitializedException: If you haven't initialized adb (adb_handler is None)

        Returns:
            tbcml.BulkAdbHandler: Adb handler
        """
        if self.adb_handler is None:
            raise ModLoaderUninitializedException(
                "ADB handler not initialized. Call initialize_adb() first."
            )
        return self.adb_handler

    def run_game_adb(self) -> list["tbcml.CommandResult"]:
        """Run the game with adb

        Returns:
            list[tbcml.CommandResult]: List of command results
        """
        return self.get_adb_handler().run_adb_handler_function(
            tbcml.AdbHandler.run_game
        )

    def close_game_adb(self) -> list["tbcml.CommandResult"]:
        """Close the game with adb

        Returns:
            list[tbcml.CommandResult]: List of command results
        """
        return self.get_adb_handler().run_adb_handler_function(
            tbcml.AdbHandler.close_game
        )

    def push_server_files_adb(self) -> list[list["tbcml.CommandResult"]]:
        """Pushes the downloaded server files to the game.
        WARNING: this should only be run after you have selected a language,
        otherwise the game may glitch and think there is no storage space and so
        will brick your game.

        Returns:
            list[list[tbcml.CommandResult]]: List of command results for each device and file.
        """
        apk = self.get_apk()
        return self.get_adb_handler().run_adb_handler_function(
            tbcml.AdbHandler.push_files_to_folder,
            apk.get_server_path().get_files(),
            tbcml.AdbHandler.get_battlecats_path(
                apk.get_package_name() or apk.get_default_package_name()
            ).add("files"),
        )
