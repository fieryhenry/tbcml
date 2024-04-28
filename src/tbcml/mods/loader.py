from __future__ import annotations
from typing import Callable

import tbcml
from tbcml.io.apk import Apk


class ModLoaderUninitializedException(Exception):
    """Exception raised when the mod loader was not initialized."""


class ModLoaderWrongInitializationException(Exception):
    """Exception raised when the mod loader was initialized with the wrong method. E.g initialize_apk instead of initialize_ipa."""


class ModLoader:
    def __init__(
        self,
        country_code: tbcml.CC,
        game_version: tbcml.GV,
        raise_on_error: bool = True,
    ):
        """Initializes the ModLoader class.

        Args:
            country_code (tbcml.CC): The country code. Can be a string (en, jp, kr, tw) or a CountryCode object.
            game_version (tbcml.GV): The game version. Can be a string ("12.3.0") or a GameVersion object.
            raise_on_error (bool, optional): Whether to raise an exception when an error occurs instead of just returning a result. Defaults to True.
        """
        self.country_code = tbcml.CountryCode.from_cc(country_code)
        self.game_version = tbcml.GameVersion.from_gv(game_version)
        self.raise_on_error = raise_on_error

        self.game_packs: tbcml.GamePacks | None = None
        self.pkg: tbcml.Pkg | None = None
        self.adb_handler: tbcml.BulkAdbHandler | None = None

    @staticmethod
    def from_pkg(pkg: tbcml.Pkg) -> ModLoader:
        """Generates a ModLoader object from a Pkg object.
        Note that this does not initialize the ModLoader object.

        Args:
            pkg (tbcml.Pkg): The package object.

        Returns:
            ModLoader: The ModLoader object.
        """
        return ModLoader(pkg.country_code, pkg.game_version)

    def get_game_packs(self) -> tbcml.GamePacks:
        """Gets the game packs object.

        Raises:
            ModLoaderUninitializedException: If the game packs object is None.

        Returns:
            tbcml.GamePacks: The game packs object.
        """
        if self.game_packs is None:
            raise ModLoaderUninitializedException(
                "self.game_packs is None. Please initialize the mod loader first!"
            )
        return self.game_packs

    def get_apk(self) -> tbcml.Apk:
        """Gets the Apk object.

        Raises:
            ModLoaderWrongInitializationException: If the package object is not of type Apk.

        Returns:
            tbcml.Apk: The Apk object.
        """
        pkg = self.get_pkg()
        if not isinstance(pkg, tbcml.Apk):
            raise ModLoaderWrongInitializationException(
                "self.pkg is not of type Apk! Make sure you called the correct initialize function"
            )
        return pkg

    def get_ipa(self) -> tbcml.Ipa:
        """Gets the Ipa object.

        Raises:
            ModLoaderWrongInitializationException: If the package object is not of type Ipa.

        Returns:
            tbcml.Ipa: The Ipa object.
        """
        pkg = self.get_pkg()
        if not isinstance(pkg, tbcml.Ipa):
            raise ModLoaderWrongInitializationException(
                "self.pkg is not of type Ipa! Make sure you called the correct initialize function"
            )
        return pkg

    def get_pkg(self) -> tbcml.Pkg:
        """Gets the package object.

        Raises:
            ModLoaderUninitializedException: If the package object is None.

        Returns:
            tbcml.Pkg: The package object.
        """
        if self.pkg is None:
            raise ModLoaderUninitializedException(
                "self.pkg is None. Please initialize the mod loader first!"
            )
        return self.pkg

    def __initialize(self, lang: tbcml.Language | None) -> tbcml.Result:
        """Initializes the game packs object.

        Args:
            lang (tbcml.Language | None): The language of the game packs.

        Raises:
            ModLoaderUninitializedException: If the package object is None.

        Returns:
            tbcml.Result: The result object.
        """
        if self.pkg is None:
            res = tbcml.Result(
                False,
                error="Package must not be None. Call initialize_apk or initialize_ipa first!",
            )
            if self.raise_on_error:
                raise ModLoaderUninitializedException(res.error)
            return res

        self.game_packs = self.pkg.get_game_packs(lang=lang)
        return tbcml.Result(True)

    def initialize_apk(
        self,
        *,
        apk: tbcml.Apk | None = None,
        lang: tbcml.LanguageStr | None = None,
        apk_folder: tbcml.PathStr | None = None,
        decode_resources: bool = True,
        use_apktool: bool = True,
        allowed_script_mods: bool = True,
        skip_signature_check: bool = False,
        download_server_files: bool = True,
        force_download: bool = False,
        force_download_server_files: bool = False,
        force_extract: bool = False,
        download_progress: (
            Callable[[float, int, int, bool], None] | None
        ) = Apk.progress,
    ) -> tbcml.Result:
        """Initializes the ModLoader object with an Apk object.

        Args:
            apk (tbcml.Apk | None, optional): The Apk object. Defaults to None. If None, a new Apk object will be created.
            lang (tbcml.LanguageStr | None, optional): The language of the game packs if using an en apk (e.g fr, de, it, th, es). Defaults to None.
            apk_folder (tbcml.PathStr | None, optional): The folder where the apk should be located. Defaults to None. If None, the default folder will be used.
            decode_resources (bool, optional): Whether to decode the apk's resources. Defaults to True. If False, you will not be able to set certain things such as package name, app name or other strings.
            use_apktool (bool, optional): Whether to use apktool to extract/decode the apk. Defaults to True. If False, the apk will be extracted by simply unzipping it. This does not decode the resources. Use this if apktool is not working for you.
            allowed_script_mods (bool, optional): Whether to allow script mods. Defaults to True.
            skip_signature_check (bool, optional): Whether to skip the apk signature check to check that the downloaded apk is an official ponos apk. Defaults to False.
            download_server_files (bool, optional): Whether to download the server files. Defaults to True.
            force_download (bool, optional): Whether to force download the apk even if it exists. Defaults to False.
            force_download_server_files (bool, optional): Whether to force download the server files even if they exist. Defaults to False.
            force_extract (bool, optional): Whether to force extract the apk even if it is already extracted. Defaults to False.
            download_progress (Callable[[float, int, int, bool], None]  |  None, optional): The download progress callback function when downloading the apk. Defaults to Apk.progress.

        Raises:
            RuntimeError: If an error occurs when downloading the apk.
            RuntimeError: If an error occurs when extracting the apk.
            RuntimeError: If an error occurs when downloading the server files.

        Returns:
            tbcml.Result: The result object.
        """
        if lang is not None:
            lang = tbcml.Language.from_langstr(lang)

        if apk is None:
            apk = tbcml.Apk(
                self.game_version,
                self.country_code,
                apk_folder,
                allowed_script_mods=allowed_script_mods,
            )

        if not (
            res := apk.download(download_progress, force_download, skip_signature_check)
        ):
            if self.raise_on_error:
                raise RuntimeError(res.error)
            return res

        if not (
            res := apk.extract(
                force=force_extract,
                decode_resources=decode_resources,
                use_apktool=use_apktool,
            )
        ):
            if self.raise_on_error:
                raise RuntimeError(res.error)
            return res

        if download_server_files:
            if not (
                res := apk.download_server_files(
                    lang=lang,
                    force=force_download_server_files,
                    display=download_progress is not None,
                )
            ):
                if self.raise_on_error:
                    raise RuntimeError(res.error)
                return res

        self.pkg = apk

        return self.__initialize(lang=lang)

    def initialize_ipa(
        self,
        *,
        ipa: tbcml.Ipa | tbcml.PathStr,
        lang: tbcml.LanguageStr | None = None,
        ipa_folder: tbcml.PathStr | None = None,
        allowed_script_mods: bool = True,
        download_server_files: bool = True,
        force_download_server_files: bool = False,
        force_extract: bool = False,
        display_server_download_progress: bool = False,
    ) -> tbcml.Result:
        """Initializes the ModLoader object with an Ipa object.

        Args:
            ipa (tbcml.Ipa | tbcml.PathStr): The Ipa object or the path to the ipa file.
            lang (tbcml.LanguageStr | None, optional): The language of the game packs if using an en ipa (e.g fr, de, it, th, es). Defaults to None.
            ipa_folder (tbcml.PathStr | None, optional): The folder where the ipa should be located. Defaults to None. If None, the default folder will be used.
            allowed_script_mods (bool, optional): Whether to allow script mods. Defaults to True.
            download_server_files (bool, optional): Whether to download the server files. Defaults to True.
            force_download_server_files (bool, optional): Whether to force download the server files even if they exist. Defaults to False.
            force_extract (bool, optional): Whether to force extract the ipa even if it is already extracted. Defaults to False.
            display_server_download_progress (bool, optional): Whether to display the download progress when downloading the server files. Defaults to False.

        Raises:
            RuntimeError: If an error occurs when loading the ipa from a path.
            RuntimeError: If the ipa fails to load from the path.
            RuntimeError: If an error occurs when extracting the ipa.
            RuntimeError: If an error occurs when downloading the server files.

        Returns:
            tbcml.Result: _description_
        """
        if lang is not None:
            lang = tbcml.Language.from_langstr(lang)

        if not isinstance(ipa, tbcml.Ipa):
            ipa_o, res = tbcml.to_ipa(
                ipa,
                cc_overwrite=self.country_code,
                gv_overwrite=self.game_version,
                pkg_folder=ipa_folder,
                allowed_script_mods=allowed_script_mods,
            )
            if not res:
                if self.raise_on_error:
                    raise RuntimeError(res.error)
                return res
            if ipa_o is None:
                res = tbcml.Result(
                    False, error=f"Falied to initialize ipa from path: {ipa}"
                )
                if self.raise_on_error:
                    raise RuntimeError(res.error)
                return res
        else:
            ipa_o = ipa

        if not (res := ipa_o.extract(force=force_extract)):
            if self.raise_on_error:
                raise RuntimeError(res.error)
            return res

        if download_server_files:
            if not (
                res := ipa_o.download_server_files(
                    lang=lang,
                    force=force_download_server_files,
                    display=display_server_download_progress,
                )
            ):
                if self.raise_on_error:
                    raise RuntimeError(res.error)
                return res

        self.pkg = ipa_o
        return self.__initialize(lang)

    def apply(
        self,
        mods: list[tbcml.Mod] | tbcml.Mod | None = None,
        *,
        custom_enc_key: str | None = None,
        custom_enc_iv: str | None = None,
        open_pkg_path: bool = False,
        save_as_modded_pkg: bool = False,
        add_modded_html: bool = True,
        progress_callback: (
            Callable[[tbcml.PKGProgressSignal], bool | None] | None
        ) = None,
        do_final_pkg_actions: bool = True,
        use_apktool: bool | None = None,
    ) -> tbcml.Result:
        """Applies the mods to the package.

        Args:
            mods (list[tbcml.Mod] | tbcml.Mod | None): The mods to apply. Defaults to None.
            custom_enc_key (str | None, optional): Custom encryption key. Defaults to None. If None, the default encryption key will be used.
            custom_enc_iv (str | None, optional): Custom encryption iv. Defaults to None. If None, the default encryption iv will be used.
            open_pkg_path (bool, optional): Whether to open the package path in a file explorer after finishing. Defaults to False.
            save_as_modded_pkg (bool, optional): Whether to save the package in the modded package location. Defaults to False.
            add_modded_html (bool, optional): Whether to add the modded html to the package. Defaults to True.
            progress_callback (Callable[[tbcml.PKGProgressSignal], bool  |  None]  |  None, optional): The progress callback function. Defaults to None.
            do_final_pkg_actions (bool, optional): Whether to do the final package actions. Defaults to True
            use_apktool (bool | None, optional): Whether to use apktool to build the package. Defaults to None. If None, the value used in the initialize_apk function will be used.

        Raises:
            RuntimeError: If an error occurs when loading the mods.

        Returns:
            tbcml.Result: The result object.
        """
        if mods is None:
            mods = []
        if isinstance(mods, tbcml.Mod):
            mods = [mods]

        pkg = self.get_pkg()

        if isinstance(pkg, tbcml.Apk):
            res = pkg.load_mods(
                mods,
                self.game_packs,
                key=custom_enc_key,
                iv=custom_enc_iv,
                add_modded_html=add_modded_html,
                save_in_modded_pkgs=save_as_modded_pkg,
                progress_callback=progress_callback,
                do_final_pkg_actions=do_final_pkg_actions,
                use_apktool=use_apktool,
            )
        else:
            res = pkg.load_mods(
                mods,
                self.game_packs,
                key=custom_enc_key,
                iv=custom_enc_iv,
                add_modded_html=add_modded_html,
                save_in_modded_pkgs=save_as_modded_pkg,
                progress_callback=progress_callback,
                do_final_pkg_actions=do_final_pkg_actions,
            )
        if not res:
            if self.raise_on_error:
                raise RuntimeError(res.error)
            return res

        if open_pkg_path:
            pkg.output_path.open()

        return tbcml.Result(True)

    def initialize_adb(self, device_id: str | None = None):
        """Initializes the ADB handler.

        Args:
            device_id (str | None, optional): The device id. Defaults to None. If None, all connected devices will be added.

        Raises:
            Exception: If no devices are connected.
        """
        self.adb_handler = tbcml.BulkAdbHandler(
            self.get_apk().get_package_name()
            or self.get_apk().get_default_package_name()
        )
        if device_id is not None:
            self.adb_handler.add_device(device_id)
        else:
            success = self.adb_handler.add_all_connected_devices()
            if not success:
                raise Exception("No devices connected.")

    def get_adb_handler(self) -> tbcml.BulkAdbHandler:
        """Gets the ADB handler.

        Raises:
            ModLoaderUninitializedException: If the ADB handler is None.

        Returns:
            tbcml.BulkAdbHandler: The ADB handler.
        """
        if self.adb_handler is None:
            raise ModLoaderUninitializedException(
                "ADB handler not initialized. Call initialize_adb() first."
            )
        return self.adb_handler

    def install_adb(self, run_game: bool = False) -> list[list[tbcml.CommandResult]]:
        """Installs the apk on the device.

        Args:
            run_game (bool, optional): Whether to run the game after installing the apk. Defaults to False.

        Returns:
            list[list[tbcml.CommandResult]]: The results of the installation and running of the game.
        """
        results = self.get_adb_handler().run_adb_handler_function(
            tbcml.AdbHandler.install_apk, self.get_apk().final_pkg_path
        )

        if run_game:
            return [results, self.run_game_adb()]
        return [results]

    def copy_to_android_download_folder(self):
        """Copies the apk to the android download folder."""
        self.get_apk().copy_to_android_download_folder()

    def run_game_adb(self) -> list[tbcml.CommandResult]:
        """Runs the game on the device.

        Returns:
            list[tbcml.CommandResult]: The results of running the game.
        """
        return self.get_adb_handler().run_adb_handler_function(
            tbcml.AdbHandler.run_game
        )

    def close_game_adb(self) -> list[tbcml.CommandResult]:
        """Closes the game on the device.

        Returns:
            list[tbcml.CommandResult]: The results of closing the game.
        """
        return self.get_adb_handler().run_adb_handler_function(
            tbcml.AdbHandler.close_game
        )

    def push_server_files_adb(self) -> list[list[tbcml.CommandResult]]:
        """Pushes the server files to the device.
        Note that this should only be used after you have started the game at least once and have started to download the server files.
        If you do it too early, the game may think that the device has no free space and will stop you from saving your save data.

        Returns:
            list[list[tbcml.CommandResult]]: The results of pushing the server files.
        """
        apk = self.get_apk()
        game_packs = self.get_game_packs()
        paths: list[tbcml.Path] = []
        for pack_name, pack in game_packs.packs.items():
            if pack.is_server_pack(pack_name):
                paths.append(apk.get_server_path().add(pack_name + ".pack"))
                paths.append(apk.get_server_path().add(pack_name + ".list"))

        for file in apk.get_all_server_audio().values():
            paths.append(file)

        return self.get_adb_handler().run_adb_handler_function(
            tbcml.AdbHandler.push_files_to_folder,
            paths,
            tbcml.AdbHandler.get_battlecats_path(
                apk.get_package_name() or apk.get_default_package_name()
            ).add("files"),
        )
