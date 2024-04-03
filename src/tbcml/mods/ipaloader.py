import tbcml
from typing import List, Optional, Union


class ModLoaderUninitializedException(Exception):
    pass


class IpaModLoader:
    """ModLoader class to handle loading the ipa and apply mods to the game

    Basic Usage:
        ```
        loader = IpaModLoader("en", "12.3.0")
        loader.initialize(r"path/to/ipa.ipa")

        ... # create mod here

        loader.apply(mod)
        ```
    """

    def __init__(
        self,
        country_code: "tbcml.CC",
        game_version: "tbcml.GV",
    ):
        """Initialize ModLoader

        Args:
            country_code: (str | tbcml.CountryCode), the country code of the ipa ("en", "jp", "kr", "tw")
            game_version: (str | tbcml.GameVersion), the game version of the ipa (e.g "12.3.0" or "latest")
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
        self.ipa: Optional[tbcml.Ipa] = None

    @staticmethod
    def from_ipa(
        ipa: "tbcml.Ipa",
    ):
        """Creates a ModLoader from an already existing Ipa object

        Args:
            ipa (tbcml.Ipa): Ipa object to create the ModLoader from

        Returns:
            IpaModLoader: ModLoader object
        """
        return IpaModLoader(ipa.country_code, ipa.game_version)

    def initialize(
        self,
        ipa_path: "tbcml.PathStr",
        force_extract: bool = False,
        print_errors: bool = True,
        custom_ipa_folder: Optional["tbcml.Path"] = None,
        lang: Optional["tbcml.LanguageStr"] = None,
    ):
        """Initializes the mod loader, loads ipa + game packs.
        Must be called before doing anything really.

        Args:
            ipa_path (tbcml.PathStr): Path to an ipa file. Note that you should probably change the custom_ipa_folder if using a non-original tbc ipa
            force_extract (bool, optional): Whether to always extract the ipa, even if it has already been extracted before.
            print_errors (bool, optional): Whether to show errors if they occur. Defaults to True.
            custom_ipa_folder (Optional[tbcml.Path], optional): If you want to specify where the ipa is downloaded / extracted to. Defaults to None which means leave as default (Documents/tbcml/ipas).
            lang (Optional["fr", "it", "de", "es", "th"], optional): If you are using an en ipa, change what language should be used. Defaults to None which is the country code
        """
        if isinstance(lang, str):
            lang = tbcml.Language(lang)

        self.__get_ipa(
            force_extract=force_extract,
            print_errors=print_errors,
            custom_ipa_folder=custom_ipa_folder,
            lang=lang,
            ipa_path=ipa_path,
        )

    def __get_ipa(
        self,
        ipa_path: "tbcml.PathStr",
        force_extract: bool = False,
        lang: Optional["tbcml.Language"] = None,
        print_errors: bool = True,
        custom_ipa_folder: Optional["tbcml.PathStr"] = None,
        display_server_download_progress: bool = False,
    ):
        if custom_ipa_folder is not None:
            custom_ipa_folder = tbcml.Path(custom_ipa_folder)

        ipa_path = tbcml.Path(ipa_path)
        self.ipa = tbcml.Ipa.from_ipa_path(
            ipa_path,
            cc_overwrite=self.country_code,
            gv_overwrite=self.game_version,
            ipa_folder=custom_ipa_folder,
        )
        if not self.ipa.extract(
            force=force_extract,
        ):
            if print_errors:
                print("Failed to extract ipa.")
            return
        try:
            self.ipa.download_server_files(
                lang=lang, display=display_server_download_progress
            )
        except tbcml.GameVersionSearchError:
            # old versions (<7.0) aren't supported for downloading game files atm + some really old versions don't have any
            if print_errors:
                print(
                    "Please use a newer version of the game to download server files."
                )

        self.game_packs = tbcml.GamePacks.from_pkg(self.ipa, lang=lang)

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
        raise_error: bool = True,
        save_in_modded_ipas: bool = False,
    ):
        """Applies a mod / mods to the ipa to create a modded ipa.

        Args:
            mods (Union[List[tbcml.Mod], tbcml.Mod]): Mod / mods to apply to the loaded ipa
            custom_enc_key (Optional[str], optional): Custom game pack encryption key. Defaults to None which is default key. Use if you want it to be harder to decrypt your game data. Does not apply to ImageDataLocal + makes applying mods take longer
            custom_enc_iv (Optional[str], optional): Custom game pack encryption iv, same use case / issues as key as shown above. Defaults to None.
            open_path (bool, optional): Whether to open the folder containing the final ipa after everything has been loaded. Defaults to False.
            add_modded_html (bool, optional): Whether to modify the transfer screen to display your current mods. Defaults to True.
            raise_error (bool): Whether to raise an error if applying mods fails. Defaults to True
            save_in_modded_ipas (bool, optional): Whether to save the modded ipa in the modded ipas folder. Defaults to False.

        Raises:
            ModLoaderUninitializedException: If the ipa has not been initialized (didn't call initialize())
        """
        if self.ipa is None:
            raise ModLoaderUninitializedException(
                "ipa not initialized. Call initialize() first."
            )
        if isinstance(mods, tbcml.Mod):
            mods = [mods]

        if not self.ipa.load_mods(
            mods=mods,
            game_packs=self.game_packs,
            key=custom_enc_key,
            iv=custom_enc_iv,
            add_modded_html=add_modded_html,
            save_in_modded_ipas=save_in_modded_ipas,
        ):
            if raise_error:
                raise ValueError("Failed to load mods.")

        if open_path:
            self.ipa.output_path.open()

    def get_ipa(self) -> "tbcml.Ipa":
        """Gets the ipa from a ModLoader instance. Will never be None

        Raises:
            ModLoaderUninitializedException: If the ipa has not been initialized (didn't call initialize())

        Returns:
            tbcml.ipa: ipa
        """
        if self.ipa is None:
            raise ModLoaderUninitializedException(
                "ipa not initialized. Call initialize() first."
            )
        return self.ipa

    def get_pkg(self) -> "tbcml.PKG":
        """Gets the pkg from a ModLoader instance. Will never be None

        Raises:
            ModLoaderUninitializedException: If the ipa has not been initialized (didn't call initialize())

        Returns:
            tbcml.pkg: pkg
        """
        return self.get_ipa()
