import dataclasses
import enum
import json
import uuid
from typing import Any, Optional, Sequence, Union

import tbcml
from marshmallow_dataclass import class_schema


class ModificationType(enum.Enum):
    CAT = "cat"
    ENEMY = "enemy"
    SHOP = "shop"
    LOCALIZABLE = "localizable"
    MAP = "map"
    SOUND_SETTING = "sound_setting"
    CHARA_GROUP = "chara_group"
    LOADING_SCREEN = "loading_screen"
    LOGO_SCREEN = "logo_screen"

    @staticmethod
    def from_str_value(string: str) -> Optional["ModificationType"]:
        for type in ModificationType:
            if type.value == string:
                return type
        return None

    @staticmethod
    def get_map() -> dict["ModificationType", type]:
        return {
            ModificationType.CAT: tbcml.Cat,
            ModificationType.ENEMY: tbcml.Enemy,
            ModificationType.SHOP: tbcml.ItemShop,
            ModificationType.LOCALIZABLE: tbcml.Localizable,
            ModificationType.MAP: tbcml.Map,
            ModificationType.SOUND_SETTING: tbcml.SoundSetting,
            ModificationType.CHARA_GROUP: tbcml.CharaGroup,
            ModificationType.LOADING_SCREEN: tbcml.LoadingScreen,
            ModificationType.LOGO_SCREEN: tbcml.LogoScreen,
        }

    @staticmethod
    def from_cls(ty: Any) -> "ModificationType":
        for type, cls in ModificationType.get_map().items():
            if isinstance(ty, cls):
                return type
        raise ValueError("Invalid class")

    def get_cls(self) -> type:
        cls = ModificationType.get_map().get(self)
        if cls is None:
            raise ValueError("Invalid modification type")
        return cls


class ModPath(enum.Enum):
    METADATA = "metadata.json"

    MODIFICATIONS = "modifications"

    SCRIPTS = "scripts"
    SMALI = "smali"
    LIB_PATCHES = "lib_patches"

    GAME_FILES = "game_files"
    AUDIO_FILES = "audio_files"

    COMPILATION_TARGETS = "compiled_game_files"

    PKG_ASSETS = "pkg_assets"
    PKG_STRINGS = "pkg_strings.json"
    ENC_PKG_ASSETS = "encrypted_pkg_assets"
    APK_FILES = "apk_files"
    IPA_FILES = "ipa_files"


class Modification:
    def to_json(self) -> str:
        self.pre_to_json()
        modification_type = ModificationType.from_cls(self)
        base_cls = modification_type.get_cls()
        schema = class_schema(clazz=base_cls)
        return schema().dumps(self)  # type: ignore

    def from_json(self, data: str, modification_type: ModificationType) -> Any:
        base_cls = modification_type.get_cls()
        schema = class_schema(clazz=base_cls)
        cls = schema().loads(data)  # type: ignore
        cls.post_from_json()  # type: ignore
        return cls  # type: ignore

    def merge(self, other: Any):
        """Merge this modification with another

        Note that the implimentation should prioritize itself over the other modification

        Args:
            other (Any): The other modification

        Raises:
            ValueError: If the type of other is not the same as self
        """
        if not isinstance(other, Modification):
            raise ValueError("Cannot merge modification with non modification")

        if self.modification_type != other.modification_type:
            raise ValueError("Cannot merge modifications of different types")

    @property
    def modification_type(self) -> ModificationType:
        return ModificationType.from_cls(self)

    def apply_game_data(self, game_data: "tbcml.GamePacks"): ...

    def apply_pkg(self, pkg: "tbcml.PKG", lang: Optional[str]): ...

    @staticmethod
    def apply_csv_fields(
        obj: Any,
        csv: "tbcml.CSV",
        required_values: Optional[Sequence[tuple[int, Union[str, int]]]] = None,
        remove_others: bool = True,
        field_offset: int = 0,
        length: Optional[int] = None,
    ):
        csv_name_len = len("_csv__")

        cleared_lines: dict[int, bool] = {}

        for name, value in obj.__dict__.items():
            if isinstance(value, tbcml.CSVField):
                value.col_index += field_offset
                new_name = name[csv_name_len:]
                new_value = getattr(obj, new_name)
                value.value = new_value

                if remove_others:
                    value.initialize_csv(csv, writing=True)
                    if not cleared_lines.get(csv.index):
                        cleared_lines[csv.index] = True
                        if csv.index >= len(csv.lines) or csv.lines[csv.index]:
                            csv.set_line([], csv.index)
                    value.uninitialize_csv(csv)

                if required_values:
                    value.initialize_csv(csv, writing=True)
                    original_len = 0
                    if csv.index < len(csv.lines):
                        original_len = len(csv.lines[csv.index])

                    for ind, val in required_values:
                        if ind < original_len:
                            continue
                        csv.set_str(val, ind, length)
                    value.uninitialize_csv(csv)

                value.write_to_csv(csv, length)
                value.col_index -= field_offset

    @staticmethod
    def read_csv_fields(
        obj: Any,
        csv: "tbcml.CSV",
        required_values: Optional[Sequence[tuple[int, Union[str, int]]]] = None,
        field_offset: int = 0,
    ):
        csv_str_len = len("_csv__")

        for name, value in obj.__dict__.items():
            if isinstance(value, tbcml.CSVField):
                value.col_index += field_offset
                if not required_values:
                    value.read_from_csv(csv)
                else:
                    for ind, val in required_values:
                        if ind == value.col_index:
                            value.read_from_csv(csv, default=val)
                            break
                    else:
                        value.read_from_csv(csv)

                value.col_index -= field_offset

                new_name = name[csv_str_len:]
                setattr(obj, new_name, value.value)  # type: ignore

    def pre_to_json(self) -> None: ...

    def post_from_json(self) -> None: ...

    def get_custom_html(self) -> str:
        return ""

    @staticmethod
    def sync(curr: Any, new: Any):
        if not dataclasses.is_dataclass(curr) or not dataclasses.is_dataclass(new):
            return
        for field in dataclasses.fields(curr):
            curr_value = getattr(curr, field.name)
            new_value = getattr(new, field.name)
            if curr_value is None:
                setattr(curr, field.name, new_value)
                continue
            if isinstance(curr_value, list) and not curr_value:
                setattr(curr, field.name, new_value)
                continue

            Modification.sync(curr_value, new_value)


class Mod:
    """Mod class to represent a mod

    Example usage:
        ```python
        mod = Mod(
            name="My Mod",
            authors="fieryhenry",
            short_description="My first mod"
        )

        mod.add_modification(tbcml.Cat(...))

        mod.save("mod.zip")
        ```

    Methods:
        `add_modification(...)`: Add a modification to the mod.
        `add_script(...)`: Add a frida script to the mod.
        `add_smali(...)`: Add some smali code to the mod.
        `add_pkg_asset(...)`: Add a file to be placed in the apk/ipa assets folder when applying the mod
        `add_encrypted_pkg_asset(...)`: Add an encrypted file to be placed in the apk/ipa assets folder when applying the mod
        `add_apk_file(...)`: Add a file to be placed in the apk when applying the mod.
        `add_ipa_file(...)`: Add a file to be placed in the ipa when applying the mod.
        `add_audio_file(...)`: Add an audio file to the mod.
        `add_game_file(...)`: Add a game file to the mod.
        `add_compilation_target(...)`: Add a compilation target to the mod.
        `add_lib_patch(...)`: Add a lib patch to the mod.
        `get_asset(...)`: Get an asset from the mod.
        `to_zip(...)`: Convert the mod to a zip file.
        `to_file(...)`: Save the mod to a file.
        `load(...)`: Load a mod from a file.
        `save(...)`: Save the mod to a file.
        `compile(...)`: Compile the mod to raw game files.
        `get_custom_html(...)`: Get the custom html for the mod.
        `apply_to_game_data(...)`: Apply the mod to the game data.
        `apply_to_pkg(...)`: Apply the mod to a package (apk/ipa).
        `remove_duplicate_modifications(...)`: Remove duplicate modifications from the mod.
        `merge_modifications(...)`: Merge modifications together in the mod.
        `is_author(...)`: Check if the mod has an author. Note that this is not a secure way to check for authors, as the authors can be easily changed
        `add_pkg_string(...)`: Add a string to be set in the apk/ipa when applying the mod.

    Fields:
        `name`: The name of the mod
        `authors`: The authors of the mod
        `short_description`: The short description of the mod. Should be relatively short.
        `long_description`: The description of the mod. Can be a longer string.
        `custom_html`: The custom html for the mod. This will be visible in the transfer menu mod list. If you do not provide a custom html, tbcml will create a basic page for you.
        `id`: The unique id of the mod
        `modifications`: The modifications to apply to the game data.
        `scripts`: The frida scripts to apply to the game. Is not supported for ipa files atm.
        `game_files`: The game files to apply to the game data.
        `pkg_assets`: The files to place in the assets of the apk/ipa when applying the mod.
        `encrypted_pkg_assets`: The encrypted files to place in the assets of the apk/ipa when applying the mod.
        `apk_files`: The files to place in the apk when applying the mod.
        `ipa_files`: The files to place in the ipa when applying the mod.
        `audio_files`: The audio files to add to the mod.
        `pkg_strings`: The strings to set in the apk/ipa when applying the mod.
        `smali`: The smali code to add to the mod. Is not supported for ipa files.
        `patches`: The lib patches to add to the mod. Is not supported for ipa files atm.
        `compilation_targets`: The compilation targets of the mod, which specify the game versions, country codes and languages that the compiled game files should be applied to (if they exist).
    """

    def __init__(
        self,
        name: str = "",
        authors: Union[str, list[str]] = "",
        short_description: str = "",
        long_description: str = "",
        custom_html: Optional[str] = None,
        mod_id: Optional[str] = None,
    ):
        """Initialize a mod

        Args:
            name (str, optional): The name of the mod, should be relatively short. Defaults to "".
            authors (Union[str, list[str]], optional): The authors of the mod, can either be a single string e.g `"fieryhenry"`, but can be a list of names e.g `["fieryhenry", "enderelijas"]`. Defaults to "".
            short_description (str, optional): Short Description of the mod, should be relatively short. Defaults to "".
            long_description (str, optional): Long Description of the mod, can be a longer string. Defaults to "".
            custom_html (Optional[str], optional): The HTML to load when the user clicks this mod in the transfer menu mod list. Defaults to None which means that tbcml will create a basic page for you.
            mod_id (Optional[str], optional): The unique id of the mod. Defaults to None.
        """
        self.name = name
        """str: The name of the mod"""
        if isinstance(authors, str):
            authors = [authors]
        self.authors = authors
        """list[str]: The authors of the mod"""

        self.short_description = short_description
        """str: The short description of the mod.
        Should be relatively short."""

        self.long_description = long_description
        """str: The description of the mod.
        Can be a longer string."""

        self.custom_html = custom_html
        """Optional[str]: The custom html for the mod. This will be visible in
        the transfer menu mod list. If you do not provide a custom html, tbcml
        will create a basic page for you."""

        if mod_id is None:
            mod_id = str(uuid.uuid4())

        self.id = mod_id
        """str: The unique id of the mod"""

        self.modifications: list[Modification] = []
        """list[Modification]: The modifications to apply to the game data.

        See tbcml.Modification for more information on modifications."""

        self.scripts: list[tbcml.FridaScript] = []
        """list[tbcml.FridaScript]: The frida scripts to apply to the game. Is
        not supported for ipa files atm.

        See tbcml.FridaScript for more information on frida scripts."""

        self.game_files: dict[str, tbcml.Data] = {}
        """dict[str, tbcml.Data]: The game files to apply to the game data. str
        is the file name, tbcml.Data is the file data."""

        self.pkg_assets: dict[str, tbcml.Data] = {}
        """dict[str, tbcml.Data]: The files to place in the assets of
        the apk/ipa when applying the mod. str is the location in the
        asset to place the file, tbcml.Data is the actual file / data to place
        in that location. If you want to modify specifically ipa or apk files
        use apk_files and ipa_files instead."""

        self.encrypted_pkg_assets: dict[str, tbcml.Data] = {}
        """dict[str, tbcml.Data]: The encrypted files to place in the assets of
        the apk/ipa when applying the mod. str is the location in the asset to
        place the file, tbcml.Data is the un-encrypted file / data that will be
        encrypted and then placed location."""

        self.apk_files: dict[str, tbcml.Data] = {}
        """dict[str, tbcml.Data]: The files to place in the apk when
        applying the mod. str is the location in the apk to place
        the file, tbcml.Data is the actual file / data to place in that
        location. If you are modifying assets, these should be placed in
        pkg_assets instead."""

        self.ipa_files: dict[str, tbcml.Data] = {}
        """dict[str, tbcml.Data]: The files to place in the ipa when
        applying the mod. str is the location in the ipa to place
        the file, tbcml.Data is the actual file / data to place in that
        location. If you are modifying assets, these should be placed in
        pkg_assets instead."""

        self.audio_files: dict[int, tbcml.AudioFile] = {}
        """dict[int, tbcml.AudioFile]: The audio files to add to the mod. int
        is the id that the game uses to reference the audio file,
        tbcml.AudioFile is the audio file / data to add.
        
        See tbcml.AudioFile for more information on audio files."""

        self.pkg_strings: dict[str, tuple[str, bool]] = {}
        """dict[str, tuple[str, bool]]: The strings to set in the apk/ipa when applying the mod.
        In the apk it is used to set the strings in the strings.xml file.
        In the ipa it is used to set the strings in the Localizable.strings file.
        It is setup as: dict[key, tuple[value, include_lang]]
        """

        self.smali: tbcml.SmaliSet = tbcml.SmaliSet.create_empty()
        """tbcml.SmaliSet: The smali code to add to the mod. Is not supported
        for ipa files. Smali code is used to modify the java game code.
        
        See tbcml.SmaliSet for more information on smali code."""
        self.patches: tbcml.LibPatches = tbcml.LibPatches.create_empty()
        """tbcml.LibPatches: The lib patches to add to the mod. Is not
        supported for ipa files atm. Lib patches are used to modify
        small parts of the game code, e.g replacing a string in the game code.
        
        See tbcml.LibPatches for more information on lib patches."""

        self.compilation_targets: list[tbcml.CompilationTarget] = []
        """list[tbcml.CompilationTarget]: The compilation targets of the
        mod, which specify the game versions, country codes and languages that
        the compiled game files should be applied to (if they exist).

        See tbcml.CompilationTarget for more information on compilation
        targets."""

    def remove_duplicate_modifications(self):
        """Remove duplicate modifications from the mod.

        Example Usage:
            ```python
            mod = Mod(...)
            mod.remove_duplicate_modifications()
            ```
        """
        new_modifications: list[Modification] = []
        for mod in self.modifications:
            if mod not in new_modifications:
                new_modifications.append(mod)

        self.modifications = new_modifications

    def merge_modifications(self):
        """Merge modifications in the mod.

        Example Usage:
            ```python
            mod = Mod(...)
            mod.merge_modifications()
            ```
        """
        new_modifications: list[Modification] = []
        modifs = self.modifications.copy()
        modifs.reverse()
        for mod in modifs:
            found = False
            for new_mod in new_modifications:
                if mod.modification_type == new_mod.modification_type:
                    new_mod.merge(mod)
                    found = True
                    break
            if not found:
                new_modifications.append(mod)

        self.modifications = new_modifications

    def is_author(self, author: str, ignore_case: bool = False) -> bool:
        """Check if the mod has an author.
        Note that this is not a secure way to check for authors, as the authors can be easily changed

        Args:
            author (str): The author to check for.
            ignore_case (bool, optional): Whether to ignore the case of the author. Defaults to False.

        Returns:
            bool: Whether the mod has the author or not.

        Example Usage:
            ```python
            mod = Mod(...)
            if mod.is_author("fieryhenry"):
                print("fieryhenry is an author of this mod")
            ```
        """
        for auth in self.authors:
            if ignore_case:
                if auth.lower() == author.lower():
                    return True
            else:
                if auth == author:
                    return True
        return False

    def add_pkg_string(self, key: str, value: str, include_lang: bool):
        """Add a string to be set in the apk/ipa when applying the mod.

        Args:
            key (str): The key of the string to set.
            value (str): The value of the string to set.
            include_lang (bool): Whether to append the current language after the key

        Example Usage:
            ```python
            mod = Mod(...)
            mod.add_pkg_string("app_name", "My Cool App", False)
            ```
        """
        self.pkg_strings[key] = (value, include_lang)

    def add_compilation_target(self, target: "tbcml.CompilationTarget"):
        """Add a compilation target to the mod.

        See tbcml.CompilationTarget for more information on compilation targets.

        A compilation target specifies the game versions, country codes and
        languages that the compiled game files should be applied to (if they
        exist).


        Args:
            target (tbcml.CompilationTarget): The compilation target to add

        Example Usage:
            ```python
            mod = Mod(...)

            target = tbcml.CompilationTarget(target_country_codes="!jp", target_game_versions="*")
            mod.add_compilation_target(target)
            ```

        """
        self.compilation_targets.append(target)

    def add_encrypted_pkg_asset(
        self,
        asset_path: "tbcml.PathStr",
        local_f: "tbcml.File",
    ):
        """Add an encrypted file to be placed in the apk/ipa asset folder when applying the mod.

        Args:
            asset_path (tbcml.PathStr): The location in the apk/ipa to place the asset
            local_f (tbcml.File): The actual decrypted file / data to encrypt and place in that location.

        Example Usage:
            ```python
            mod = Mod(...)
            local_path = tbcml.Path("new_ponos_logo.png")
            mod.add_encrypted_pkg_asset("logo.png", local_path)
            ```
        """
        data = tbcml.load(local_f)
        path = tbcml.Path(asset_path).strip_leading_slash().to_str_forwards()
        self.encrypted_pkg_assets[path] = data

    def add_pkg_asset(
        self,
        asset_path: "tbcml.PathStr",
        local_f: "tbcml.File",
    ):
        """Add a file to be placed in the apk/ipa asset folder when applying
        the mod.

        If you want to edit apk/ipa specific files use the `add_apk_file(...)`
        and `add_ipa_file(...)` functions respectively.

        Args:
            asset_path (tbcml.PathStr): The location in the apk/ipa to place the asset
            local_f (tbcml.File): The actual file / data to place in that location.

        Example Usage:
            ```python
            mod = Mod(...)
            local_path = tbcml.Path("complete_new.png")
            mod.add_pkg_asset("complete.png", local_path)
            ```
        """
        data = tbcml.load(local_f)
        path = tbcml.Path(asset_path).strip_leading_slash().to_str_forwards()
        self.pkg_assets[path] = data

    def add_apk_file(
        self,
        apk_path: "tbcml.PathStr",
        local_f: "tbcml.File",
    ):
        """Add a file to be placed in the apk when applying the mod.

        If you are editing an asset you should use `add_pkg_asset` to also work
        with ipa files.

        Args:
            apk_path (tbcml.PathStr): The location in the apk to place the file
            local_f (tbcml.File): The actual file / data to place in that location.

        Example Usage:
            ```python
            mod = Mod(...)
            local_path = tbcml.Path("modded_classes.dex")
            mod.add_apk_file("classes.dex", local_path)
            ```
        """
        data = tbcml.load(local_f)
        path = tbcml.Path(apk_path).strip_leading_slash().to_str_forwards()
        self.apk_files[path] = data

    def add_ipa_file(
        self,
        ipa_path: "tbcml.PathStr",
        local_f: "tbcml.File",
    ):
        """Add a file to be placed in the ipa when applying the mod.

        If you are editing an asset you should use `add_pkg_asset` to also work
        with apk files.

        Args:
            ipa_path (tbcml.PathStr): The location in the ipa to place the file
            local_f (tbcml.File): The actual file / data to place in that location.

        Example Usage:
            ```python
            mod = Mod(...)
            local_path = tbcml.Path("cool_framework.dylib")
            mod.add_ipa_file("Frameworks/cool_framework.dylib", local_path)
            ```
        """
        data = tbcml.load(local_f)
        path = tbcml.Path(ipa_path).strip_leading_slash().to_str_forwards()
        self.ipa_files[path] = data

    def get_asset(
        self, asset_name: "tbcml.PathStr", is_apk: bool
    ) -> tuple[Optional["tbcml.Data"], bool]:
        """Get an asset from the mod.

        Args:
            asset_name (tbcml.PathStr): The path of the asset to get.
            is_apk (bool): Whether the asset is an apk asset or not.

        Returns:
            tuple[Optional[tbcml.Data], bool]: The data of the asset if it exists, and whether the asset is from an encrypted asset or not.

        Example Usage:
            ```python
            mod = Mod(...)
            asset = mod.get_asset("cool_asset.png", True)
            if asset is not None:
                print("Asset exists!")
            ```
        """
        path = tbcml.Path(asset_name).strip_leading_slash().to_str_forwards()
        if is_apk:
            pkg_file = self.apk_files.get("assets/" + path)
            if pkg_file is not None:
                return pkg_file, False
        else:
            pkg_file = self.ipa_files.get(path)
        pkg_asset = self.pkg_assets.get(path)
        if pkg_asset is not None:
            return pkg_asset, False
        return self.encrypted_pkg_assets.get(path), True

    def add_audio_file(
        self,
        game_id: int,
        f: "tbcml.File",
        is_bgm: bool,
        loop: bool,
        priority: int = -1,
    ):
        """Add an audio file to the mod.

        Note that this does create a modification for the sound setting, so you do not need to add a sound setting modification yourself.

        Args:
            game_id (int): The id that the game uses to reference the audio file. E.g used when getting stage music.
            f (tbcml.File): The audio file / data to add.
            is_bgm (bool): Whether the audio file is a background music or not (sound effect).
            loop (bool): Whether the audio file should loop. Most background music should loop.
            priority (int, optional): The priority of the audio file. Defaults to -1 which is used for most background music.

        Example Usage:
            ```python
            mod = Mod(...)
            local_path = tbcml.Path("bgm.ogg")
            mod.add_audio_file(7, local_path, True, True, -1)
            ```

        """
        data = tbcml.load(f)
        audio_file = tbcml.AudioFile(game_id, is_bgm, data)
        sound_setting = tbcml.SoundSetting(
            game_id, bgm=is_bgm, loop=loop, priority=priority
        )
        self.__add_audio_file(audio_file, sound_setting)

    def add_game_file(
        self,
        game_name: str,
        f: "tbcml.File",
    ):
        """Add a game file to the mod.

        Args:
            game_name (str): The name of the game file to add.
            f (tbcml.File): The actual file / data to place in that location.

        Example Usage:
            ```python
            mod = Mod(...)
            local_path = tbcml.Path("new_localizable.tsv")
            mod.add_game_file("localizable.tsv", local_path)
            ```
        """
        data = tbcml.load(f)
        self.game_files[game_name] = data

    def to_zip(self) -> "tbcml.Data":
        """Convert the mod to a zip file.

        Returns:
            tbcml.Data: The data of the zip file.

        Example Usage:
            ```python
            ...
            data = mod.to_zip()
            ...
            ```
        """
        zipfile = tbcml.Zip()
        metadata_json = self.__metadata_to_json()
        metadata_file_name = tbcml.Path(ModPath.METADATA.value)
        zipfile.add_file(metadata_file_name, tbcml.Data(metadata_json))

        self.__add_modifications_to_zip(zipfile)
        self.__add_scripts_to_zip(zipfile)
        self.__add_game_files_to_zip(zipfile)

        self.__add_pkg_assets_to_zip(zipfile)
        self.__add_pkg_strings_to_zip(zipfile)
        self.__add_enc_pkg_assets_to_zip(zipfile)
        self.__add_apk_files_to_zip(zipfile)
        self.__add_ipa_files_to_zip(zipfile)

        self.__add_audio_files_to_zip(zipfile)
        self.__add_compilation_targets_to_zip(zipfile)

        self.smali.add_to_zip(zipfile)
        self.patches.add_to_zip(zipfile)

        return zipfile.to_data()

    @staticmethod
    def load(f: "tbcml.File") -> "Mod":
        """Load a mod from a file.

        Args:
            f (tbcml.File): The file to load the mod from.

        Returns:
            Mod: The loaded mod.

        Example Usage:
            ```python
            file = tbcml.Path("mod.zip")
            mod = Mod.load(file)
            print(mod.name)
            ...
            ```
        """
        data = tbcml.load(f)

        zipfile = tbcml.Zip(data)
        metadata_file_name = tbcml.Path(ModPath.METADATA.value)
        metadata_json = zipfile.get_file(metadata_file_name)
        if metadata_json is None:
            return Mod()
        mod = Mod.__metadata_from_json(metadata_json.to_str())

        Mod.__modifications_from_zip(zipfile, mod)
        Mod.__scripts_from_zip(zipfile, mod)
        Mod.__game_files_from_zip(zipfile, mod)

        Mod.__pkg_assets_from_zip(zipfile, mod)
        Mod.__pkg_strings_from_zip(zipfile, mod)
        Mod.__enc_pkg_assets_from_zip(zipfile, mod)
        Mod.__apk_files_from_zip(zipfile, mod)
        Mod.__ipa_files_from_zip(zipfile, mod)

        Mod.__audio_files_from_zip(zipfile, mod)
        Mod.__compilation_targets_from_zip(zipfile, mod)

        Mod.__patches_from_zip(zipfile, mod)

        mod.smali = tbcml.SmaliSet.from_zip(zipfile)

        return mod

    def save(self, path: "tbcml.PathStr"):
        """Save the mod to a file.

        Does the same thing as `to_file`.

        Args:
            path (tbcml.PathStr): The path to save the mod to.

        Example Usage:
            ```python
            mod = Mod(...)
            mod.save("mod.zip")
            ```

        """
        path = tbcml.Path(path)
        self.to_zip().to_file(path)

    def to_file(self, path: "tbcml.PathStr"):
        """Save the mod to a file.

        Does the same thing as `save`.

        Args:
            path (tbcml.PathStr): The path to save the mod to.

        Example Usage:
            ```python
            mod = Mod(...)
            mod.save("mod.zip")
            ```
        """
        self.save(path)

    def add_modification(self, modification: "Modification", merge: bool = False):
        """Add a modification to the mod.

        See tbcml.ModificationType for the different types of modifications
        that are currently supported.

        See each modification types respective class for more information on
        specific modifications.

        Args:
            modification (Modification): The modification to add.
            merge (bool, optional): Whether to merge the modification with other modifications of the same type. Defaults to False.

        Raises:
            ValueError: If the modification does not inherit from `Modification` (Invalid modification)

        Example Usage:
            ```python
            class CustomCat(tbcml.Cat): # Cat inherits from Modification
                ...

            mod = Mod(...)
            mod.add_modification(CustomCat(...))
            ```
        """
        if not isinstance(modification, Modification):  # type: ignore
            raise ValueError("modification does not inherit Modification!")

        self.modifications.append(modification)
        if merge:
            self.merge_modifications()

    def add_script(self, script: "tbcml.FridaScript"):
        """Add a frida script to the mod.

        See tbcml.FridaScript for more information on frida scripts.

        Is not supported for ipa files atm.

        Args:
            script (tbcml.FridaScript): The frida script to add.

        Example Usage:
            ```python
            mod = Mod(...)
            script_content = "log('Hello World')"
            script = tbcml.FridaScript(name="Hello World", content=script_content, architectures="all", description="Logs Hello World")
            mod.add_script(script)
            ```
        """
        self.scripts.append(script)

    def add_lib_patch(self, lib_patch: "tbcml.LibPatch"):
        """Add a lib patch to the mod.

        See tbcml.LibPatch for more information on lib patches.

        Is not supported for ipa files atm.

        Args:
            lib_patch (tbcml.LibPatch): The lib patch to add.

        Example Usage:
            ```python
            mod = Mod(...)
            patch = tbcml.StringReplacePatch(orig="Hello", new="World")
            lib_patch = tbcml.LibPatch(name="Hello World", architectures="all", patches=[patch])
            mod.add_lib_patch(lib_patch)
            ```
        """
        self.patches.add_patch(lib_patch)

    def add_smali(self, smali: Union["tbcml.Smali", "tbcml.SmaliSet"]):
        """Add some smali code to the mod.

        Is not supported for ipa files.

        See tbcml.Smali and tbcml.SmaliSet for more information on smali code.

        Args:
            smali (tbcml.Smali | tbcml.SmaliSet): The smali code to add.

        Example Usage:
            ```python
            mod = Mod(...)
            smali = tbcml.Smali(class_code="...", class_name="com.example.MyClass", function_sig_to_call="...")
            mod.add_smali(smali)
            ```
        """
        smalis: list["tbcml.Smali"] = []
        if isinstance(smali, tbcml.Smali):
            smalis.append(smali)
        else:
            smalis = smali.get_list()

        for sml in smalis:
            self.smali.add(sml)

    def compile(
        self,
        game_packs: "tbcml.GamePacks",
        existing_target: Optional["tbcml.CompilationTarget"] = None,
        clear_modifications: bool = True,
        add_target: bool = True,
    ) -> "tbcml.CompilationTarget":
        """Compile the mod to raw game files.

        See tbcml.CompilationTarget for more information on compilation targets.

        Args:
            game_packs (tbcml.GamePacks): The game packs used to compile the mod.
            existing_target (Optional[tbcml.CompilationTarget], optional): The existing target to compile to. Defaults to None, which means a new target will be created with country code and game version from the game_packs.
            clear_modifications (bool, optional): Whether to remove the modifications after compiling. Defaults to True. (Recommended to keep this as True to prevent the same modifications being applied multiple times)
            add_target (bool, optional): Whether to add the compilation target to the mod. Defaults to True.

        Returns:
            tbcml.CompilationTarget: The compilation target that was compiled to.

        Example Usage:
            ```python
            mod = Mod(...)
            target = mod.compile(game_packs)
            mod.save("mod.zip")
            ```
        """
        target = self.__compile_modifications(
            game_packs, existing_target, clear_modifications, add_target
        )
        return target

    def apply_to_game_data(self, game_packs: "tbcml.GamePacks"):
        """Apply the mod to the game data. This should not really be called yourself, as it is called when applying the mods to a package.

        Args:
            game_packs (tbcml.GamePacks): The game packs to apply the mod to.
        """
        self.__apply_game_files(game_packs)
        self.__apply_compilations(game_packs)
        self.__apply_modifications(game_packs)

    def apply_to_pkg(self, pkg: "tbcml.PKG", lang: Optional[str] = None):
        """Apply the mod to a package (apk/ipa). This does not apply any game data modifications.
        This should not really be called yourself, as it is called when applying the mods to a package.

        Args:
            pkg (tbcml.PKG): The package to apply the mod to.
        """
        self.__apply_pkg_modifications(pkg, lang)
        self.__apply_audio_files(pkg)
        self.__apply_pkg_assets(pkg)
        self.__apply_pkg_strings(pkg, lang)
        self.__apply_enc_pkg_assets(pkg)
        if isinstance(pkg, tbcml.Apk):
            self.__apply_apk_files(pkg)
        else:
            self.__apply_ipa_files(pkg)

    def get_custom_html(self) -> str:
        """Get the custom html for the mod. This will be visible in the transfer menu mod list.

        This will be automatically generated if you do not provide a custom html when creating the mod.

        Returns:
            str: The custom html for the mod.
        """
        if self.custom_html is not None:
            return self.custom_html
        base_mod = (
            tbcml.Path.get_asset_file_path(tbcml.Path("html").add("base_mod.html"))
            .read()
            .to_str()
        )

        base_mod = base_mod.replace("{{MOD_NAME}}", self.name)
        base_mod = base_mod.replace("{{MOD_AUTHORS}}", ", ".join(self.authors))
        base_mod = base_mod.replace("{{MOD_SHORT_DESCRIPTION}}", self.short_description)
        base_mod = base_mod.replace("{{MOD_LONG_DESCRIPTION}}", self.long_description)

        modifications_str = ""

        for modification in self.modifications:
            html = modification.get_custom_html()
            modifications_str += f'<br><span class="iro">[{modification.modification_type.name}] </span>{html}<br>'

        base_mod = base_mod.replace("{{MODIFICATIONS}}", modifications_str)

        script_str = ""
        for script in self.scripts:
            html = script.get_custom_html()
            script_str += "<br>" + html + "<br>"

        base_mod = base_mod.replace("{{SCRIPTS}}", script_str)

        return base_mod

    def get_scripts_str(self, apk: "tbcml.Apk") -> tuple[dict[str, str], bool]:
        scripts_dict: dict[str, str] = {}
        inject_smali = False
        for script in self.scripts:
            scripts_str, inj = script.get_scripts_str(apk, self.name, self.authors)
            if inj:
                inject_smali = True
            for arc, string in scripts_str.items():
                if arc not in scripts_dict:
                    scripts_dict[arc] = ""
                scripts_dict[arc] += string + "\n"
        return scripts_dict, inject_smali

    def __add_audio_file(
        self,
        audio_file: "tbcml.AudioFile",
        sound_setting: Optional["tbcml.SoundSetting"],
    ):
        if sound_setting is None:
            sound_setting = tbcml.SoundSetting(audio_file.id, bgm=audio_file.is_bgm)

        self.add_modification(sound_setting)

        self.audio_files[audio_file.id] = audio_file

    def __metadata_to_json(self) -> str:
        data = {
            "name": self.name,
            "authors": self.authors,
            "short_description": self.short_description,
            "long_description": self.long_description,
            "custom_html": self.custom_html,
            "id": self.id,
        }
        return json.dumps(data)

    @staticmethod
    def __metadata_from_json(data: str) -> "Mod":
        obj = json.loads(data)
        name = obj.get("name", "")
        authors = obj.get("authors", "")
        short_description = obj.get("short_description", "")
        long_description = obj.get("long_description", "")
        custom_html = obj.get("custom_html", None)
        id = obj.get("id", None)
        return Mod(
            name=name,
            authors=authors,
            short_description=short_description,
            long_description=long_description,
            custom_html=custom_html,
            mod_id=id,
        )

    def __add_compilation_targets_to_zip(self, zipfile: "tbcml.Zip"):
        for i, target in enumerate(self.compilation_targets):
            target.add_to_zip(i, zipfile)

    def __add_pkg_assets_to_zip(self, zipfile: "tbcml.Zip"):
        for name, data in self.pkg_assets.items():
            path = tbcml.Path(ModPath.PKG_ASSETS.value).add(name)
            zipfile.add_file(path, data)

    def __add_pkg_strings_to_zip(self, zipfile: "tbcml.Zip"):
        path = tbcml.Path(ModPath.PKG_STRINGS.value)
        data = tbcml.JsonFile.from_object(self.pkg_strings).to_data()
        zipfile.add_file(path, data)

    def __add_enc_pkg_assets_to_zip(self, zipfile: "tbcml.Zip"):
        for name, data in self.encrypted_pkg_assets.items():
            path = tbcml.Path(ModPath.ENC_PKG_ASSETS.value).add(name)
            zipfile.add_file(path, data)

    def __add_apk_files_to_zip(self, zipfile: "tbcml.Zip"):
        for name, data in self.apk_files.items():
            path = tbcml.Path(ModPath.APK_FILES.value).add(name)
            zipfile.add_file(path, data)

    def __add_ipa_files_to_zip(self, zipfile: "tbcml.Zip"):
        for name, data in self.ipa_files.items():
            path = tbcml.Path(ModPath.IPA_FILES.value).add(name)
            zipfile.add_file(path, data)

    def __add_audio_files_to_zip(self, zipfile: "tbcml.Zip"):
        for id, audio in self.audio_files.items():
            ext = audio.get_sound_format()
            path = tbcml.Path(ModPath.AUDIO_FILES.value).add(
                f"{str(id).zfill(3)}.{ext}"
            )
            zipfile.add_file(path, audio.data)

    def __add_game_files_to_zip(self, zipfile: "tbcml.Zip"):
        for name, data in self.game_files.items():
            path = tbcml.Path(ModPath.GAME_FILES.value).add(name)
            zipfile.add_file(path, data)

    def __add_scripts_to_zip(self, zipfile: "tbcml.Zip"):
        for i, script in enumerate(self.scripts):
            script.add_to_zip(i, zipfile)

    def __add_modifications_to_zip(self, zipfile: "tbcml.Zip"):
        for i, modification in enumerate(self.modifications):
            filepath = (
                tbcml.Path(ModPath.MODIFICATIONS.value)
                .add(modification.modification_type.value)
                .add(f"{i}.json")
            )
            json_data = modification.to_json()
            zipfile.add_file(filepath, tbcml.Data(json_data))

    @staticmethod
    def __compilation_targets_from_zip(zipfile: "tbcml.Zip", mod: "Mod"):
        for i in range(
            len(Mod.__get_files_in_mod_path(zipfile, ModPath.COMPILATION_TARGETS))
        ):
            target = tbcml.CompilationTarget.from_zip(i, zipfile)
            if target is None:
                continue
            mod.add_compilation_target(target)

    @staticmethod
    def __get_files_in_mod_path(zipfile: "tbcml.Zip", path_type: ModPath):
        return zipfile.get_paths_in_folder(tbcml.Path(path_type.value))

    @staticmethod
    def __patches_from_zip(zipfile: "tbcml.Zip", mod: "Mod"):
        lib_patches: list[tbcml.LibPatch] = []
        for path in tbcml.Mod.__get_files_in_mod_path(
            zipfile, tbcml.ModPath.LIB_PATCHES
        ):
            lib_patches.append(tbcml.LibPatch.from_zip(zipfile, path))
        mod.patches = tbcml.LibPatches(lib_patches)

    @staticmethod
    def __pkg_assets_from_zip(zipfile: "tbcml.Zip", mod: "Mod"):
        for path in Mod.__get_files_in_mod_path(zipfile, ModPath.PKG_ASSETS):
            data = zipfile.get_file(path)
            if data is not None:
                key = (
                    path.remove_prefix(ModPath.PKG_ASSETS.value)
                    .strip_leading_slash()
                    .to_str_forwards()
                )
                mod.pkg_assets[key] = data

    @staticmethod
    def __pkg_strings_from_zip(zipfile: "tbcml.Zip", mod: "Mod"):
        path = tbcml.Path(ModPath.PKG_STRINGS.value)
        data = zipfile.get_file(path)
        if data is not None:
            mod.pkg_strings = tbcml.JsonFile(data).get_json()

    @staticmethod
    def __enc_pkg_assets_from_zip(zipfile: "tbcml.Zip", mod: "Mod"):
        for path in Mod.__get_files_in_mod_path(zipfile, ModPath.ENC_PKG_ASSETS):
            data = zipfile.get_file(path)
            if data is not None:
                key = (
                    path.remove_prefix(ModPath.ENC_PKG_ASSETS.value)
                    .strip_leading_slash()
                    .to_str_forwards()
                )
                mod.encrypted_pkg_assets[key] = data

    @staticmethod
    def __apk_files_from_zip(zipfile: "tbcml.Zip", mod: "Mod"):
        for path in Mod.__get_files_in_mod_path(zipfile, ModPath.APK_FILES):
            data = zipfile.get_file(path)
            if data is not None:
                key = (
                    path.remove_prefix(ModPath.APK_FILES.value)
                    .strip_leading_slash()
                    .to_str_forwards()
                )
                mod.apk_files[key] = data

    @staticmethod
    def __ipa_files_from_zip(zipfile: "tbcml.Zip", mod: "Mod"):
        for path in Mod.__get_files_in_mod_path(zipfile, ModPath.IPA_FILES):
            data = zipfile.get_file(path)
            if data is not None:
                key = (
                    path.remove_prefix(ModPath.IPA_FILES.value)
                    .strip_leading_slash()
                    .to_str_forwards()
                )
                mod.ipa_files[key] = data

    @staticmethod
    def __audio_files_from_zip(zipfile: "tbcml.Zip", mod: "Mod"):
        for path in Mod.__get_files_in_mod_path(zipfile, ModPath.AUDIO_FILES):
            data = zipfile.get_file(path)
            if data is not None:
                key = path.basename()
                if not key.isdigit():
                    continue
                key = int(key)
                is_bgm = tbcml.AudioFile.get_is_bgm(path.get_extension())
                audio_file = tbcml.AudioFile(key, is_bgm, data)
                mod.audio_files[key] = audio_file

    @staticmethod
    def __game_files_from_zip(zipfile: "tbcml.Zip", mod: "Mod"):
        for path in Mod.__get_files_in_mod_path(zipfile, ModPath.GAME_FILES):
            data = zipfile.get_file(path)
            if data is not None:
                mod.game_files[path.basename()] = data

    @staticmethod
    def __scripts_from_zip(zipfile: "tbcml.Zip", mod: "Mod"):
        for path in Mod.__get_files_in_mod_path(zipfile, ModPath.SCRIPTS):
            script = tbcml.FridaScript.from_json(path.read().to_str())
            mod.add_script(script)

    @staticmethod
    def __modifications_from_zip(zipfile: "tbcml.Zip", mod: "Mod"):
        for path in Mod.__get_files_in_mod_path(zipfile, ModPath.MODIFICATIONS):
            if not path.get_extension() == "json":
                continue
            modification_type = path.parent().basename()
            dt = zipfile.get_file(path)
            if dt is None:
                continue
            modifiction = Mod.__modification_from_json((modification_type, dt.to_str()))
            mod.add_modification(modifiction)

    def __apply_modifications(self, game_packs: "tbcml.GamePacks"):
        for modification in self.modifications:
            modification.apply_game_data(game_packs)

    def __compile_modifications(
        self,
        game_packs: "tbcml.GamePacks",
        existing_target: Optional["tbcml.CompilationTarget"] = None,
        clear_modifications: bool = True,
        add_target: bool = True,
    ):
        game_packs.clear_log()
        game_packs.set_log_enabled(True)

        self.__apply_modifications(game_packs)

        if existing_target is None:
            existing_target = tbcml.CompilationTarget(
                game_packs.country_code.get_code(), game_packs.gv.to_string()
            )

        for file, data in game_packs.get_log().items():
            existing_target.set_file(file, data)

        game_packs.set_log_enabled(False)
        game_packs.clear_log()

        if clear_modifications:
            self.modifications = []

        if add_target:
            self.add_compilation_target(existing_target)

        return existing_target

    def __apply_game_files(self, game_packs: "tbcml.GamePacks"):
        for file, data in self.game_files.items():
            game_packs.set_file(file, data)

    def __apply_compilations(self, game_packs: "tbcml.GamePacks"):
        for target in self.compilation_targets:
            if not target.check_game_data(game_packs):
                continue
            for file, data in target.files.items():
                game_packs.set_file(file, data)

    def __apply_apk_files(self, apk: "tbcml.Apk"):
        for file, data in self.apk_files.items():
            file = tbcml.Path(file).strip_leading_slash()
            path = apk.extracted_path.add(file)
            path.parent().generate_dirs()
            path.write(data)

    def __apply_ipa_files(self, ipa: "tbcml.Ipa"):
        for file, data in self.ipa_files.items():
            file = tbcml.Path(file).strip_leading_slash()
            path = ipa.get_asset(file)
            path.parent().generate_dirs()
            path.write(data)

    def __apply_pkg_assets(self, pkg: "tbcml.PKG"):
        for file, data in self.pkg_assets.items():
            file = tbcml.Path(file).strip_leading_slash()
            path = pkg.get_asset(file)
            path.parent().generate_dirs()
            path.write(data)

    def __apply_pkg_strings(self, pkg: "tbcml.PKG", lang: Optional[str] = None):
        for key, (value, include_lang) in self.pkg_strings.items():
            pkg.set_string(key, value, include_lang, lang)

    def __apply_enc_pkg_assets(self, pkg: "tbcml.PKG"):
        for file, data in self.encrypted_pkg_assets.items():
            file = tbcml.Path(file).strip_leading_slash()
            pkg.add_asset_encrypt(file, data)

    def __apply_audio_files(self, pkg: "tbcml.PKG"):
        for audio in self.audio_files.values():
            pkg.add_audio(audio)

    def __apply_pkg_modifications(self, pkg: "tbcml.PKG", lang: Optional[str]):
        for mod in self.modifications:
            mod.apply_pkg(pkg, lang)

    @staticmethod
    def __modification_from_json(data: tuple[str, str]):
        mod_type, modification_dt = data

        type = ModificationType.from_str_value(mod_type)
        if type is None:
            raise ValueError("Invalid Modification")

        return Modification().from_json(modification_dt, type)
