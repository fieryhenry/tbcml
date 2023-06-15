"""This module contains the Localizable class."""
from typing import Any, Optional
from tbcml import core


class LocalItem:
    """A class to represent a localizable item."""

    def __init__(self, key: str, value: str):
        """Initialize a LocalItem.

        Args:
            key (str): The key of the text.
            value (str): The text itself.
        """
        self.key = key
        self.value = value


class Localizable:
    """A class to handle the localizable.tsv file."""

    def __init__(self, localizable: dict[str, LocalItem]):
        """Initialize a Localizable object.

        Args:
            localizable (dict[str, LocalItem]): The localizable data.
        """
        self.localizable = localizable

    @staticmethod
    def from_game_data(game_data: "core.GamePacks") -> "Localizable":
        """Create a Localizable object from a GamePacks object.

        Args:
            game_data (GamePacks): The GamePacks object.

        Returns:
            Localizable: The Localizable object.
        """
        file_name = Localizable.get_file_name()

        file = game_data.find_file(file_name)
        if file is None:
            return Localizable.create_empty()
        csv_data = core.CSV(file.dec_data, "\t")

        localizable: dict[str, LocalItem] = {}
        for line in csv_data:
            try:
                key = line[0]
                value = line[1]
                localizable[key] = LocalItem(key, value)
            except IndexError:
                pass
        localizable_o = Localizable(localizable)
        game_data.localizable = localizable_o
        return localizable_o

    @staticmethod
    def get_file_name() -> str:
        """Get the file name of the localizable.tsv file.

        Returns:
            str: The file name.
        """
        return "localizable.tsv"

    def to_game_data(self, game_data: "core.GamePacks"):
        """Apply the localizable data to a GamePacks object.

        Args:
            game_data (GamePacks): The GamePacks object.
        """

        if len(self.localizable) == 0:
            return
        file_name = self.get_file_name()

        file = game_data.find_file(file_name)
        if file is None:
            return
        csv = core.CSV(file.dec_data, "\t")
        remaining_items = self.localizable.copy()
        for line in csv:
            try:
                key = line[0]
                item = self.get(key)
                if item is None:
                    continue
                line[1] = item
                del remaining_items[key]
            except IndexError:
                pass
        for item in remaining_items.values():
            csv.lines.append([item.key, item.value])
        game_data.set_file(file_name, csv.to_data())

    @staticmethod
    def create_empty() -> "Localizable":
        """Create an empty Localizable object.

        Returns:
            Localizable: The empty Localizable object.
        """
        return Localizable({})

    def get(self, key: str) -> Optional[str]:
        """Get the value of a localizable item.

        Args:
            key (str): The key of the localizable item.

        Returns:
            Optional[str]: The value of the localizable item. None if the item does not exist.
        """
        try:
            return self.localizable[key].value
        except KeyError:
            return None

    def get_lang(self) -> str:
        """Get the language code of the localizable data.

        Raises:
            ValueError: If the language code is not set.

        Returns:
            str: The language code.
        """
        lang = self.get("lang")
        if lang is None:
            raise ValueError("lang is not set")
        return lang

    def set(self, key: str, value: str):
        """Set the value of a localizable item.

        Args:
            key (str): The key of the localizable item.
            value (str): The value of the localizable item.
        """
        self.localizable[key] = LocalItem(key, value)

    def remove(self, key: str):
        """Remove a localizable item.

        Args:
            key (str): The key of the localizable item to remove.
        """
        try:
            del self.localizable[key]
        except KeyError:
            pass

    def rename(self, key: str, new_key: str):
        """Rename a localizable item.

        Args:
            key (str): The key of the localizable item to rename.
            new_key (str): The new key of the localizable item.
        """
        try:
            old = self.localizable[key]
            new = LocalItem(new_key, old.value)
            del self.localizable[key]
            self.localizable[new_key] = new
        except KeyError:
            pass

    def sort(self):
        """Sort the localizable items by key alphabetically in ascending order."""

        self.localizable = dict(sorted(self.localizable.items()))

    def apply_dict(self, dict_data: dict[str, Any]):
        """Apply a dictionary to the localizable items.

        Args:
            dict_data (dict[str, Any]): The dictionary.
        """
        localizable = dict_data.get("localizable")
        if localizable is None:
            return
        current_data = self.localizable.copy()
        mod_data = core.ModEditDictHandler(localizable, current_data).get_dict()
        for key, value in mod_data.items():
            self.set(key, value)

    @staticmethod
    def apply_mod_to_game_data(mod: "core.Mod", game_data: "core.GamePacks"):
        """Apply a mod to a GamePacks object.

        Args:
            mod (core.Mod): The mod.
            game_data (GamePacks): The GamePacks object.
        """
        localizable_data = mod.mod_edits.get("localizable")
        if localizable_data is None:
            return
        localizable = game_data.localizable
        localizable.apply_dict(mod.mod_edits)
        localizable.to_game_data(game_data)
