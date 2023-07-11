"""This module contains the Localizable class."""
from typing import Optional
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


class Localizable(core.EditableClass):
    """A class to handle the localizable.tsv file."""

    def __init__(self, localizable: dict[str, LocalItem]):
        """Initialize a Localizable object.

        Args:
            localizable (dict[str, LocalItem]): The localizable data.
        """
        self.data = localizable
        super().__init__(self.data)

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

        if len(self.data) == 0:
            return
        file_name = self.get_file_name()

        file = game_data.find_file(file_name)
        if file is None:
            return
        csv = core.CSV(file.dec_data, "\t")
        remaining_items = self.data.copy()
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
            return self.data[key].value
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
        self.data[key] = LocalItem(key, value)

    def remove(self, key: str):
        """Remove a localizable item.

        Args:
            key (str): The key of the localizable item to remove.
        """
        try:
            del self.data[key]
        except KeyError:
            pass

    def rename(self, key: str, new_key: str):
        """Rename a localizable item.

        Args:
            key (str): The key of the localizable item to rename.
            new_key (str): The new key of the localizable item.
        """
        try:
            old = self.data[key]
            new = LocalItem(new_key, old.value)
            del self.data[key]
            self.data[new_key] = new
        except KeyError:
            pass

    def sort(self):
        """Sort the localizable items by key alphabetically in ascending order."""

        self.data = dict(sorted(self.data.items()))
