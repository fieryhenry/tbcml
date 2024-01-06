from typing import Optional
from marshmallow_dataclass import dataclass
from tbcml import core

from tbcml.core.io.csv_fields import (
    StringCSVField,
    CSVField,
    StrListCSVField,
)


@dataclass
class LocalizableItem:
    key: StringCSVField = CSVField.to_field(StringCSVField, 0)
    value: StrListCSVField = CSVField.to_field(StrListCSVField, 1)

    def read_csv(self, index: int, csv: "core.CSV") -> bool:
        csv.index = index
        core.Modification.read_csv_fields(self, csv)
        return True

    def apply_csv(self, index: int, csv: "core.CSV"):
        csv.index = index
        core.Modification.apply_csv_fields(self, csv, remove_others=False)


@dataclass
class CustomLocalizable(core.Modification):
    strings: Optional[dict[str, LocalizableItem]] = None
    modification_type: core.ModificationType = core.ModificationType.LOCALIZABLE

    def __post_init__(
        self,
    ):  # This is required for CustomItemShop.Schema to not be a string for some reason
        CustomLocalizable.Schema()

    @staticmethod
    def get_csv(
        game_data: "core.GamePacks",
    ) -> tuple[str, Optional["core.CSV"]]:
        file_name = "localizable.tsv"
        csv = game_data.get_csv(file_name, "\t")

        return file_name, csv

    def read_strings(self, game_data: "core.GamePacks"):
        _, csv = CustomLocalizable.get_csv(game_data)
        if csv is None:
            return
        self.strings = {}
        for i in range(len(csv.lines)):
            string = LocalizableItem()
            string.read_csv(i, csv)
            self.strings[string.key.get()] = string

    def apply_strings(self, game_data: "core.GamePacks"):
        if self.strings is None:
            return
        name, csv = CustomLocalizable.get_csv(game_data)
        if csv is None:
            return
        remaining_items: dict[str, LocalizableItem] = self.strings.copy()
        length = len(csv.lines)
        for i, _ in enumerate(csv.lines):
            current_item = LocalizableItem()
            current_item.read_csv(i, csv)

            modded_item = self.strings.get(current_item.key.get())
            if modded_item is not None:
                modded_item.apply_csv(i, csv)
                remaining_items.pop(modded_item.key.get())

        for i, item in enumerate(remaining_items.values()):
            item.apply_csv(i + length, csv)

        game_data.set_csv(name, csv)

    def read(self, game_data: "core.GamePacks"):
        self.read_strings(game_data)

    def apply(self, game_data: "core.GamePacks"):
        self.apply_strings(game_data)

    def get_custom_html(self) -> str:
        ...

    def set_string(self, key: str, value: str):
        new_item = LocalizableItem()
        new_item.key.set(key)
        new_item.value.set(value.split("\t"))

        if self.strings is None:
            self.strings = {}

        self.strings[key] = new_item

    def get_string(self, key: str) -> Optional[str]:
        if self.strings is None:
            return None

        item = self.strings.get(key)
        if item is None:
            return None
        return "\t".join(item.value.get())

    def get_lang(self) -> str:
        lang = self.get_string("lang")
        if lang is None:
            raise ValueError(
                "lang is not set, make sure you have read localizable.tsv!"
            )
        return lang
