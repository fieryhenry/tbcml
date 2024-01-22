from typing import Optional
from marshmallow_dataclass import dataclass
import tbcml

from tbcml.io.csv_fields import (
    StringCSVField,
)


@dataclass
class LocalizableItem:
    key: Optional[str] = None
    value: Optional[str] = None

    def __post_init__(self):
        self.csv__key = StringCSVField(col_index=0)
        self.csv__value = StringCSVField(col_index=1)

    def read_csv(self, index: int, csv: "tbcml.CSV") -> bool:
        csv.index = index
        tbcml.Modification.read_csv_fields(self, csv)
        return True

    def apply_csv(self, index: int, csv: "tbcml.CSV"):
        csv.index = index
        tbcml.Modification.apply_csv_fields(self, csv, remove_others=False)


@dataclass
class Localizable(tbcml.Modification):
    strings: Optional[dict[str, LocalizableItem]] = None
    modification_type: tbcml.ModificationType = tbcml.ModificationType.LOCALIZABLE

    def __post_init__(self):
        self.modified = False
        Localizable.Schema()

    @staticmethod
    def get_csv(
        game_data: "tbcml.GamePacks",
    ) -> tuple[str, Optional["tbcml.CSV"]]:
        file_name = "localizable.tsv"
        csv = game_data.get_csv(file_name, "\t")

        return file_name, csv

    def read_strings(self, game_data: "tbcml.GamePacks"):
        _, csv = Localizable.get_csv(game_data)
        if csv is None:
            return
        self.strings = {}
        for i in range(len(csv.lines)):
            string = LocalizableItem()
            string.read_csv(i, csv)
            if string.key is not None:
                self.strings[string.key] = string

    def apply_strings(self, game_data: "tbcml.GamePacks"):
        if self.strings is None or not self.modified:
            return
        name, csv = Localizable.get_csv(game_data)
        if csv is None:
            return
        remaining_items: dict[str, LocalizableItem] = self.strings.copy()
        length = len(csv.lines)
        for i, _ in enumerate(csv.lines):
            current_item = LocalizableItem()
            current_item.read_csv(i, csv)

            if current_item.key is None:
                continue

            modded_item = self.strings.get(current_item.key)
            if modded_item is not None:
                modded_item.apply_csv(i, csv)
                if modded_item.key is not None:
                    remaining_items.pop(modded_item.key)

        for i, item in enumerate(remaining_items.values()):
            item.apply_csv(i + length, csv)

        game_data.set_csv(name, csv)

    def read(self, game_data: "tbcml.GamePacks"):
        self.read_strings(game_data)

    def apply(self, game_data: "tbcml.GamePacks"):
        self.apply_strings(game_data)

    def get_custom_html(self) -> str:
        if self.strings is None:
            return "No Custom Strings"
        html = "Strings:<br>"

        for key, value in self.strings.items():
            html += f'<span style="color:#000">{key} : {value}</span>'
        return html

    def set_string(self, key: str, value: str):
        new_item = LocalizableItem()
        new_item.key = key
        new_item.value = value

        if self.strings is None:
            self.strings = {}

        self.strings[key] = new_item
        self.modified = True

    def get_string(self, key: str) -> Optional[str]:
        if self.strings is None:
            return None

        item = self.strings.get(key)
        if item is None:
            return None
        return item.value

    def get_lang(self) -> str:
        lang = self.get_string("lang")
        if lang is None:
            raise ValueError(
                "lang is not set, make sure you have read localizable.tsv!"
            )
        return lang
