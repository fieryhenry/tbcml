from typing import Optional
from marshmallow_dataclass import dataclass
import tbcml

from tbcml.io.csv_fields import (
    IntCSVField,
    StringCSVField,
    IntListCSVField,
)


@dataclass
class CharaGroup(tbcml.Modification):
    group_id: int
    text_id: Optional[str] = None
    group_type: Optional[int] = None
    cat_ids: Optional[list[int]] = None
    modification_type: tbcml.ModificationType = tbcml.ModificationType.CHARA_GROUP

    def __post_init__(self):
        self._csv__group_id = IntCSVField(col_index=0)
        self._csv__text_id = StringCSVField(col_index=1)
        self._csv__group_type = IntCSVField(col_index=2)
        self._csv__cat_ids = IntListCSVField(col_index=3)
        CharaGroup.Schema()

    @staticmethod
    def find_index(csv: "tbcml.CSV", index: int):
        for i in range(1, len(csv.lines)):
            csv.index = i
            if csv.get_str(0) == str(index):
                return csv.index
        return None

    def read_csv(self, csv: "tbcml.CSV") -> bool:
        index = CharaGroup.find_index(csv, self.group_id)
        if index is None:
            return False

        csv.index = index
        tbcml.Modification.read_csv_fields(self, csv)

        return True

    def apply_csv(self, csv: "tbcml.CSV"):
        index = CharaGroup.find_index(csv, self.group_id)
        if index is None:
            index = len(csv.lines)
        csv.index = index
        csv.set_line([], index)
        tbcml.Modification.apply_csv_fields(self, csv, remove_others=False)

    @staticmethod
    def get_csv(game_data: "tbcml.GamePacks") -> tuple[str, Optional["tbcml.CSV"]]:
        filename = "Charagroup.csv"
        csv = game_data.get_csv(filename, remove_comments=False)
        return filename, csv

    def read(self, game_data: "tbcml.GamePacks"):
        _, csv = self.get_csv(game_data)
        if csv is None:
            return
        self.read_csv(csv)

    def apply(self, game_data: "tbcml.GamePacks"):
        file_name, csv = self.get_csv(game_data)
        if csv is None:
            return
        self.apply_csv(csv)

        game_data.set_csv(file_name, csv)
