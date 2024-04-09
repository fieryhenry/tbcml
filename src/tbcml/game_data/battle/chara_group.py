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

    def __post_init__(self):
        self._csv__group_id = IntCSVField(col_index=0)
        self._csv__text_id = StringCSVField(col_index=1)
        self._csv__group_type = IntCSVField(col_index=2)
        self._csv__cat_ids = IntListCSVField(col_index=3)

    def import_from_bcu(
        self,
        bcu_zip: "tbcml.BCUZip",
        bcu_id: int,
        cat_id_map: dict[int, int],
    ) -> bool:
        """Import a character group from a bcuzip file

        Args:
            bcu_zip (tbcml.BCUZip): The bcuzip
            bcu_id (int): The id of the character group specified in bcu
            cat_id_map (dict[int, int]): A mapping of which bcu ids map to which cats. E.g {0: 10, 1: 22}, will map bcu cat id 0 to game cat id 10 and bcu cat id 1 to game cat id 22.

        Returns:
            bool: If the import was successful
        """
        bcu_chara_group = bcu_zip.get_bcu_chara_group(bcu_id, self.group_id, cat_id_map)
        if bcu_chara_group is None:
            return False
        bcu_chara_group.write_to_chara_group(self)
        return True

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

    def apply_game_data(self, game_data: "tbcml.GamePacks"):
        file_name, csv = self.get_csv(game_data)
        if csv is None:
            return
        self.apply_csv(csv)

        game_data.set_csv(file_name, csv)
