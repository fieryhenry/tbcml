from __future__ import annotations

from marshmallow_dataclass import dataclass
import tbcml

from tbcml.io.csv_fields import IntCSVField, BoolCSVField


@dataclass
class SoundSetting(tbcml.Modification):
    sound_id: int
    bgm: bool | None = None
    loop: bool | None = None
    priority: int | None = None

    def __post_init__(self):
        self._csv__bgm = BoolCSVField(col_index=0)
        self._csv__loop = BoolCSVField(col_index=1)
        self._csv__priority = IntCSVField(col_index=2)

    def read_csv(self, csv: tbcml.CSV) -> bool:
        csv.index = self.sound_id + 1
        tbcml.Modification.read_csv_fields(self, csv)
        return True

    def apply_csv(self, csv: tbcml.CSV):
        csv.index = self.sound_id + 1
        tbcml.Modification.apply_csv_fields(self, csv, remove_others=False)

    @staticmethod
    def get_csv(
        game_data: tbcml.GamePacks,
    ) -> tuple[str, tbcml.CSV | None]:
        file_name = "Sound_setting.tsv"
        csv = game_data.get_csv(file_name, "\t")
        return file_name, csv

    def read(self, game_data: tbcml.GamePacks):
        _, csv = self.get_csv(game_data)
        if csv is None:
            return
        self.read_csv(csv)

    def apply_game_data(self, game_data: tbcml.GamePacks):
        file_name, csv = self.get_csv(game_data)
        if csv is None:
            return
        self.apply_csv(csv)

        game_data.set_csv(file_name, csv)
