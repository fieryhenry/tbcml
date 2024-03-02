from typing import Optional
from marshmallow_dataclass import dataclass
import tbcml

from tbcml.io.csv_fields import IntCSVField, BoolCSVField


@dataclass
class SoundSetting(tbcml.Modification):
    sound_id: int
    bgm: Optional[bool] = None
    loop: Optional[int] = None
    priority: Optional[int] = None
    modification_type: tbcml.ModificationType = tbcml.ModificationType.SOUND_SETTING

    def __post_init__(self):
        self._csv__bgm = BoolCSVField(col_index=0)
        self._csv__loop = BoolCSVField(col_index=1)
        self._csv__priority = IntCSVField(col_index=2)
        SoundSetting.Schema()

    def read_csv(self, csv: "tbcml.CSV") -> bool:
        csv.index = self.sound_id + 1
        tbcml.Modification.read_csv_fields(self, csv)
        return True

    def apply_csv(self, csv: "tbcml.CSV"):
        csv.index = self.sound_id + 1
        tbcml.Modification.apply_csv_fields(self, csv, remove_others=False)

    @staticmethod
    def get_csv(
        game_data: "tbcml.GamePacks",
    ) -> tuple[str, Optional["tbcml.CSV"]]:
        file_name = "Sound_setting.tsv"
        csv = game_data.get_csv(file_name, "\t")
        return file_name, csv

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
