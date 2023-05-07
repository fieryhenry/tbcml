import enum
from typing import Optional
from tbcml.core.game_data import pack
from tbcml.core import io


class GatyaType(enum.Enum):
    RARE = "R"
    NORMAL = "N"
    EVENT = "E"


class GatyaDataSetData:
    def __init__(
        self,
        id: int,
        cats: list[int],
    ):
        self.id = id
        self.cats = cats


class GatyaDataSet:
    def __init__(
        self,
        gatya_type: GatyaType,
        index: int,
        sets: dict[int, GatyaDataSetData],
    ):
        self.gatya_type = gatya_type
        self.index = index
        self.sets = sets

    @staticmethod
    def get_file_name(type: GatyaType, index: int) -> str:
        return f"GatyaDataSet{type.value}{index+1}.csv"

    @staticmethod
    def from_game_data(
        game_data: "pack.GamePacks", type: GatyaType, index: int
    ) -> Optional["GatyaDataSet"]:
        file_name = GatyaDataSet.get_file_name(type, index)
        file = game_data.find_file(file_name)
        if file is None:
            return None
        csv = io.bc_csv.CSV(file.dec_data)
        sets: dict[int, GatyaDataSetData] = {}
        for i, line in enumerate(csv.lines):
            cats: list[int] = []
            for cat in line:
                try:
                    cat_id = int(cat)
                except ValueError:
                    cat_id = -1
                if cat_id != -1:
                    cats.append(cat_id)
            sets[i] = GatyaDataSetData(i, cats)
        return GatyaDataSet(type, index, sets)

    def to_game_data(self, game_data: "pack.GamePacks") -> None:
        file_name = GatyaDataSet.get_file_name(self.gatya_type, self.index)
        file = game_data.find_file(file_name)
        if file is None:
            return None
        csv = io.bc_csv.CSV(file.dec_data)
        for set in self.sets.values():
            line: list[str] = []
            for cat in set.cats:
                line.append(str(cat))
            line.append(str(-1))
            csv.lines[set.id] = line
        game_data.set_file(file_name, csv.to_data())


class GatyaDataSets:
    def __init__(
        self,
        type: GatyaType,
        gatya_sets: dict[int, GatyaDataSet],
    ):
        self.type = type
        self.gatya_sets = gatya_sets

    @staticmethod
    def from_game_data(game_data: "pack.GamePacks", type: GatyaType) -> "GatyaDataSets":
        gatya_sets: dict[int, GatyaDataSet] = {}
        i = 0
        while True:
            gatya_set = GatyaDataSet.from_game_data(game_data, type, i)
            if gatya_set is None:
                break
            gatya_sets[i] = gatya_set
            i += 1
        return GatyaDataSets(type, gatya_sets)

    def to_game_data(self, game_data: "pack.GamePacks") -> None:
        for gatya_set in self.gatya_sets.values():
            gatya_set.to_game_data(game_data)

    def get_gatya_set(self, index: int) -> Optional[GatyaDataSet]:
        return self.gatya_sets.get(index, None)

    def set_gatya_set(self, index: int, gatya_set: GatyaDataSet) -> None:
        gatya_set.index = index
        gatya_set.gatya_type = self.type
        self.gatya_sets[index] = gatya_set


class GatyaDataSetsAll:
    def __init__(
        self,
        gatya_data_sets: dict[GatyaType, GatyaDataSets],
    ):
        self.gatya_data_sets = gatya_data_sets

    @staticmethod
    def from_game_data(game_data: "pack.GamePacks") -> "GatyaDataSetsAll":
        gatya_data_sets: dict[GatyaType, GatyaDataSets] = {}
        for type in GatyaType:
            gatya_data_sets[type] = GatyaDataSets.from_game_data(game_data, type)
        return GatyaDataSetsAll(gatya_data_sets)

    def to_game_data(self, game_data: "pack.GamePacks") -> None:
        for gatya_data_set in self.gatya_data_sets.values():
            gatya_data_set.to_game_data(game_data)

    def get_gatya_data_sets(self, type: GatyaType) -> Optional[GatyaDataSets]:
        return self.gatya_data_sets.get(type, None)

    def set_gatya_data_sets(
        self, type: GatyaType, gatya_data_sets: GatyaDataSets
    ) -> None:
        gatya_data_sets.type = type
        self.gatya_data_sets[type] = gatya_data_sets

    @staticmethod
    def create_empty() -> "GatyaDataSetsAll":
        return GatyaDataSetsAll({})


class GatyaOptionSet:
    def __init__(
        self,
        gatya_set_id: int,
        banner_enabled: bool,
        ticket_item_id: int,
        anime_id: int,
        btn_cut_id: int,
        series_id: int,
        menu_cut_id: int,
        chara_id: Optional[int],
        extra: list[int],
    ):
        self.gatya_set_id = gatya_set_id
        self.banner_enabled = banner_enabled
        self.ticket_item_id = ticket_item_id
        self.anime_id = anime_id
        self.btn_cut_id = btn_cut_id
        self.series_id = series_id
        self.menu_cut_id = menu_cut_id
        self.chara_id = chara_id
        self.extra = extra


class GatyaOptions:
    def __init__(self, type: GatyaType, options: dict[int, GatyaOptionSet]):
        self.type = type
        self.options = options

    @staticmethod
    def get_file_name(type: GatyaType) -> str:
        return f"GatyaData_Option_Set{type.value}.tsv"

    @staticmethod
    def from_game_data(game_data: "pack.GamePacks", type: GatyaType) -> "GatyaOptions":
        file_name = GatyaOptions.get_file_name(type)
        file = game_data.find_file(file_name)
        if file is None:
            return GatyaOptions.create_empty(type)
        csv = io.bc_csv.CSV(file.dec_data, delimeter="\t")
        options: dict[int, GatyaOptionSet] = {}
        for line in csv.lines[1:]:
            id = int(line[0])
            try:
                chara_id = int(line[7])
            except IndexError:
                chara_id = None
            try:
                extra = [int(x) for x in line[8:]]
            except IndexError:
                extra = []

            options[id] = GatyaOptionSet(
                id,
                bool(line[1]),
                int(line[2]),
                int(line[3]),
                int(line[4]),
                int(line[5]),
                int(line[6]),
                chara_id,
                extra,
            )
        return GatyaOptions(type, options)

    def to_game_data(self, game_data: "pack.GamePacks"):
        file_name = GatyaOptions.get_file_name(self.type)
        file = game_data.find_file(file_name)
        if file is None:
            return
        remaining = self.options.copy()
        csv = io.bc_csv.CSV(file.dec_data, delimeter="\t")
        for i, line in enumerate(csv.lines[1:]):
            id = int(line[0])
            option = self.options[id]
            line[1] = "1" if option.banner_enabled else "0"
            line[2] = str(option.ticket_item_id)
            line[3] = str(option.anime_id)
            line[4] = str(option.btn_cut_id)
            line[5] = str(option.series_id)
            line[6] = str(option.menu_cut_id)
            if option.chara_id is not None:
                line[7] = str(option.chara_id)
            for i, value in enumerate(option.extra):
                line[8 + i] = str(value)
            csv.lines[i + 1] = line
            del remaining[id]
        for id, option in remaining.items():
            aline: list[str] = []
            aline.append(str(id))
            aline.append("1" if option.banner_enabled else "0")
            aline.append(str(option.ticket_item_id))
            aline.append(str(option.anime_id))
            aline.append(str(option.btn_cut_id))
            aline.append(str(option.series_id))
            aline.append(str(option.menu_cut_id))
            if option.chara_id is not None:
                aline.append(str(option.chara_id))
            aline.extend([str(x) for x in option.extra])
            csv.lines.append(aline)
        game_data.set_file(file_name, csv.to_data())

    @staticmethod
    def create_empty(type: GatyaType) -> "GatyaOptions":
        return GatyaOptions(type, {})


class GatyaOptionsAll:
    def __init__(self, gatya_options: dict[GatyaType, GatyaOptions]):
        self.gatya_options = gatya_options

    @staticmethod
    def from_game_data(game_data: "pack.GamePacks") -> "GatyaOptionsAll":
        gatya_otpions: dict[GatyaType, GatyaOptions] = {}
        for type in GatyaType:
            options = GatyaOptions.from_game_data(game_data, type)
            gatya_otpions[type] = options
        return GatyaOptionsAll(gatya_otpions)

    def to_game_data(self, game_data: "pack.GamePacks"):
        for options in self.gatya_options.values():
            options.to_game_data(game_data)

    @staticmethod
    def create_empty() -> "GatyaOptionsAll":
        return GatyaOptionsAll({})

    def set_gatya_options(self, type: GatyaType, options: GatyaOptions):
        options.type = type
        self.gatya_options[type] = options


class Gatya:
    def __init__(
        self, gatya_options: GatyaOptionsAll, gatya_data_sets: GatyaDataSetsAll
    ):
        self.gatya_options = gatya_options
        self.gatya_data_sets = gatya_data_sets

    def get_gatya_options(self, type: GatyaType) -> GatyaOptions:
        return self.gatya_options.gatya_options[type]

    def set_gatya_options(self, type: GatyaType, options: GatyaOptions):
        self.gatya_options.set_gatya_options(type, options)

    @staticmethod
    def from_game_data(game_data: "pack.GamePacks") -> "Gatya":
        gatya_options = GatyaOptionsAll.from_game_data(game_data)
        gatya_data_sets = GatyaDataSetsAll.from_game_data(game_data)
        return Gatya(gatya_options, gatya_data_sets)

    def to_game_data(self, game_data: "pack.GamePacks"):
        self.gatya_options.to_game_data(game_data)
        self.gatya_data_sets.to_game_data(game_data)

    @staticmethod
    def create_empty() -> "Gatya":
        return Gatya(GatyaOptionsAll.create_empty(), GatyaDataSetsAll.create_empty())

    def set_gatya(self, gatya: "Gatya"):
        self.gatya_options = gatya.gatya_options
        self.gatya_data_sets = gatya.gatya_data_sets
