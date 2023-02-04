import enum
from typing import Any, Optional
from bcml.core.game_data import pack
from bcml.core import io


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

    def serialize(self) -> dict[str, Any]:
        return {
            "cats": self.cats,
        }

    @staticmethod
    def deserialize(data: dict[str, Any], id: int) -> "GatyaDataSetData":
        return GatyaDataSetData(
            id,
            data["cats"],
        )


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

    def serialize(self) -> dict[str, Any]:
        return {
            "sets": {str(key): value.serialize() for key, value in self.sets.items()},
        }

    @staticmethod
    def deserialize(
        data: dict[str, Any], gatya_type: GatyaType, index: int
    ) -> "GatyaDataSet":
        return GatyaDataSet(
            gatya_type,
            index,
            {
                int(key): GatyaDataSetData.deserialize(value, int(key))
                for key, value in data["sets"].items()
            },
        )

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
                    cat_id = cat.to_int()
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
            line: list[int] = []
            for cat in set.cats:
                line.append(cat)
            line.append(-1)
            csv.set_line(set.id, line)
        game_data.set_file(file_name, csv.to_data())


class GatyaDataSets:
    def __init__(
        self,
        type: GatyaType,
        gatya_sets: dict[int, GatyaDataSet],
    ):

        self.type = type
        self.gatya_sets = gatya_sets

    def serialize(self) -> dict[str, Any]:
        return {
            "type": self.type.value,
            "gatya_sets": {
                str(key): value.serialize() for key, value in self.gatya_sets.items()
            },
        }

    @staticmethod
    def deserialize(data: dict[str, Any]) -> "GatyaDataSets":
        return GatyaDataSets(
            GatyaType(data["type"]),
            {
                int(key): GatyaDataSet.deserialize(
                    value, GatyaType(data["type"]), int(key)
                )
                for key, value in data["gatya_sets"].items()
            },
        )

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

    def serialize(self) -> dict[str, Any]:
        return {
            "gatya_data_sets": {
                str(key.value): value.serialize()
                for key, value in self.gatya_data_sets.items()
            },
        }

    @staticmethod
    def deserialize(data: dict[str, Any]) -> "GatyaDataSetsAll":
        return GatyaDataSetsAll(
            {
                GatyaType(key): GatyaDataSets.deserialize(value)
                for key, value in data["gatya_data_sets"].items()
            },
        )

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

    def serialize(self) -> dict[str, Any]:
        return {
            "gatya_set_id": self.gatya_set_id,
            "banner_enabled": self.banner_enabled,
            "ticket_item_id": self.ticket_item_id,
            "anime_id": self.anime_id,
            "btn_cut_id": self.btn_cut_id,
            "series_id": self.series_id,
            "menu_cut_id": self.menu_cut_id,
            "chara_id": self.chara_id,
            "extra": self.extra,
        }

    @staticmethod
    def deserialize(data: dict[str, Any]) -> "GatyaOptionSet":
        return GatyaOptionSet(
            data["gatya_set_id"],
            data["banner_enabled"],
            data["ticket_item_id"],
            data["anime_id"],
            data["btn_cut_id"],
            data["series_id"],
            data["menu_cut_id"],
            data["chara_id"],
            data["extra"],
        )


class GatyaOptions:
    def __init__(self, type: GatyaType, options: dict[int, GatyaOptionSet]):
        self.type = type
        self.options = options

    def serialize(self) -> dict[str, Any]:
        return {
            "type": self.type.value,
            "options": {
                str(key): value.serialize() for key, value in self.options.items()
            },
        }

    @staticmethod
    def deserialize(data: dict[str, Any]) -> "GatyaOptions":
        return GatyaOptions(
            GatyaType(data["type"]),
            {
                int(key): GatyaOptionSet.deserialize(value)
                for key, value in data["options"].items()
            },
        )

    @staticmethod
    def get_file_name(type: GatyaType) -> str:
        return f"GatyaData_Option_Set{type.value}.tsv"

    @staticmethod
    def from_game_data(
        game_data: "pack.GamePacks", type: GatyaType
    ) -> Optional["GatyaOptions"]:
        file_name = GatyaOptions.get_file_name(type)
        file = game_data.find_file(file_name)
        if file is None:
            return None
        csv = io.bc_csv.CSV(file.dec_data, delimeter="\t")
        options: dict[int, GatyaOptionSet] = {}
        for line in csv.lines[1:]:
            id = line[0].to_int()
            try:
                chara_id = line[7].to_int()
            except IndexError:
                chara_id = None
            try:
                extra = io.data.Data.data_list_int_list(line[8:])
            except IndexError:
                extra = []

            options[id] = GatyaOptionSet(
                id,
                line[1].to_bool(),
                line[2].to_int(),
                line[3].to_int(),
                line[4].to_int(),
                line[5].to_int(),
                line[6].to_int(),
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
            id = line[0].to_int()
            option = self.options[id]
            line[1].set(option.banner_enabled)
            line[2].set(option.ticket_item_id)
            line[3].set(option.anime_id)
            line[4].set(option.btn_cut_id)
            line[5].set(option.series_id)
            line[6].set(option.menu_cut_id)
            if option.chara_id is not None:
                line[7].set(option.chara_id)
            for i, value in enumerate(option.extra):
                line[8 + i].set(value)
            csv.set_line(i + 1, line)
            del remaining[id]
        for id, option in remaining.items():
            aline: list[Any] = []
            aline.append(id)
            aline.append(option.banner_enabled)
            aline.append(option.ticket_item_id)
            aline.append(option.anime_id)
            aline.append(option.btn_cut_id)
            aline.append(option.series_id)
            aline.append(option.menu_cut_id)
            if option.chara_id is not None:
                aline.append(option.chara_id)
            aline.extend(option.extra)
            csv.add_line(aline)
        game_data.set_file(file_name, csv.to_data())


class GatyaOptionsAll:
    def __init__(self, gatya_options: dict[GatyaType, GatyaOptions]):
        self.gatya_options = gatya_options

    def serialize(self) -> dict[str, Any]:
        return {
            "gatya_otpions": {
                key.value: value.serialize()
                for key, value in self.gatya_options.items()
            },
        }

    @staticmethod
    def deserialize(data: dict[str, Any]) -> "GatyaOptionsAll":
        return GatyaOptionsAll(
            {
                GatyaType(key): GatyaOptions.deserialize(value)
                for key, value in data["gatya_otpions"].items()
            },
        )

    @staticmethod
    def from_game_data(game_data: "pack.GamePacks") -> Optional["GatyaOptionsAll"]:
        gatya_otpions: dict[GatyaType, GatyaOptions] = {}
        for type in GatyaType:
            options = GatyaOptions.from_game_data(game_data, type)
            if options is None:
                return None
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

    def serialize(self) -> dict[str, Any]:
        return {
            "gatya_options": self.gatya_options.serialize(),
            "gatya_data_sets": self.gatya_data_sets.serialize(),
        }

    @staticmethod
    def deserialize(data: dict[str, Any]) -> "Gatya":
        return Gatya(
            GatyaOptionsAll.deserialize(data["gatya_options"]),
            GatyaDataSetsAll.deserialize(data["gatya_data_sets"]),
        )

    @staticmethod
    def get_json_file_path() -> "io.path.Path":
        return io.path.Path("catbase").add("gatya.json")

    def add_to_zip(self, zip: "io.zip.Zip"):
        json = io.json_file.JsonFile.from_json(self.serialize())
        zip.add_file(self.get_json_file_path(), json.to_data())

    @staticmethod
    def from_zip(zip: "io.zip.Zip") -> "Gatya":
        json_data = zip.get_file(Gatya.get_json_file_path())
        if json_data is None:
            return Gatya.create_empty()
        json = io.json_file.JsonFile.from_data(json_data)
        return Gatya.deserialize(json.get_json())

    @staticmethod
    def from_game_data(game_data: "pack.GamePacks") -> Optional["Gatya"]:
        gatya_options = GatyaOptionsAll.from_game_data(game_data)
        gatya_data_sets = GatyaDataSetsAll.from_game_data(game_data)
        if gatya_options is None or gatya_data_sets is None:
            return None
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

    def import_gatya(self, other: "Gatya"):
        self.gatya_options.gatya_options.update(other.gatya_options.gatya_options)
        self.gatya_data_sets.gatya_data_sets.update(
            other.gatya_data_sets.gatya_data_sets
        )
