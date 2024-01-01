import enum
from typing import Any, Optional, Sequence, TypeVar, Union
from tbcml import core
from dataclasses import fields


class ModificationType(enum.Enum):
    CAT = "cat"


T = TypeVar("T")


class Modification:
    Schema: Any

    def __init__(self, modification_type: ModificationType):
        self.modification_type = modification_type

    def to_json(self) -> str:
        return self.Schema().dumps(self)  # type: ignore

    @staticmethod
    def from_json(obj: type[T], data: str) -> T:
        return obj.Schema().loads(data)  # type: ignore

    def apply(self, game_data: "core.GamePacks"):
        ...

    @staticmethod
    def apply_csv_fields(
        obj: Any,
        csv: "core.CSV",
        required_values: Optional[Sequence[tuple[int, Union[str, int]]]] = None,
    ):
        if not hasattr(obj, "__dataclass_fields__"):
            raise ValueError("obj is not a dataclass!")
        if required_values is None:
            required_values = []
        for field in fields(obj):
            name = field.name
            value = getattr(obj, name)
            if isinstance(value, core.CSVField):
                original_len = len(csv.get_current_line() or [])
                for ind, val in required_values:
                    if ind < original_len:
                        continue
                    csv.set_str(val, ind)

                value.write_to_csv(csv)

    @staticmethod
    def read_csv_fields(
        obj: Any,
        csv: "core.CSV",
    ):
        if not hasattr(obj, "__dataclass_fields__"):
            raise ValueError("obj is not a dataclass!")

        for field in fields(obj):
            name = field.name
            value = getattr(obj, name)
            if isinstance(value, core.CSVField):
                value.read_from_csv(csv)


class NewMod:
    def __init__(self):
        self.modifications: list[Modification] = []

    def add_modification(self, modification: "Modification"):
        self.modifications.append(modification)

    def apply_modifications(self, game_packs: "core.GamePacks"):
        for modification in self.modifications:
            modification.apply(game_packs)

    def modifications_to_json(self) -> list[tuple[str, str]]:
        data: list[tuple[str, str]] = []
        for modification in self.modifications:
            data.append((modification.modification_type.value, modification.to_json()))
        return data

    def modifications_from_json(self, data: list[tuple[str, str]]):
        modifications: list[Modification] = []
        for mod_type, modification_dt in data:
            cls = None

            if mod_type == ModificationType.CAT.value:
                cls = core.CustomCat

            if cls is None:
                raise ValueError("Invalid Modification")

            modification = Modification.from_json(cls, modification_dt)
            modifications.append(modification)
        return modifications
