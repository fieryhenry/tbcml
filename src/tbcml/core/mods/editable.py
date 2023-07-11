from typing import Any, Optional
from tbcml import core


class EditableClass:
    def __init__(self, data: Optional[dict[Any, Any]] = None):
        self.data = data

    @staticmethod
    def create_empty() -> "EditableClass":
        ...

    @staticmethod
    def from_game_data(game_data: "core.GamePacks") -> "EditableClass":
        ...

    def to_game_data(self, game_data: "core.GamePacks"):
        ...

    def apply_dict(
        self,
        dict_data: dict[str, Any],
        mod_edit_key: str,
        convert_int: bool = True,
    ):
        if self.data is None:
            raise ValueError("EditableClass.data is None!")
        data = dict_data.get(mod_edit_key)
        if data is None:
            return
        current_data = self.data.copy()
        modded_data = core.ModEditDictHandler(data, current_data).get_dict(
            convert_int=convert_int
        )
        for id, modded_item in modded_data.items():
            current_item = current_data.get(id)
            if current_item is None:
                current_item = self.create_empty()
            try:
                current_item.apply_dict(modded_item, mod_edit_key)
            except TypeError:
                current_item.apply_dict(modded_item)
            current_data[id] = current_item
        self.data = current_data

    def apply_mod_to_game_data(
        self,
        mod: "core.Mod",
        game_data: "core.GamePacks",
        mod_edit_key: str,
        convert_int: bool = True,
    ):
        data = mod.mod_edits.get(mod_edit_key)
        if data is None:
            return

        data_o = self.from_game_data(game_data)
        data_o.apply_dict(mod.mod_edits, mod_edit_key, convert_int=convert_int)
        data_o.to_game_data(game_data)

    def get(self, key: Any) -> Any:
        if self.data is None:
            raise ValueError("EditableClass.data is None!")
        return self.data.get(key)

    def set(self, key: Any, value: Any):
        if self.data is None:
            raise ValueError("EditableClass.data is None!")
        self.data[key] = value
