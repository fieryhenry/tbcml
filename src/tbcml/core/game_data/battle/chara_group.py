import enum
from typing import Any, Optional
from tbcml import core


class GroupType(enum.Enum):
    """The type of restriction that the group imposes on the lineup."""

    EXCLUDE = 0
    """The group cannot be in the lineup."""
    INCLUDE = 2
    """Only units in the group can be in the lineup."""


class CharaGroupSet:
    def __init__(
        self,
        group_id: int,
        text_id: Optional[str] = None,
        group_type: Optional[GroupType] = None,
        chara_ids: Optional[list[int]] = None,
    ):
        """Initializes a new CharaGroupSet.

        Args:
            group_id (int): The ID of the group.
            text_id (str): The text ID of the group. This is used to display the restriction message in the game. Found in resLocal/localizable.tsv.
            group_type (GroupType): The type of restriction that the group imposes on the lineup.
            chara_ids (list[int]): The IDs of the units in the group.
        """
        self.group_id = group_id
        self.text_id = text_id
        self.group_type = group_type
        self.chara_ids = chara_ids

    def apply_dict(self, dict_data: dict[str, Any]):
        self.group_id = dict_data.get("group_id", self.group_id)
        self.text_id = dict_data.get("text_id", self.text_id)
        group_type = dict_data.get("group_type")
        if group_type is not None:
            self.group_type = GroupType(group_type)
        self.chara_ids = dict_data.get("chara_ids", self.chara_ids)

    @staticmethod
    def create_empty(group_id: int) -> "CharaGroupSet":
        """Creates an empty CharaGroupSet.

        Args:
            group_id (int): The ID of the group.

        Returns:
            CharaGroupSet: An empty CharaGroupSet.
        """
        return CharaGroupSet(group_id)


class CharaGroups:
    def __init__(self, groups: dict[int, CharaGroupSet]):
        """Initializes a new CharaGroups.

        Args:
            groups (dict[int, CharaGroupSet]): The groups in the CharaGroups.
        """
        self.groups = groups

    @staticmethod
    def get_file_name() -> str:
        """Gets the name of the file that the CharaGroups are stored in.

        Returns:
            str: The name of the file that the CharaGroups are stored in.
        """
        return "Charagroup.csv"

    @staticmethod
    def from_game_data(game_data: "core.GamePacks") -> "CharaGroups":
        """Loads the CharaGroups from the game data.

        Returns:
            CharaGroups: The CharaGroups loaded from the game data.
        """
        if game_data.chara_groups is not None:
            return game_data.chara_groups
        file_name = CharaGroups.get_file_name()
        file = game_data.find_file(file_name)
        if file is None:
            return CharaGroups.create_empty()
        csv = core.CSV(file.dec_data)
        groups: dict[int, CharaGroupSet] = {}
        for line in csv.lines[1:]:
            id = int(line[0])
            text_id = line[1]
            group_type = GroupType(int(line[2]))
            chara_ids = [int(line[i]) for i in range(3, len(line))]
            groups[id] = CharaGroupSet(id, text_id, group_type, chara_ids)
        chara_o = CharaGroups(groups)
        game_data.chara_groups = chara_o
        return chara_o

    def to_game_data(self, game_data: "core.GamePacks"):
        """Writes the CharaGroups to the game data.

        Args:
            game_data (core.GamePacks): The game data to write to.
        """
        file_name = CharaGroups.get_file_name()
        file = game_data.find_file(file_name)
        if file is None:
            return
        csv = core.CSV(file.dec_data)
        remaining_groups = set(self.groups.keys())
        for i, line in enumerate(csv.lines[1:]):
            id = int(line[0])
            try:
                group = self.groups[id]
            except KeyError:
                continue
            if group.text_id is not None:
                line[1] = str(group.text_id)
            if group.group_type is not None:
                line[2] = str(group.group_type.value)

            if group.chara_ids is not None:
                for j, chara_id in enumerate(group.chara_ids):
                    line[j + 3] = str(chara_id)
            csv.lines[i + 1] = line
            remaining_groups.remove(id)

        for id in remaining_groups:
            group = self.groups[id]
            a_line = [
                str(id),
                str(group.text_id or 0),
                str(group.group_type.value) if group.group_type is not None else "0",
            ]
            for chara_id in group.chara_ids or []:
                a_line.append(str(chara_id))
            csv.lines.append(a_line)

        game_data.set_file(file_name, csv.to_data())

    @staticmethod
    def create_empty() -> "CharaGroups":
        """Creates an empty CharaGroups.

        Returns:
            CharaGroups: The empty CharaGroups.
        """
        return CharaGroups({})

    def apply_dict(self, dict_data: dict[str, Any]):
        groups = dict_data.get("chara_groups")
        if groups is not None:
            current_groups = self.groups.copy()
            modded_groups = core.ModEditDictHandler(groups, current_groups).get_dict(
                convert_int=True
            )
            for id, modded_group in modded_groups.items():
                group = current_groups.get(id)
                if group is None:
                    group = CharaGroupSet.create_empty(id)
                group.apply_dict(modded_group)
                current_groups[id] = group
            self.groups = current_groups

    @staticmethod
    def apply_mod_to_game_data(mod: "core.Mod", game_data: "core.GamePacks"):
        """Apply a mod to a GamePacks object.

        Args:
            mod (core.Mod): The mod.
            game_data (GamePacks): The GamePacks object.
        """
        chara_data = mod.mod_edits.get("chara_groups")
        if chara_data is None:
            return
        groups = CharaGroups.from_game_data(game_data)
        groups.apply_dict(mod.mod_edits)
        groups.to_game_data(game_data)
