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


class CharaGroups(core.EditableClass):
    def __init__(self, groups: dict[int, CharaGroupSet]):
        """Initializes a new CharaGroups.

        Args:
            groups (dict[int, CharaGroupSet]): The groups in the CharaGroups.
        """
        self.data = groups
        super().__init__(groups)

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
        for i in range(len(csv.lines[1:])):
            csv.init_getter(i + 1)
            id = csv.get_int()
            text_id = csv.get_str()
            group_type = GroupType(csv.get_int())
            chara_ids = csv.get_int_list()
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
        for group in self.data.values():
            csv.init_setter(group.group_id, 3, index_line_index=0)
            csv.set_str(group.group_id)
            csv.set_str(group.text_id)
            csv.set_str(group.group_type)
            csv.set_list(group.chara_ids)

        game_data.set_file(file_name, csv.to_data())

    @staticmethod
    def create_empty() -> "CharaGroups":
        """Creates an empty CharaGroups.

        Returns:
            CharaGroups: The empty CharaGroups.
        """
        return CharaGroups({})
