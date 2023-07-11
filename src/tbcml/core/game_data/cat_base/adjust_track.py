"""Module for handling the adjust track data."""
from typing import Any, Optional

from tbcml import core


class GatyaTrack:
    """A class to represent a gatya track event."""

    def __init__(
        self,
        roll_type: "core.RollType",
        event_token_1_uu: Optional[str] = None,
        event_token_2_total: Optional[str] = None,
        name: Optional[str] = None,
    ):
        """Initialize a GatyaTrack.

        Args:
            roll_type (core.RollType): The roll type.
            event_token_1_uu (Optional[str], optional): Event token 1 uu?. Defaults to None.
            event_token_2_total (Optional[str], optional): Event token 2 total?. Defaults to None.
            name (Optional[str], optional): The name of the event. Defaults to None.
        """
        self.roll_type = roll_type
        self.event_token_1_uu = event_token_1_uu
        self.event_token_2_total = event_token_2_total
        self.name = name

    def apply_dict(self, dict_data: dict[str, Any]):
        """Apply a dict to the GatyaTrack.

        Args:
            dict_data (dict[str, Any]): The dict to apply.
        """
        self.event_token_1_uu = dict_data.get("event_token_1_uu")
        self.event_token_2_total = dict_data.get("event_token_2_total")
        self.name = dict_data.get("name")

    @staticmethod
    def create_empty(roll_type: "core.RollType") -> "GatyaTrack":
        """Create an empty GatyaTrack.

        Args:
            roll_type (core.RollType): The roll type.

        Returns:
            GatyaTrack: The empty GatyaTrack.
        """
        return GatyaTrack(roll_type)


class GatyaTrackEvents:
    """A class to represent a gatya track event."""

    def __init__(
        self,
        gatya_type: "core.GatyaType",
        events: dict["core.RollType", GatyaTrack],
    ):
        """Initialize a GatyaTrackEvents.

        Args:
            gatya_type (core.GatyaType): The gatya type.
            events (dict[core.RollType, GatyaTrack]): The events.
        """
        self.gatya_type = gatya_type
        self.events = events

    def apply_dict(self, dict_data: dict[str, Any]):
        """Apply a dict to the GatyaTrackEvents.

        Args:
            dict_data (dict[str, Any]): The dict to apply.
        """
        events = dict_data.get("events")
        if events is not None:
            current_events = self.events.copy()
            modded_events = core.ModEditDictHandler(events, current_events).get_dict(
                convert_int=True
            )
            for id, modded_event in modded_events.items():
                event = self.events.get(id)
                if event is None:
                    event = GatyaTrack.create_empty(
                        core.RollType(id),
                    )
                event.apply_dict(modded_event)
                current_events[id] = event
            self.events = current_events

    @staticmethod
    def create_empty(gatya_type: "core.GatyaType") -> "GatyaTrackEvents":
        """Create an empty GatyaTrackEvents.

        Args:
            gatya_type (core.GatyaType): The gatya type.

        Returns:
            GatyaTrackEvents: The empty GatyaTrackEvents.
        """
        return GatyaTrackEvents(gatya_type, {})


class GatyaTrackData(core.EditableClass):
    """A class to represent the gatya track data."""

    def __init__(self, data: dict["core.GatyaType", GatyaTrackEvents]):
        """Initialize a GatyaTrackData.

        Args:
            data (dict[core.GatyaType, GatyaTrackEvents]): The data.
        """
        self.data = data
        super().__init__(self.data)

    @staticmethod
    def create_empty() -> "GatyaTrackData":
        """Create an empty GatyaTrackData.

        Returns:
            GatyaTrackData: The empty GatyaTrackData.
        """
        return GatyaTrackData({})

    @staticmethod
    def get_file_name(lang: str) -> str:
        """Get the file name for the GatyaTrackData.

        Args:
            lang (str): The language.

        Returns:
            str: The file name.
        """
        return f"AdjustTrackEventToken_Gacha_{lang}.tsv"

    @staticmethod
    def from_game_data(game_data: "core.GamePacks") -> "GatyaTrackData":
        """Create a GatyaTrackData from the game data.

        Args:
            game_data (core.GamePacks): The game data.

        Returns:
            GatyaTrackData: The GatyaTrackData.
        """
        file = game_data.find_file(
            GatyaTrackData.get_file_name(game_data.localizable.get_lang())
        )
        if file is None:
            return GatyaTrackData.create_empty()
        csv = core.CSV(file.dec_data, "\t")

        data: dict[core.GatyaType, GatyaTrackEvents] = {}
        events: dict[core.GatyaType, dict[core.RollType, GatyaTrack]] = {}
        for i in range(len(csv.lines[1:])):
            csv.init_getter(i + 1)
            gatya_type = core.GatyaType(csv.get_int())
            roll_type = core.RollType(csv.get_int())
            event_token_1_uu = csv.get_str()
            event_token_2_total = csv.get_str()
            name = csv.get_str()
            if gatya_type not in events:
                events[gatya_type] = {}
            events[gatya_type][roll_type] = GatyaTrack(
                roll_type, event_token_1_uu, event_token_2_total, name
            )

        for gatya_type, event in events.items():
            data[gatya_type] = GatyaTrackEvents(gatya_type, event)
        return GatyaTrackData(data)

    def to_game_data(self, game_data: "core.GamePacks") -> None:
        """Write the GatyaTrackData to the game data.

        Args:
            game_data (core.GamePacks): The game data.
        """
        file = game_data.find_file(
            GatyaTrackData.get_file_name(game_data.localizable.get_lang())
        )
        if file is None:
            return
        csv = core.CSV(file.dec_data, "\t")

        remaining_events = self.data.copy()
        for i, line in enumerate(csv.lines[1:]):
            gatya_type = core.GatyaType(int(line[0]))
            roll_type = core.RollType(int(line[1]))
            event = remaining_events.get(gatya_type)
            if event is None:
                continue
            track_event = event.events.get(roll_type)
            if track_event is None:
                continue
            if track_event.event_token_1_uu is not None:
                line[2] = str(track_event.event_token_1_uu)
            if track_event.event_token_2_total is not None:
                line[3] = str(track_event.event_token_2_total)
            if track_event.name is not None:
                line[4] = str(track_event.name)
            csv.lines[i + 1] = line
            del remaining_events[gatya_type]
        for gatya_type, event in remaining_events.items():
            for roll_type, track_event in event.events.items():
                csv.lines.append(
                    [
                        str(gatya_type),
                        str(roll_type),
                        str(track_event.event_token_1_uu or ""),
                        str(track_event.event_token_2_total or ""),
                        str(track_event.name or ""),
                    ]
                )

        game_data.set_file(
            GatyaTrackData.get_file_name(game_data.localizable.get_lang()),
            csv.to_data(),
        )


class LegendStageTrack:
    """A LegendStageTrack event."""

    def __init__(
        self,
        stage_index: int,
        event_token: Optional[str] = None,
    ):
        """Create a LegendStageTrack clear event.

        Args:
            stage_index (int): The stage index.
            event_token (Optional[str], optional): The event token. Defaults to None.
        """
        self.stage_index = stage_index
        self.event_token = event_token

    def apply_dict(self, dict_data: dict[str, Any]):
        """Apply the mod edits to the LegendStageTrack.

        Args:
            dict_data (dict[str, Any]): The mod edits.
        """
        self.event_token = dict_data.get("event_token", self.event_token)

    @staticmethod
    def create_empty(stage_index: int) -> "LegendStageTrack":
        """Create an empty LegendStageTrack.

        Args:
            stage_index (int): The stage index.

        Returns:
            LegendStageTrack: The empty LegendStageTrack.
        """
        return LegendStageTrack(stage_index)


class LegendStageTrackEvents:
    """A LegendStageTrack event."""

    def __init__(self, map_id: int, events: dict[int, LegendStageTrack]):
        """Create a LegendStageTrackEvents.

        Args:
            map_id (int): The map id.
            events (dict[int, LegendStageTrack]): The events.
        """
        self.map_id = map_id
        self.events = events

    def apply_dict(self, dict_data: dict[str, Any]):
        """Apply the mod edits to the LegendStageTrackEvents.

        Args:
            dict_data (dict[str, Any]): The mod edits.
        """
        events = dict_data.get("events")
        if events is not None:
            current_events = self.events.copy()
            modded_events = core.ModEditDictHandler(events, current_events).get_dict(
                convert_int=True
            )
            for id, modded_event in modded_events.items():
                event = self.events.get(id)
                if event is None:
                    event = LegendStageTrack.create_empty(
                        id,
                    )
                event.apply_dict(modded_event)
                current_events[id] = event
            self.events = current_events

    @staticmethod
    def create_empty(map_id: int) -> "LegendStageTrackEvents":
        """Create an empty LegendStageTrackEvents.

        Args:
            map_id (int): The map id.

        Returns:
            LegendStageTrackEvents: The empty LegendStageTrackEvents.
        """
        return LegendStageTrackEvents(map_id, {})


class LegendStageTrackData(core.EditableClass):
    """A LegendStageTrackData."""

    def __init__(self, events: dict[int, LegendStageTrackEvents]):
        """Create a LegendStageTrackData.

        Args:
            events (dict[int, LegendStageTrackEvents]): The events.
        """
        self.data = events
        super().__init__(self.data)

    @staticmethod
    def get_file_name(lang: str) -> str:
        """Get the file name for the LegendStageTrackData.

        Args:
            lang (str): The language.

        Returns:
            str: The file name.
        """
        return f"AdjustTrackEventToken_LegendStageClear_{lang}.tsv"

    @staticmethod
    def from_game_data(game_data: "core.GamePacks") -> "LegendStageTrackData":
        """Get the LegendStageTrackData from the game data.

        Args:
            game_data (core.GamePacks): The game data.

        Returns:
            LegendStageTrackData: The LegendStageTrackData.
        """
        file = game_data.find_file(
            LegendStageTrackData.get_file_name(game_data.localizable.get_lang())
        )
        if file is None:
            return LegendStageTrackData.create_empty()
        csv_data = core.CSV(file.dec_data, "\t")
        data: dict[int, LegendStageTrackEvents] = {}
        events: dict[int, dict[int, LegendStageTrack]] = {}
        for line in csv_data.lines:
            map_id = int(line[0])
            stage_index = int(line[1])
            event_token = line[2]
            if map_id not in events:
                events[map_id] = {}
            events[map_id][stage_index] = LegendStageTrack(stage_index, event_token)
        for map_id, event in events.items():
            data[map_id] = LegendStageTrackEvents(map_id, event)
        return LegendStageTrackData(data)

    def to_game_data(self, game_data: "core.GamePacks") -> None:
        """Write the LegendStageTrackData to the game data.

        Args:
            game_data (core.GamePacks): The game data.
        """
        file = game_data.find_file(
            LegendStageTrackData.get_file_name(game_data.localizable.get_lang())
        )
        if file is None:
            return
        csv_data = core.CSV(file.dec_data, "\t")

        remaining_events = self.data.copy()
        for i, line in enumerate(csv_data.lines):
            map_id = int(line[0])
            stage_index = int(line[1])
            event = remaining_events.get(map_id)
            if event is None:
                continue
            track_event = event.events.get(stage_index)
            if track_event is None:
                continue
            if track_event.event_token is not None:
                line[2] = str(track_event.event_token)
            csv_data.lines[i] = line
            del remaining_events[map_id]
        for map_id, event in remaining_events.items():
            for stage_index, track_event in event.events.items():
                csv_data.lines.append(
                    [
                        str(map_id),
                        str(stage_index),
                        str(track_event.event_token or ""),
                    ]
                )

        game_data.set_file(
            LegendStageTrackData.get_file_name(game_data.localizable.get_lang()),
            csv_data.to_data(),
        )

    @staticmethod
    def create_empty() -> "LegendStageTrackData":
        """Create an empty LegendStageTrackData.

        Returns:
            LegendStageTrackData: The LegendStageTrackData.
        """
        return LegendStageTrackData({})


class StageClearTrack:
    """A StageClearTrack."""

    def __init__(
        self,
        stage_id: int,
        event_token: Optional[str] = None,
        name: Optional[str] = None,
    ):
        """Create a StageClearTrack event.

        Args:
            stage_id (int): The stage id.
            event_token (Optional[str], optional): The event token. Defaults to None.
            name (Optional[str], optional): The name. Defaults to None.
        """
        self.stage_id = stage_id
        self.event_token = event_token
        self.name = name

    def apply_dict(self, dict_data: dict[str, Any]):
        """Apply the dict data to the StageClearTrack.

        Args:
            dict_data (dict[str, Any]): The dict data.
        """
        self.event_token = dict_data.get("event_token", self.event_token)
        self.name = dict_data.get("name", self.name)

    @staticmethod
    def create_empty(stage_id: int) -> "StageClearTrack":
        """Create an empty StageClearTrack.

        Args:
            stage_id (int): The stage id.

        Returns:
            StageClearTrack: The StageClearTrack.
        """
        return StageClearTrack(stage_id)


class StageClearTrackEvents:
    """StageClearTrackEvents."""

    def __init__(self, chapter_id: int, events: dict[int, StageClearTrack]):
        """Create a StageClearTrackEvents.

        Args:
            chapter_id (int): The chapter id.
            events (dict[int, StageClearTrack]): The events.
        """
        self.chapter_id = chapter_id
        self.events = events

    def apply_dict(self, dict_data: dict[str, Any]):
        """Apply the dict data to the StageClearTrackEvents.

        Args:
            dict_data (dict[str, Any]): The dict data.
        """
        events = dict_data.get("events")
        if events is not None:
            current_events = self.events.copy()
            modded_events = core.ModEditDictHandler(events, current_events).get_dict(
                convert_int=True
            )
            for id, modded_event in modded_events.items():
                event = self.events.get(id)
                if event is None:
                    event = StageClearTrack.create_empty(
                        id,
                    )
                event.apply_dict(modded_event)
                current_events[id] = event
            self.events = current_events

    @staticmethod
    def create_empty(chapter_id: int) -> "StageClearTrackEvents":
        """Create an empty StageClearTrackEvents.

        Args:
            chapter_id (int): The chapter id.

        Returns:
            StageClearTrackEvents: The StageClearTrackEvents.
        """
        return StageClearTrackEvents(chapter_id, {})


class StageClearTrackData(core.EditableClass):
    """StageClearTrackData."""

    def __init__(self, events: dict[int, StageClearTrackEvents]):
        """Create a StageClearTrackData.

        Args:
            events (dict[int, StageClearTrackEvents]): The events.
        """
        self.data = events
        super().__init__(self.data)

    @staticmethod
    def get_file_name(lang: str) -> str:
        """Get the file name.

        Args:
            lang (str): The language.

        Returns:
            str: The file name.
        """
        return f"AdjustTrackEventToken_StageClear_{lang}.tsv"

    @staticmethod
    def from_game_data(game_data: "core.GamePacks") -> "StageClearTrackData":
        """Get the StageClearTrackData from the game data.

        Args:
            game_data (core.GamePacks): The game data.

        Returns:
            StageClearTrackData: The StageClearTrackData.
        """
        file = game_data.find_file(
            StageClearTrackData.get_file_name(game_data.localizable.get_lang())
        )
        if file is None:
            return StageClearTrackData.create_empty()
        csv_data = core.CSV(file.dec_data, "\t")
        data: dict[int, StageClearTrackEvents] = {}
        events: dict[int, dict[int, StageClearTrack]] = {}
        for line in csv_data.lines:
            chapter_id = int(line[0])
            stage_id = int(line[1])
            event_token = line[2]
            if chapter_id not in events:
                events[chapter_id] = {}
            events[chapter_id][stage_id] = StageClearTrack(stage_id, event_token)
        for chapter_id, event in events.items():
            data[chapter_id] = StageClearTrackEvents(chapter_id, event)
        return StageClearTrackData(data)

    def to_game_data(self, game_data: "core.GamePacks") -> None:
        """Write the StageClearTrackData to the game data.

        Args:
            game_data (core.GamePacks): The game data.
        """
        file = game_data.find_file(
            StageClearTrackData.get_file_name(game_data.localizable.get_lang())
        )
        if file is None:
            return
        csv_data = core.CSV(file.dec_data, "\t")

        remaining_events = self.data.copy()
        for i, line in enumerate(csv_data.lines):
            chapter_id = int(line[0])
            stage_id = int(line[1])
            event = remaining_events.get(chapter_id)
            if event is None:
                continue
            event = event.events.get(stage_id)
            if event is None:
                continue
            if event.event_token is not None:
                line[2] = event.event_token
            del remaining_events[chapter_id]
            csv_data.lines[i] = line

        for chapter_id, event in remaining_events.items():
            for stage_id, event in event.events.items():
                csv_data.lines.append(
                    [str(chapter_id), str(stage_id), event.event_token or ""]
                )

        game_data.set_file(
            StageClearTrackData.get_file_name(game_data.localizable.get_lang()),
            csv_data.to_data(),
        )

    @staticmethod
    def create_empty() -> "StageClearTrackData":
        """Create an empty StageClearTrackData.

        Returns:
            StageClearTrackData: The StageClearTrackData.
        """
        return StageClearTrackData({})


class PurchaseEvent:
    """Represents a PurchaseEvent."""

    def __init__(
        self,
        product_id: str,
        event_token: Optional[str] = None,
        name: Optional[str] = None,
    ):
        """Create a PurchaseEvent.

        Args:
            product_id (str): The product id.
            event_token (Optional[str], optional): The event token. Defaults to None.
            name (Optional[str], optional): The name of the event. Defaults to None.
        """
        self.product_id = product_id
        self.event_token = event_token
        self.name = name

    def apply_dict(self, dict_data: dict[str, Any]):
        """Apply the dict data to the PurchaseEvent.

        Args:
            dict_data (dict[str, Any]): The dict data.
        """
        self.event_token = dict_data.get("event_token", self.event_token)
        self.name = dict_data.get("name", self.name)

    @staticmethod
    def create_empty(product_id: str) -> "PurchaseEvent":
        """Create an empty PurchaseEvent.

        Args:
            product_id (str): The product id.

        Returns:
            PurchaseEvent: The empty PurchaseEvent.
        """
        return PurchaseEvent(product_id)


class PurchaseTrackData(core.EditableClass):
    """Represents the PurchaseTrackData."""

    def __init__(self, events: dict[str, PurchaseEvent]):
        """Create a PurchaseTrackData.

        Args:
            events (dict[str, PurchaseEvent]): The events.
        """
        self.data = events
        super().__init__(self.data)

    @staticmethod
    def get_file_name(lang: str) -> str:
        """Get the file name for the PurchaseTrackData.

        Args:
            lang (str): The language.

        Returns:
            str: The file name.
        """
        return f"AdjustTrackEventToken_Purchase_{lang}.tsv"

    @staticmethod
    def from_game_data(game_data: "core.GamePacks") -> "PurchaseTrackData":
        """Get the PurchaseTrackData from the game data.

        Args:
            game_data (core.GamePacks): The game data.

        Returns:
            PurchaseTrackData: The PurchaseTrackData.
        """
        file = game_data.find_file(
            PurchaseTrackData.get_file_name(game_data.localizable.get_lang())
        )
        if file is None:
            return PurchaseTrackData.create_empty()
        csv_data = core.CSV(file.dec_data, "\t")
        data: dict[str, PurchaseEvent] = {}
        for line in csv_data.lines:
            product_id = line[0]
            event_token = line[1]
            name = line[2]
            data[product_id] = PurchaseEvent(product_id, event_token, name)
        return PurchaseTrackData(data)

    def to_game_data(self, game_data: "core.GamePacks") -> None:
        """Write the PurchaseTrackData to the game data.

        Args:
            game_data (core.GamePacks): The game data.
        """
        file = game_data.find_file(
            PurchaseTrackData.get_file_name(game_data.localizable.get_lang())
        )
        if file is None:
            return
        csv_data = core.CSV(file.dec_data, "\t")

        remaining_events = self.data.copy()
        for line in csv_data.lines:
            product_id = line[0]
            event = remaining_events.get(product_id)
            if event is None:
                continue
            if event.event_token is not None:
                line[1] = str(event.event_token)
            if event.name is not None:
                line[2] = str(event.name)
            del remaining_events[product_id]
        for product_id, event in remaining_events.items():
            csv_data.lines.append(
                [
                    str(product_id),
                    str(event.event_token or ""),
                    str(event.name or ""),
                ]
            )

        game_data.set_file(
            PurchaseTrackData.get_file_name(game_data.localizable.get_lang()),
            csv_data.to_data(),
        )

    @staticmethod
    def create_empty() -> "PurchaseTrackData":
        """Create an empty PurchaseTrackData.

        Returns:
            PurchaseTrackData: The empty PurchaseTrackData.
        """
        return PurchaseTrackData({})


class UserRankTrack:
    """Represents a UserRankTrack."""

    def __init__(
        self,
        user_rank: int,
        event_token: Optional[str] = None,
    ):
        """Create a UserRankTrack.

        Args:
            user_rank (int): The user rank.
            event_token (Optional[str], optional): The event token. Defaults to None.
        """
        self.user_rank = user_rank
        self.event_token = event_token

    def apply_dict(self, dict_data: dict[str, Any]):
        """Apply the dict data to the UserRankTrack.

        Args:
            dict_data (dict[str, Any]): The dict data.
        """
        self.event_token = dict_data.get("event_token", self.event_token)

    @staticmethod
    def create_empty(user_rank: int) -> "UserRankTrack":
        """Create an empty UserRankTrack.

        Args:
            user_rank (int): The user rank.

        Returns:
            UserRankTrack: The empty UserRankTrack.
        """
        return UserRankTrack(user_rank)


class UserRankTrackData(core.EditableClass):
    """Represents the UserRankTrackData."""

    def __init__(self, events: dict[int, UserRankTrack]):
        """Create a UserRankTrackData.

        Args:
            events (dict[int, UserRankTrack]): The events.
        """
        self.data = events
        super().__init__(self.data)

    @staticmethod
    def get_file_name(lang: str) -> str:
        """Get the file name for the UserRankTrackData.

        Args:
            lang (str): The language.

        Returns:
            str: The file name.
        """
        return f"AdjustTrackEventToken_UserRank_{lang}.tsv"

    @staticmethod
    def from_game_data(game_data: "core.GamePacks") -> "UserRankTrackData":
        """Get the UserRankTrackData from the game data.

        Args:
            game_data (core.GamePacks): The game data.

        Returns:
            UserRankTrackData: The UserRankTrackData.
        """
        file = game_data.find_file(
            UserRankTrackData.get_file_name(game_data.localizable.get_lang())
        )
        if file is None:
            return UserRankTrackData.create_empty()
        csv_data = core.CSV(file.dec_data, "\t")
        data: dict[int, UserRankTrack] = {}
        for line in csv_data.lines:
            user_rank = int(line[0])
            event_token = line[1]
            data[user_rank] = UserRankTrack(user_rank, event_token)
        return UserRankTrackData(data)

    def to_game_data(self, game_data: "core.GamePacks") -> None:
        """Write the UserRankTrackData to the game data.

        Args:
            game_data (core.GamePacks): The game data.
        """
        file = game_data.find_file(
            UserRankTrackData.get_file_name(game_data.localizable.get_lang())
        )
        if file is None:
            return
        csv_data = core.CSV(file.dec_data, "\t")

        remaining_events = self.data.copy()
        for line in csv_data.lines:
            user_rank = int(line[0])
            event = remaining_events.get(user_rank)
            if event is None:
                continue
            if event.event_token is not None:
                line[1] = str(event.event_token)
            del remaining_events[user_rank]
        for user_rank, event in remaining_events.items():
            csv_data.lines.append(
                [
                    str(user_rank),
                    str(event.event_token or ""),
                ]
            )

        game_data.set_file(
            UserRankTrackData.get_file_name(game_data.localizable.get_lang()),
            csv_data.to_data(),
        )

    @staticmethod
    def create_empty() -> "UserRankTrackData":
        """Create an empty UserRankTrackData.

        Returns:
            UserRankTrackData: The empty UserRankTrackData.
        """
        return UserRankTrackData({})


class AdjustData(core.EditableClass):
    """Represents the AdjustData."""

    def __init__(
        self,
        gatya_track_data: Optional[GatyaTrackData] = None,
        legend_stage_track_data: Optional[LegendStageTrackData] = None,
        stage_clear_track_data: Optional[StageClearTrackData] = None,
        purchase_track_data: Optional[PurchaseTrackData] = None,
        user_rank_track_data: Optional[UserRankTrackData] = None,
    ):
        """Create an AdjustData.

        Args:
            gatya_track_data (Optional[GatyaTrackData], optional): GatyaTrackData. Defaults to None.
            legend_stage_track_data (Optional[LegendStageTrackData], optional): LegendStageTrackData. Defaults to None.
            stage_clear_track_data (Optional[StageClearTrackData], optional): StageClearTrackData. Defaults to None.
            purchase_track_data (Optional[PurchaseTrackData], optional): PurchaseTrackData. Defaults to None.
            user_rank_track_data (Optional[UserRankTrackData], optional): UserRankTrackData. Defaults to None.
        """
        self.gatya_track_data = gatya_track_data
        self.legend_stage_track_data = legend_stage_track_data
        self.stage_clear_track_data = stage_clear_track_data
        self.purchase_track_data = purchase_track_data
        self.user_rank_track_data = user_rank_track_data
        super().__init__()

    def get_gatya_track_data(self) -> GatyaTrackData:
        """Get the GatyaTrackData.

        Returns:
            GatyaTrackData: The GatyaTrackData.
        """
        if self.gatya_track_data is None:
            return GatyaTrackData.create_empty()
        return self.gatya_track_data

    def get_legend_stage_track_data(self) -> LegendStageTrackData:
        """Get the LegendStageTrackData.

        Returns:
            LegendStageTrackData: The LegendStageTrackData.
        """
        if self.legend_stage_track_data is None:
            return LegendStageTrackData.create_empty()
        return self.legend_stage_track_data

    def get_stage_clear_track_data(self) -> StageClearTrackData:
        """Get the StageClearTrackData.

        Returns:
            StageClearTrackData: The StageClearTrackData.
        """
        if self.stage_clear_track_data is None:
            return StageClearTrackData.create_empty()
        return self.stage_clear_track_data

    def get_purchase_track_data(self) -> PurchaseTrackData:
        """Get the PurchaseTrackData.

        Returns:
            PurchaseTrackData: The PurchaseTrackData.
        """
        if self.purchase_track_data is None:
            return PurchaseTrackData.create_empty()
        return self.purchase_track_data

    def get_user_rank_track_data(self) -> UserRankTrackData:
        """Get the UserRankTrackData.

        Returns:
            UserRankTrackData: The UserRankTrackData.
        """
        if self.user_rank_track_data is None:
            return UserRankTrackData.create_empty()
        return self.user_rank_track_data

    def apply_dict(
        self,
        dict_data: dict[str, Any],
        mod_edit_key: str,
        convert_int: bool = True,
    ):
        """Apply a dict to the AdjustData.

        Args:
            dict_data (dict[str, Any]): The dict.
        """
        adjust_data = dict_data.get(mod_edit_key)
        if adjust_data is None:
            return

        self.get_gatya_track_data().apply_dict(adjust_data, "gatya_track_data")
        self.get_legend_stage_track_data().apply_dict(
            adjust_data, "legend_stage_track_data"
        )
        self.get_stage_clear_track_data().apply_dict(
            adjust_data, "stage_clear_track_data"
        )
        self.get_purchase_track_data().apply_dict(adjust_data, "purchase_track_data")
        self.get_user_rank_track_data().apply_dict(adjust_data, "user_rank_track_data")

    @staticmethod
    def from_game_data(game_data: "core.GamePacks") -> "AdjustData":
        """Create an AdjustData from a GamePacks.

        Args:
            game_data (core.GamePacks): The GamePacks.

        Returns:
            AdjustData: The AdjustData.
        """
        if game_data.adjust_data is not None:
            return game_data.adjust_data
        gatya_track_data = GatyaTrackData.from_game_data(game_data)
        legend_stage_track_data = LegendStageTrackData.from_game_data(game_data)
        stage_clear_track_data = StageClearTrackData.from_game_data(game_data)
        purchase_track_data = PurchaseTrackData.from_game_data(game_data)
        user_rank_track_data = UserRankTrackData.from_game_data(game_data)
        adjust_data = AdjustData(
            gatya_track_data,
            legend_stage_track_data,
            stage_clear_track_data,
            purchase_track_data,
            user_rank_track_data,
        )
        game_data.adjust_data = adjust_data
        return adjust_data

    def to_game_data(self, game_data: "core.GamePacks"):
        """Apply the AdjustData to a GamePacks.

        Args:
            game_data (core.GamePacks): The GamePacks.
        """
        if self.gatya_track_data is not None:
            self.gatya_track_data.to_game_data(game_data)
        if self.legend_stage_track_data is not None:
            self.legend_stage_track_data.to_game_data(game_data)
        if self.stage_clear_track_data is not None:
            self.stage_clear_track_data.to_game_data(game_data)
        if self.purchase_track_data is not None:
            self.purchase_track_data.to_game_data(game_data)
        if self.user_rank_track_data is not None:
            self.user_rank_track_data.to_game_data(game_data)

    @staticmethod
    def create_empty() -> "AdjustData":
        """Create an empty AdjustData.

        Returns:
            AdjustData: The empty AdjustData.
        """
        return AdjustData()
