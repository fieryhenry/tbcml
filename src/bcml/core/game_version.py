from typing import Any, Optional
from bcml.core import io, country_code

class GameVersion:
    def __init__(self, game_version: int):
        self.game_version = game_version
    
    def to_string(self) -> str:
        split_gv = str(self.game_version).zfill(6)
        split_gv = [str(int(split_gv[i : i + 2])) for i in range(0, len(split_gv), 2)]
        return ".".join(split_gv)
    
    def get_parts_zfill(self) -> list[str]:
        return [part.zfill(2) for part in self.to_string().split(".")]
    
    def get_parts(self) -> list[int]:
        return [int(part) for part in self.get_parts_zfill()]
    
    def format(self) -> str:
        parts = self.get_parts_zfill()
        string = ""
        for part in parts:
            string += f"{part}."
        return f"{string[:-1]}"
    
    def __str__(self) -> str:
        return self.to_string()
    
    def __repr__(self) -> str:
        return f"game_version({self.game_version}) {self.to_string()}"
    
    @staticmethod
    def read(data: "io.data.Data") -> "GameVersion":
        return GameVersion(data.read_int())
    
    def write(self, data: "io.data.Data"):
        data.write_int(self.game_version)
    
    def serialize(self) -> dict[str, Any]:
        return {"game_version": self.game_version}
    
    @staticmethod
    def deserialize(game_version: dict[str, Any]) -> "GameVersion":
        return GameVersion(game_version["game_version"])
    
    @staticmethod
    def from_string(game_version: str) -> "GameVersion":
        split_gv = game_version.split(".")
        if len(split_gv) == 2:
            split_gv.append("0")
        final = ""
        for split in split_gv:
            final += split.zfill(2)
        return GameVersion(int(final))
    
    @staticmethod
    def from_string_latest(game_version: str, country_code: "country_code.CountryCode") -> "GameVersion":
        if game_version == "latest":
            gv = GameVersion.get_latest_version(country_code)
            if gv is None:
                return GameVersion.from_string("1.0.0")
            return gv
        else:
            return GameVersion.from_string(game_version)
    
    @staticmethod
    def get_latest_version(country_code: "country_code.CountryCode") -> Optional["GameVersion"]:
        return io.apk.Apk.get_latest_version(country_code)
        
    def __eq__(self, other: Any) -> bool:
        if isinstance(other, GameVersion):
            return self.game_version == other.game_version
        elif isinstance(other, int):
            return self.game_version == other
        elif isinstance(other, str):
            return self.game_version == GameVersion.from_string(other).game_version
        else:
            return False
        
    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)
    
    def __lt__(self, other: Any) -> bool:
        if isinstance(other, GameVersion):
            return self.game_version < other.game_version
        elif isinstance(other, int):
            return self.game_version < other
        elif isinstance(other, str):
            return self.game_version < GameVersion.from_string(other).game_version
        else:
            return False
        
    def __le__(self, other: Any) -> bool:
        return self.__lt__(other) or self.__eq__(other)
    
    def __gt__(self, other: Any) -> bool:
        return not self.__le__(other)
    
    def __ge__(self, other: Any) -> bool:
        return not self.__lt__(other)
