from __future__ import annotations

import json
from typing import Any
import tbcml


class JsonFile:
    def __init__(self, data: tbcml.Data):
        self.json = json.loads(data.data)

    @staticmethod
    def from_path(path: tbcml.Path) -> JsonFile:
        return JsonFile(path.read())

    @staticmethod
    def from_object(js: Any) -> JsonFile:
        return JsonFile(tbcml.Data(json.dumps(js)))

    @staticmethod
    def from_data(data: tbcml.Data) -> JsonFile:
        return JsonFile(data)

    def to_data(self) -> tbcml.Data:
        return tbcml.Data(json.dumps(self.json, indent=4))

    def to_data_request(self) -> tbcml.Data:
        return tbcml.Data(json.dumps(self.json)).replace(
            tbcml.Data(" "), tbcml.Data("")
        )

    def save(self, path: tbcml.Path) -> None:
        path.write(self.to_data())

    def get_json(self) -> Any:
        return self.json

    def get(self, key: str) -> Any:
        return self.json[key]

    def set(self, key: str, value: Any) -> None:
        self.json[key] = value

    def __str__(self) -> str:
        return str(self.json)

    def __getitem__(self, key: str) -> Any:
        return self.json[key]

    def __setitem__(self, key: str, value: Any) -> None:
        self.json[key] = value
