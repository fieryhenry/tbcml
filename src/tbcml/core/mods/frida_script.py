from typing import Any, Optional
from tbcml import core


class FridaScript:
    def __init__(
        self,
        arc: str,
        cc: "core.CountryCode",
        gv: "core.GameVersion",
        script: str,
        name: str,
        mod: "core.Mod",
    ):
        self.arc = arc
        self.cc = cc
        self.gv = gv
        self.script = script
        self.name = name
        self.mod = mod

    @staticmethod
    def get_file_path(arc: str, name: str) -> "core.Path":
        return core.Path(f"scripts/{arc}/{name}.json")

    def add_to_zip(self, zip: "core.Zip"):
        json_data = self.serialize()
        json_file = core.JsonFile.from_object(json_data)
        zip.add_file(
            self.get_file_path(self.arc, self.name),
            json_file.to_data(),
        )

    def serialize(self) -> dict[str, Any]:
        return {
            "arc": self.arc,
            "cc": self.cc.get_code(),
            "gv": self.gv.to_string(),
            "script": self.script,
            "name": self.name,
        }

    @staticmethod
    def deserialize(data: dict[str, Any], mod: "core.Mod") -> "FridaScript":
        return FridaScript(
            data["arc"],
            core.CountryCode.from_code(data["cc"]),
            core.GameVersion.from_string(data["gv"]),
            data["script"],
            data["name"],
            mod,
        )

    @staticmethod
    def from_zip(
        zip: "core.Zip",
        mod: "core.Mod",
        arc: str,
        name: str,
    ) -> "FridaScript":
        file = zip.get_file(FridaScript.get_file_path(arc, name))
        if file is None:
            raise ValueError("File not found in zip.")
        json_file = core.JsonFile.from_data(file)
        return FridaScript.deserialize(json_file.get_json(), mod)


class FridaScripts:
    def __init__(
        self,
        scripts: list["FridaScript"],
    ):
        self.scripts = scripts

    def is_valid_script(
        self,
        script: "FridaScript",
        cc: "core.CountryCode",
        gv: "core.GameVersion",
    ) -> bool:
        return script.cc == cc and script.gv == gv

    def validate_scripts(self, cc: "core.CountryCode", gv: "core.GameVersion"):
        new_scripts: list["FridaScript"] = []
        for script in self.scripts:
            if self.is_valid_script(script, cc, gv):
                new_scripts.append(script)
        self.scripts = new_scripts

    def is_empty(self) -> bool:
        return len(self.scripts) == 0

    def add_script(self, script: "FridaScript"):
        self.scripts.append(script)

    def remove_script(self, script: "FridaScript"):
        if script in self.scripts:
            self.scripts.remove(script)

    def get_script(self, arc: str) -> Optional["FridaScript"]:
        for script in self.scripts:
            if script.arc == arc:
                return script
        return None

    def add_scripts(self, scripts: "FridaScripts"):
        for script in scripts.scripts:
            self.add_script(script)

    def get_base_script(self):
        return core.Path("base_script.js", True).read()

    def combine_scripts(self, arc: str) -> "core.Data":
        script_text = self.get_base_script() + "\r\n"
        for script in self.scripts:
            if script.arc == arc:
                script_text += f"// {'-'*50}\r\n// {script.name} from mod {script.mod.name} by {script.mod.author}\r\n// {'-'*50}\r\n\r\n"
                script_text += script.script
        return core.Data(script_text)

    def add_to_zip(self, zip: "core.Zip"):
        arcs: dict[str, list[str]] = {}
        for script in self.scripts:
            script.add_to_zip(zip)
            if script.arc not in arcs:
                arcs[script.arc] = []
            arcs[script.arc].append(script.name)
        json_data = {
            "arcs": arcs,
        }
        json = core.JsonFile.from_object(json_data)
        zip.add_file(core.Path("scripts/scripts.json"), json.to_data())

    @staticmethod
    def from_zip(
        zip: "core.Zip",
        mod: "core.Mod",
    ) -> "FridaScripts":
        file = zip.get_file(core.Path("scripts/scripts.json"))
        if file is None:
            raise ValueError("File not found in zip.")
        json = core.JsonFile.from_data(file)
        json_data = json.get_json()
        arcs = json_data["arcs"]
        scripts: list["FridaScript"] = []
        for arc in arcs:
            for name in arcs[arc]:
                scripts.append(FridaScript.from_zip(zip, mod, arc, name))
        return FridaScripts(scripts)

    def import_scripts(self, other: "FridaScripts"):
        for script in other.scripts:
            self.add_script(script)

    def get_used_arcs(self) -> list[str]:
        arcs: set[str] = set()
        for script in self.scripts:
            arcs.add(script.arc)
        return list(arcs)
