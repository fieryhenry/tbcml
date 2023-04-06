from typing import Optional
from bcml.core import io, game_version, country_code


class FridaScript:
    def __init__(
        self,
        arc: str,
        cc: "country_code.CountryCode",
        gv: "game_version.GameVersion",
        script: str,
        name: Optional[str] = None,
    ):
        self.arc = arc
        self.cc = cc
        self.gv = gv
        self.script = script
        if name is None:
            self.name = arc
        else:
            self.name = name

    def get_script_data(self) -> "io.data.Data":
        return io.data.Data(self.script)

    def add_to_zip(self, zip: "io.zip.Zip"):
        zip.add_file(io.path.Path(f"scripts/{self.arc}.js"), self.get_script_data())

    @staticmethod
    def from_zip(
        zip: "io.zip.Zip",
        arc: str,
        cc: "country_code.CountryCode",
        gv: "game_version.GameVersion",
    ) -> "FridaScript":
        file = zip.get_file(io.path.Path(f"scripts/{arc}.js"))
        if file is None:
            raise ValueError("File not found in zip.")
        return FridaScript(arc, cc, gv, file.to_str())


class Scripts:
    def __init__(
        self,
        scripts: list["FridaScript"],
        cc: Optional["country_code.CountryCode"] = None,
        gv: Optional["game_version.GameVersion"] = None,
    ):
        self.scripts = scripts
        if len(scripts) > 0:
            self.cc = scripts[0].cc
            self.gv = scripts[0].gv
        else:
            if cc is None or gv is None:
                raise ValueError(
                    "Country code and game version must be specified if no scripts are provided."
                )
            self.cc = cc
            self.gv = gv
        self.validate_scripts()

    def is_valid_script(self, script: "FridaScript") -> bool:
        return script.cc == self.cc and script.gv == self.gv

    def validate_scripts(self):
        for script in self.scripts:
            if not self.is_valid_script(script):
                raise ValueError(
                    "Script is not valid for this game version and country code."
                )

    def add_script(self, script: "FridaScript"):
        if self.is_valid_script(script):
            self.scripts.append(script)
        else:
            raise ValueError(
                "Script is not valid for this game version and country code."
            )

    def remove_script(self, script: "FridaScript"):
        if script in self.scripts:
            self.scripts.remove(script)
        else:
            raise ValueError("Script is not in this Scripts object.")

    def get_script(self, arc: str) -> Optional["FridaScript"]:
        for script in self.scripts:
            if script.arc == arc:
                return script
        return None

    def combine_scripts(self, arc: str) -> "io.data.Data":
        script_text = ""
        for script in self.scripts:
            if script.arc == arc:
                script_text += f"// {'-'*50}\r\n// {script.name}\r\n// {'-'*50}\r\n\r\n"
                script_text += script.script
        return io.data.Data(script_text)

    def add_to_zip(self, zip: "io.zip.Zip"):
        arcs: set[str] = set()
        for script in self.scripts:
            script.add_to_zip(zip)
            arcs.add(script.arc)
        json_data = {
            "arcs": list(arcs),
        }
        json = io.json_file.JsonFile.from_object(json_data)
        zip.add_file(io.path.Path("scripts/scripts.json"), json.to_data())

    @staticmethod
    def from_zip(
        zip: "io.zip.Zip",
        cc: "country_code.CountryCode",
        gv: "game_version.GameVersion",
    ) -> "Scripts":
        file = zip.get_file(io.path.Path("scripts/scripts.json"))
        if file is None:
            raise ValueError("File not found in zip.")
        json = io.json_file.JsonFile.from_data(file)
        json_data = json.get_json()
        arcs = json_data["arcs"]
        scripts: list[FridaScript] = []
        for arc in arcs:
            scripts.append(FridaScript.from_zip(zip, arc, cc, gv))
        return Scripts(scripts, cc, gv)

    def import_scripts(self, other: "Scripts"):
        for script in other.scripts:
            if self.is_valid_script(script):
                self.add_script(script)

    def get_used_arcs(self) -> list[str]:
        arcs: set[str] = set()
        for script in self.scripts:
            arcs.add(script.arc)
        return list(arcs)
