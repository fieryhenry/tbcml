from typing import Optional
from bcml.core import io, game_version, country_code, mods


class FridaScript:
    def __init__(
        self,
        arc: str,
        cc: "country_code.CountryCode",
        gv: "game_version.GameVersion",
        script: str,
        name: str,
        mod: "mods.bc_mod.Mod",
    ):
        self.arc = arc
        self.cc = cc
        self.gv = gv
        self.script = script
        self.name = name
        self.mod = mod

    def get_script_data(self) -> "io.data.Data":
        return io.data.Data(self.script)

    @staticmethod
    def get_file_path(arc: str, name: str) -> "io.path.Path":
        return io.path.Path(f"scripts/{arc}/{name}.js")

    def add_to_zip(self, zip: "io.zip.Zip"):
        zip.add_file(
            self.get_file_path(self.arc, self.name),
            self.get_script_data(),
        )

    @staticmethod
    def from_zip(
        zip: "io.zip.Zip",
        arc: str,
        cc: "country_code.CountryCode",
        gv: "game_version.GameVersion",
        mod: "mods.bc_mod.Mod",
        name: str,
    ) -> "FridaScript":
        file = zip.get_file(FridaScript.get_file_path(arc, name))
        if file is None:
            raise ValueError("File not found in zip.")
        return FridaScript(arc, cc, gv, file.to_str(), name, mod)


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

    def get_base_script(self):
        return """'use strict';

// This part of the script is automatically generated by bcml.

function logError(message) {
    Java.perform(function () {
        var Log = Java.use("android.util.Log");
        Log.e("bcml", message);
        console.error(message);
    });
}
function logWarning(message) {
    Java.perform(function () {
        var Log = Java.use("android.util.Log");
        Log.w("bcml", message);
        console.warn(message);
    });
}
function logInfo(message) {
    Java.perform(function () {
        var Log = Java.use("android.util.Log");
        Log.i("bcml", message);
        console.info(message);
    });
}
function logVerbose(message) {
    Java.perform(function () {
        var Log = Java.use("android.util.Log");
        Log.v("bcml", message);
        console.log(message);
    });
}
function logDebug(message) {
    Java.perform(function () {
        var Log = Java.use("android.util.Log");
        Log.d("bcml", message);
        console.log(message);
    });
}
function log(message, level = "info") {
    switch (level) {
        case "error":
            logError(message);
            break;
        case "warning":
            logWarning(message);
            break;
        case "info":
            logInfo(message);
            break;
        case "verbose":
            logVerbose(message);
            break;
        case "debug":
            logDebug(message);
            break;
        default:
            logInfo(message);
            break;
    }
}

log("Script loaded successfully.");

function getBaseAddress() {
    return Module.findBaseAddress("libnative-lib.so").add(4096); // offset due to libgadget being added
}

function readStdString(address) {
    const isTiny = (address.readU8() & 1) === 0;
    if (isTiny) {
        return address.add(1).readUtf8String();
    }

    return address.add(2 * Process.pointerSize).readUtf8String();
}

// Mod scripts goes here.
"""

    def combine_scripts(self, arc: str) -> "io.data.Data":
        script_text = self.get_base_script() + "\r\n"
        for script in self.scripts:
            if script.arc == arc:
                script_text += f"// {'-'*50}\r\n// {script.name} from mod {script.mod.name} by {script.mod.author}\r\n// {'-'*50}\r\n\r\n"
                script_text += script.script
        return io.data.Data(script_text)

    def add_to_zip(self, zip: "io.zip.Zip"):
        arcs: dict[str, list[str]] = {}
        for script in self.scripts:
            script.add_to_zip(zip)
            if script.arc not in arcs:
                arcs[script.arc] = []
            arcs[script.arc].append(script.name)
        json_data = {
            "arcs": arcs,
        }
        json = io.json_file.JsonFile.from_object(json_data)
        zip.add_file(io.path.Path("scripts/scripts.json"), json.to_data())

    @staticmethod
    def from_zip(
        zip: "io.zip.Zip",
        cc: "country_code.CountryCode",
        gv: "game_version.GameVersion",
        mod: "mods.bc_mod.Mod",
    ) -> "Scripts":
        file = zip.get_file(io.path.Path("scripts/scripts.json"))
        if file is None:
            raise ValueError("File not found in zip.")
        json = io.json_file.JsonFile.from_data(file)
        json_data = json.get_json()
        arcs = json_data["arcs"]
        scripts: list["FridaScript"] = []
        for arc in arcs:
            for name in arcs[arc]:
                scripts.append(FridaScript.from_zip(zip, arc, cc, gv, mod, name))
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
