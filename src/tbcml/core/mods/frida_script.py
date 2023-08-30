"""Module for handling Frida scripts"""

from typing import Any, Optional
import uuid

from tbcml import core


class FridaScript:
    """A class to represent a Frida script."""

    def __init__(
        self,
        arc: str,
        cc: "core.CountryCode",
        gv: "core.GameVersion",
        script: str,
        name: str,
        id: str,
        mod: "core.Mod",
    ):
        """Initializes a new instance of the FridaScript class.

        Args:
            arc (str): The architecture the script is designed for
            cc (core.CountryCode): The country code the script is designed for
            gv (core.GameVersion): The game version the script is designed for
            script (str): The script code
            name (str): The name of the script
            mod (core.Mod): The mod the script belongs to
        """
        self.arc = arc
        self.cc = cc
        self.gv = gv
        self.script = script
        self.name = name
        self.id = id
        self.mod = mod

    @staticmethod
    def create_id() -> str:
        return str(uuid.uuid4())

    @staticmethod
    def get_file_path(arc: str, id: str) -> "core.Path":
        """Gets the file path for a Frida script.

        Args:
            arc (str): Architecture the script is designed for
            id (str): ID of the script

        Returns:
            core.Path: The file path for the Frida script
        """
        return core.Path(f"scripts/{arc}/{id}.json")

    def add_to_zip(self, zip: "core.Zip"):
        """Adds the Frida script to a zip file.

        Args:
            zip (core.Zip): The zip file to add the Frida script to
        """
        json_data = self.serialize()
        json_file = core.JsonFile.from_object(json_data)
        zip.add_file(
            self.get_file_path(self.arc, self.id),
            json_file.to_data(),
        )

    def serialize(self) -> dict[str, Any]:
        """Serializes the Frida script.

        Returns:
            dict[str, Any]: The serialized Frida script
        """
        return {
            "arc": self.arc,
            "cc": self.cc.get_code(),
            "gv": self.gv.to_string(),
            "script": self.script,
            "name": self.name,
            "id": self.id,
        }

    @staticmethod
    def deserialize(data: dict[str, Any], mod: "core.Mod") -> "FridaScript":
        """Deserializes a Frida script.

        Args:
            data (dict[str, Any]): The serialized Frida script
            mod (core.Mod): The mod the Frida script belongs to

        Returns:
            FridaScript: The deserialized Frida script
        """
        return FridaScript(
            data["arc"],
            core.CountryCode.from_code(data["cc"]),
            core.GameVersion.from_string(data["gv"]),
            data["script"],
            data["name"],
            data["id"],
            mod,
        )

    @staticmethod
    def from_zip(
        zip: "core.Zip",
        mod: "core.Mod",
        arc: str,
        id: str,
    ) -> "FridaScript":
        """Creates a Frida script from a zip file.

        Args:
            zip (core.Zip): Zip file to create the Frida script from
            mod (core.Mod): The mod the Frida script belongs to
            arc (str): Architecture the script is designed for
            id (str): Id of the script

        Raises:
            ValueError: If the file is not found in the zip

        Returns:
            FridaScript: The Frida script created from the zip file
        """
        file = zip.get_file(FridaScript.get_file_path(arc, id))
        if file is None:
            raise ValueError("File not found in zip.")
        json_file = core.JsonFile.from_data(file)
        return FridaScript.deserialize(json_file.get_json(), mod)


class FridaScripts:
    """A class to represent a collection of Frida scripts."""

    def __init__(
        self,
        scripts: list["FridaScript"],
    ):
        """Initializes a new instance of the FridaScripts class.

        Args:
            scripts (list[FridaScript]): The Frida scripts
        """
        self.scripts = scripts

    def is_valid_script(
        self,
        script: "FridaScript",
        cc: "core.CountryCode",
        gv: "core.GameVersion",
    ) -> bool:
        """Checks if a Frida script is valid for a given country code and game version.

        Args:
            script (FridaScript): The Frida script to check
            cc (core.CountryCode): The country code to check
            gv (core.GameVersion): The game version to check

        Returns:
            bool: True if the Frida script is valid for the given country code and game version, False otherwise
        """
        return script.cc == cc and script.gv == gv

    def validate_scripts(self, cc: "core.CountryCode", gv: "core.GameVersion"):
        """Removes all Frida scripts that are not valid for a given country code and game version.

        Args:
            cc (core.CountryCode): Country code to validate against
            gv (core.GameVersion): Game version to validate against
        """
        new_scripts: list["FridaScript"] = []
        for script in self.scripts:
            if self.is_valid_script(script, cc, gv):
                new_scripts.append(script)
        self.scripts = new_scripts

    def is_empty(self) -> bool:
        """Checks if the collection of Frida scripts is empty.

        Returns:
            bool: True if the collection of Frida scripts is empty, False otherwise
        """
        return len(self.scripts) == 0

    def add_script(self, script: "FridaScript"):
        """Adds a Frida script to the collection.

        Args:
            script (FridaScript): The Frida script to add
        """
        self.scripts.append(script)

    def remove_script(self, script: "FridaScript"):
        """Removes a Frida script from the collection.

        Args:
            script (FridaScript): The Frida script to remove
        """
        if script in self.scripts:
            self.scripts.remove(script)

    def get_script(self, arc: str) -> Optional["FridaScript"]:
        """Gets a Frida script from the collection.

        Returns:
            Optional[FridaScript]: The Frida script if found, None otherwise
        """
        for script in self.scripts:
            if script.arc == arc:
                return script
        return None

    def add_scripts(self, scripts: "FridaScripts"):
        """Adds a collection of Frida scripts to the collection.

        Args:
            scripts (FridaScripts): The collection of Frida scripts to add
        """
        for script in scripts.scripts:
            self.add_script(script)

    def get_base_script(self) -> str:
        """Gets the base Frida script with helper functions.

        Returns:
            str: The base Frida script content
        """
        return core.Path("base_script.js", True).read().to_str()

    def combine_scripts(self, arc: str) -> "core.Data":
        """Combines all Frida scripts for a given architecture into one script.

        Args:
            arc (str): The architecture to combine scripts for

        Returns:
            core.Data: The combined Frida script
        """
        base_script = self.get_base_script() + "\r\n"
        script_text = ""
        for script in self.scripts:
            if script.arc == arc:
                text = ""
                text += f"// {'-'*50}\r\n// {script.name} from mod {script.mod.name} by {script.mod.author}\r\n// {'-'*50}\r\n\r\n"
                text += script.script
                text += "\r\n\r\n"
                script_text += text
        base_script = base_script.replace("// {{SCRIPTS}}", script_text)
        return core.Data(base_script)

    def add_to_zip(self, zip: "core.Zip"):
        """Adds the collection of Frida scripts to a zip file.

        Args:
            zip (core.Zip): The zip file to add the Frida scripts to
        """
        arcs: dict[str, list[str]] = {}
        for script in self.scripts:
            script.add_to_zip(zip)
            if script.arc not in arcs:
                arcs[script.arc] = []
            arcs[script.arc].append(script.id)
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
        """Creates a new instance of the FridaScripts class from a zip file.

        Args:
            zip (core.Zip): The zip file to create the FridaScripts instance from
            mod (core.Mod): The mod to create the FridaScripts instance for

        Raises:
            ValueError: If the zip file does not contain the scripts.json file

        Returns:
            FridaScripts: The FridaScripts instance
        """
        file = zip.get_file(core.Path("scripts").add("scripts.json"))
        if file is None:
            raise ValueError("File not found in zip.")
        json = core.JsonFile.from_data(file)
        json_data = json.get_json()
        arcs = json_data["arcs"]
        scripts: list["FridaScript"] = []
        for arc in arcs:
            for id in arcs[arc]:
                scripts.append(FridaScript.from_zip(zip, mod, arc, id))
        return FridaScripts(scripts)

    def import_scripts(self, other: "FridaScripts"):
        """Imports all Frida scripts from another FridaScripts instance.

        Args:
            other (FridaScripts): The FridaScripts instance to import the scripts from
        """
        for script in other.scripts:
            self.add_script(script)

    def get_used_arcs(self) -> list[str]:
        """Gets a list of all used architectures.

        Returns:
            list[str]: The list of used architectures
        """
        arcs: set[str] = set()
        for script in self.scripts:
            arcs.add(script.arc)
        return list(arcs)


class FridaGadgetHelper:
    def __init__(self):
        self.repo = "frida/frida"

    def get_latest_release(self) -> str:
        """Gets the latest release of Frida.

        Returns:
            str: The latest release of Frida
        """
        return (
            core.RequestHandler(
                f"https://api.github.com/repos/{self.repo}/releases/latest"
            )
            .get()
            .json()["tag_name"]
        )

    def get_gadget_download_url(self, version: str, arc: str) -> str:
        """Gets the download URL for a Frida gadget.

        Args:
            version (str): The Frida version
            arc (str): The architecture

        Returns:
            str: The download URL for the Frida gadget
        """
        return f"https://github.com/{self.repo}/releases/download/{version}/frida-gadget-{version}-android-{arc}.so.xz"

    def get_true_arc(self, frida_arc: str):
        if frida_arc == "arm":
            return "armeabi-v7a"
        elif frida_arc == "arm64":
            return "arm64-v8a"
        else:
            return frida_arc

    def download_gadget(self, version: str, arc: str):
        """Downloads a Frida gadget.

        Args:
            version (str): The Frida version
            arc (str): The architecture
        """
        path = self.get_path(arc)

        url = self.get_gadget_download_url(version, arc)
        data = core.RequestHandler(url).get_stream().raw.read()

        data = core.Data(data)
        data = data.decompress_xz()

        path.write(data)

    def get_path(self, arc: str) -> "core.Path":
        """Gets the path to a Frida gadget.

        Args:
            arc (str): The architecture

        Returns:
            core.Path: The path to the Frida gadget
        """
        true_arc = self.get_true_arc(arc)
        return core.Apk.get_libgadgets_path().add(true_arc).add("libfrida-gadget.so")

    def is_downloaded(self, arc: str) -> bool:
        return self.get_path(arc).exists()

    def download_gadgets(self, redownload: bool = False):
        """Downloads all Frida gadgets."""
        version = None
        for arc in ["arm", "arm64", "x86", "x86_64"]:
            if self.is_downloaded(arc) and not redownload:
                continue
            if version is None:
                version = self.get_latest_release()
            self.download_gadget(version, arc)
