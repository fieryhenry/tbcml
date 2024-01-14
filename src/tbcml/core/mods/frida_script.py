from typing import Optional
from marshmallow_dataclass import dataclass
from tbcml import core


@dataclass
class FridaScript:
    name: str
    content: str
    architectures: "core.ARCS"
    description: str = ""
    inject_smali: bool = False
    valid_ccs: Optional[list["core.CC"]] = None
    valid_game_versions: Optional[list["core.GV"]] = None

    def to_json(self) -> str:
        return FridaScript.Schema().dumps(self)  # type: ignore

    @staticmethod
    def from_json(data: str) -> "FridaScript":
        return FridaScript.Schema().loads(data)  # type: ignore

    @staticmethod
    def get_path(index: int) -> "core.Path":
        return core.Path(core.ModPath.SCRIPTS.value).add(f"{index}.json")

    def add_to_zip(self, index: int, zip: "core.Zip"):
        path = FridaScript.get_path(index)
        json = self.to_json()
        zip.add_file(path, core.Data(json))

    @staticmethod
    def from_zip(index: int, zip: "core.Zip") -> Optional["FridaScript"]:
        path = FridaScript.get_path(index)
        data = zip.get_file(path)
        if data is None:
            return None
        return FridaScript.from_json(data.to_str())

    def get_script_str(self, mod_name: str, mod_authors: list[str]) -> str:
        mod_authors_str = ", ".join(mod_authors)
        if self.architectures:
            if self.architectures == "all":
                arcs = ["all"]
            elif self.architectures in ["32", "64"]:
                arcs = [self.architectures + " bit"]
            else:
                arcs = self.architectures
            arcs_str = ", ".join(arcs) + " architectures"
        else:
            arcs_str = "smali injection"
        string = "/*\n"
        string += f"\t{self.name} from {mod_name} by {mod_authors_str} for {arcs_str}\n"
        string += f"\t{self.description}\n"
        string += "*/\n\n"
        string += self.content
        return string

    def get_scripts_str(
        self, apk: "core.Apk", mod_name: str, mod_authors: list[str]
    ) -> tuple[dict[str, str], bool]:
        is_valid = self.is_valid(apk.country_code, apk.game_version)
        if not is_valid:
            return {}, self.inject_smali

        arcs = apk.get_architectures_subset(self.architectures)
        scripts: dict[str, str] = {}
        for arc in arcs:
            scripts[arc] = self.get_script_str(mod_name, mod_authors)
        return scripts, self.inject_smali

    @staticmethod
    def get_base_script() -> str:
        return core.Path("base_script.js", True).read().to_str()

    def get_custom_html(self) -> str:
        return f'<span class="iro">[{self.name}]</span><br>{self.description}<br><span class="iro">Code:</span><br><pre><code class="language-javascript">{self.content}</code></pre>'

    def is_valid(self, cc: "core.CountryCode", gv: "core.GameVersion") -> bool:
        if self.valid_ccs is not None:
            valid_cc_str = [str(valid_cc) for valid_cc in self.valid_ccs]
            if str(cc) not in valid_cc_str:
                return False
        if self.valid_game_versions is not None:
            valid_gv_str = [str(valid_gv) for valid_gv in self.valid_game_versions]
            if str(gv) not in valid_gv_str:
                return False
        return True


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
