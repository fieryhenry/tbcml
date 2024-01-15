from typing import Optional
from marshmallow_dataclass import dataclass
import tbcml


@dataclass
class FridaScript:
    """FridaScript object
    See <https://frida.re/> for what frida is

    Usage:
        ```
        script_content = \"""
        let func_name = "_ZN5Botan11PK_Verifier14verify_messageEPKhmS2_m"

        // Botan::PK_Verifier::verify_message(...)
        Interceptor.attach(Module.findExportByName("libnative-lib.so", func_name), {
            onLeave: function (retval) {
                retval.replace(0x1)
            }
        })
        \"""
        script = FridaScript(
            name="Mailbox Hack",
            content=script_content,
            architectures="64",
            description="Disable signature verification",
        )
        mod.add_script(script)
        ```

    Args:
        name: (str), the name of the script
        content: (str), the actual script code
        architectures: (list[str] | str), the architectrues the script should apply to.
        description: (str), the description of what the script does. Defaults to ""
        inject_smali: (bool), whether to inject the frida-gadget library into the onCreate method of the apk instead of the native-lib. Defaults to False
        valid_ccs: (list[str | tbcml.CountryCode] | None), the country codes (en, jp, kr, tw) the script should apply to. If None, apply to all country codes. Defaults to None
        valid_game_versions: (list[str | tbcml.GameVersion] | None), the game versions (e.g 12.3.0, 13.0.0) the script should apply to. If None, apply to all game versions. Defaults to None
    """

    name: str
    """The name of the script"""
    content: str
    """The actual script code, see <https://frida.re/docs/javascript-api/> on how to write a script, or look at the examples"""
    architectures: "tbcml.ARCS"
    """The architectrues the script should apply to.
    
    Options are: `[x86, x86_64, arm64-v8a, armeabi-v7a, armeabi, mips, mips64], all, 32, 64.`

    32 = all 32 bit architectures.
    64 = all 64 bit architectures.
    all = all architectures.

    `x86, x86_64, arm64-v8a, armeabi-v7a, armeabi, mips, mips64` should be specified in a list. e.g ["x86", "arm64-v8a"],
    whereas `all, 32, 64` should be specified on their own e.g "32" or "all"
    """
    description: str = ""
    """The description of what the script does. Defaults to ""."""
    inject_smali: bool = False
    """Whether to inject the frida-gadget library into the onCreate method of the apk instead of the native-lib.
    
    This is less reliable than injecting into libnative-lib.so, but may work for old versions.
    Also useful if you want to hook into something as soon as the app loads. Defaults to False
    """
    valid_ccs: Optional[list["tbcml.CC"]] = None
    """List of country codes (en, jp, kr, tw) the script should apply to.
    If None, the script should apply to all country codes. Defaults to None
    """
    valid_game_versions: Optional[list["tbcml.GV"]] = None
    """List of game versions (e.g 12.3.0, 13.0.0) the script should apply to
    If None, the script should apply to all game versions. Defaults to None
    """

    def to_json(self) -> str:
        return FridaScript.Schema().dumps(self)  # type: ignore

    @staticmethod
    def from_json(data: str) -> "FridaScript":
        return FridaScript.Schema().loads(data)  # type: ignore

    @staticmethod
    def get_path(index: int) -> "tbcml.Path":
        return tbcml.Path(tbcml.ModPath.SCRIPTS.value).add(f"{index}.json")

    def add_to_zip(self, index: int, zip: "tbcml.Zip"):
        path = FridaScript.get_path(index)
        json = self.to_json()
        zip.add_file(path, tbcml.Data(json))

    @staticmethod
    def from_zip(index: int, zip: "tbcml.Zip") -> Optional["FridaScript"]:
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
        self, apk: "tbcml.Apk", mod_name: str, mod_authors: list[str]
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
        return tbcml.Path("base_script.js", True).read().to_str()

    def get_custom_html(self) -> str:
        return f'<span class="iro">[{self.name}]</span><br>{self.description}<br><span class="iro">Code:</span><br><pre><code class="language-javascript">{self.content}</code></pre>'

    def is_valid(self, cc: "tbcml.CountryCode", gv: "tbcml.GameVersion") -> bool:
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
            tbcml.RequestHandler(
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
        data = tbcml.RequestHandler(url).get_stream().raw.read()

        data = tbcml.Data(data)
        data = data.decompress_xz()

        path.write(data)

    def get_path(self, arc: str) -> "tbcml.Path":
        """Gets the path to a Frida gadget.

        Args:
            arc (str): The architecture

        Returns:
            tbcml.Path: The path to the Frida gadget
        """
        true_arc = self.get_true_arc(arc)
        return tbcml.Apk.get_libgadgets_path().add(true_arc).add("libfrida-gadget.so")

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
