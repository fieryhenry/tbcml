from typing import Literal, Optional, Sequence, Union
from marshmallow_dataclass import dataclass
from tbcml import core


@dataclass
class NewFridaScript:
    name: str
    content: str
    architectures: Union[list["core.ARC"], Literal["all"]]
    description: str = ""
    inject_smali: bool = False

    def to_json(self) -> str:
        return NewFridaScript.Schema().dumps(self)  # type: ignore

    @staticmethod
    def from_json(data: str) -> "NewFridaScript":
        return NewFridaScript.Schema().loads(data)  # type: ignore

    @staticmethod
    def get_path(index: int) -> "core.Path":
        return core.Path(core.ModPath.SCRIPTS.value).add(f"{index}.json")

    def add_to_zip(self, index: int, zip: "core.Zip"):
        path = NewFridaScript.get_path(index)
        json = self.to_json()
        zip.add_file(path, core.Data(json))

    @staticmethod
    def from_zip(index: int, zip: "core.Zip") -> Optional["NewFridaScript"]:
        path = NewFridaScript.get_path(index)
        data = zip.get_file(path)
        if data is None:
            return None
        return NewFridaScript.from_json(data.to_str())

    def get_script_str(self, mod_name: str, mod_authors: list[str]) -> str:
        mod_authors_str = ", ".join(mod_authors)
        if self.architectures:
            if self.architectures == "all":
                arcs = ["all"]
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

    def get_arcs(self, apk: "core.Apk") -> Sequence[str]:
        if self.architectures == "all":
            return apk.get_architectures()
        return self.architectures

    def get_scripts_str(
        self, apk: "core.Apk", mod_name: str, mod_authors: list[str]
    ) -> tuple[dict[str, str], bool]:
        arcs = self.get_arcs(apk)
        scripts: dict[str, str] = {}
        for arc in arcs:
            scripts[arc] = self.get_script_str(mod_name, mod_authors)
        return scripts, self.inject_smali

    @staticmethod
    def get_base_script() -> str:
        return core.Path("base_script.js", True).read().to_str()

    def get_custom_html(self) -> str:
        return f'<span class="iro">[{self.name}]</span><br>{self.description}<br><span class="iro">Code:</span><br><pre><code class="language-javascript">{self.content}</code></pre>'
