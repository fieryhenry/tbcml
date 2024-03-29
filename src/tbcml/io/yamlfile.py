import yaml
import tbcml


class Yaml:
    def __init__(self, data: "tbcml.Data"):
        self.yaml = yaml.safe_load(data.to_bytes())

    @staticmethod
    def from_file(file: "tbcml.File"):
        data = tbcml.load(file)
        return Yaml(data)

    def to_data(self) -> "tbcml.Data":
        result = yaml.safe_dump(self.yaml, indent=4)
        return tbcml.Data(result)

    def to_file(self, path: "tbcml.Path"):
        self.to_data().to_file(path)
