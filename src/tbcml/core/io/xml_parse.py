from typing import Optional
import xml
import xml.etree.ElementTree
from tbcml.core import io


class XML:
    def __init__(self, data: io.data.Data):
        self.data = data
        self.root = xml.etree.ElementTree.fromstring(data.to_str())

    def get_element(self, path: str) -> Optional[xml.etree.ElementTree.Element]:
        return self.root.find(path)

    def get_elements(self, path: str) -> list[xml.etree.ElementTree.Element]:
        return self.root.findall(path)

    def set_element(self, path: str, value: str):
        element = self.root.find(path)
        if element is None:
            raise ValueError("Element not found")
        element.text = value

    def save(self):
        self.data = io.data.Data(
            xml.etree.ElementTree.tostring(self.root).decode("utf-8")
        )

    def to_file(self, path: io.path.Path):
        path.write(self.data)
