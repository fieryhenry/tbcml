from typing import Optional
import xml.etree.ElementTree as ET
from tbcml import core


class XML:
    ET = ET

    def __init__(self, data: "core.Data"):
        self.data = data
        ET.register_namespace("android", "http://schemas.android.com/apk/res/android")
        self.root = ET.fromstring(self.data.to_str())

    def get_element(self, path: str) -> Optional[ET.Element]:
        return self.root.find(path)

    def get_elements(self, path: str) -> list[ET.Element]:
        return self.root.findall(path)

    def set_element(self, path: str, value: str):
        element = self.root.find(path)
        if element is None:
            raise ValueError("Element not found")
        element.text = value

    def save(self):
        self.data = core.Data(ET.tostring(self.root).decode("utf-8"))

    def to_file(self, path: "core.Path"):
        self.save()
        path.write(self.data)

    def get_attribute_name(self, attribute: str) -> str:
        return attribute.replace(
            "android:", "{http://schemas.android.com/apk/res/android}"
        )

    def set_attribute(self, path: str, attribute: str, value: str):
        attribute = self.get_attribute_name(attribute)
        if path == "manifest":
            element = self.root
        else:
            element = self.root.find(path)
        if element is None:
            raise ValueError("Element not found")
        element.set(attribute, value)

    def get_attribute(self, path: str, attribute: str) -> Optional[str]:
        attribute = self.get_attribute_name(attribute)
        element = self.root.find(path)
        if element is None:
            return None
        return element.get(attribute)

    def remove_attribute(self, path: str, attribute: str):
        attribute = self.get_attribute_name(attribute)
        element = self.root.find(path)
        if element is None:
            raise ValueError("Element not found")
        element.attrib.pop(attribute)
