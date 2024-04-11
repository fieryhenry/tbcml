from __future__ import annotations

import xml.etree.ElementTree as ET
import tbcml


class XML:
    ET = ET

    def __init__(self, data: tbcml.Data | None = None, root: ET.Element | None = None):
        ET.register_namespace("android", "http://schemas.android.com/apk/res/android")
        if data is not None:
            self.root = ET.fromstring(data.to_str())
        if root is not None:
            self.root = root

    def get_element(self, path: str) -> ET.Element | None:
        path = path.replace("manifest", "").strip()
        path = path.lstrip("/").strip()
        if not path:
            return self.root
        else:
            return self.root.find(path)

    def get_elements(self, path: str) -> list[ET.Element]:
        return self.root.findall(path)

    def set_element(self, path: str, value: str):
        element = self.get_element(path)
        if element is None:
            raise ValueError("Element not found")
        element.text = value

    def to_data(self) -> tbcml.Data:
        string = ET.tostring(
            self.root,
            xml_declaration=True,
            encoding="utf-8",
        ).decode("utf-8")
        return tbcml.Data(string)

    def to_file(self, path: tbcml.Path):
        path.write(self.to_data())

    def get_attribute_name(self, attribute: str) -> str:
        return attribute.replace(
            "android:", "{http://schemas.android.com/apk/res/android}"
        )

    def set_attribute(self, path: str, attribute: str, value: str):
        attribute = self.get_attribute_name(attribute)
        element = self.get_element(path)
        if element is None:
            raise ValueError("Element not found")
        element.set(attribute, value)

    def get_attribute(self, path: str, attribute: str) -> str | None:
        attribute = self.get_attribute_name(attribute)
        element = self.get_element(path)
        if element is None:
            return None
        return element.get(attribute)

    def remove_attribute(self, path: str, attribute: str):
        attribute = self.get_attribute_name(attribute)
        element = self.get_element(path)
        if element is None:
            raise ValueError("Element not found")
        element.attrib.pop(attribute)
