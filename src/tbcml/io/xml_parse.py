from typing import Optional
import xml.etree.ElementTree as ET
import tbcml


class XML:
    ET = ET

    def __init__(self, data: "tbcml.Data"):
        self.data = data
        ET.register_namespace("android", "http://schemas.android.com/apk/res/android")
        self.root = ET.fromstring(self.data.to_str())

    def get_element(self, path: str) -> Optional[ET.Element]:
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

    def save(self):
        self.data = tbcml.Data(ET.tostring(self.root).decode("utf-8"))

    def to_file(self, path: "tbcml.Path"):
        self.save()
        path.write(self.data)

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

    def get_attribute(self, path: str, attribute: str) -> Optional[str]:
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
