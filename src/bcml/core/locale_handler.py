from bcml.core import io


class PropertySet:
    def __init__(self, locale: str, property: str):
        self.locale = locale
        self.path = (
            io.path.Path("locales", True).add(locale).add(property + ".properties")
        )
        self.properties: dict[str, str] = {}
        self.parse()

    def parse(self):
        lines = self.path.read().to_str().splitlines()
        for line in lines:
            if line.startswith("#") or line == "":
                continue
            parts = line.split("=")
            if len(parts) < 2:
                continue
            key = parts[0]
            value = "=".join(parts[1:])
            if key in self.properties:
                raise KeyError(f"Key {key} already exists in property file")
            self.properties[key] = value

    def get_key(self, key: str) -> str:
        return self.properties[key].replace("\\n", "\n")

    @staticmethod
    def from_config(property: str) -> "PropertySet":
        return PropertySet(io.config.Config().get(io.config.Key.LOCALE), property)


class LocalManager:
    def __init__(self, locale: str):
        self.locale = locale
        self.path = io.path.Path("locales", True).add(locale)
        self.properties: dict[str, PropertySet] = {}
        self.all_properties: dict[str, str] = {}
        self.parse()

    def parse(self):
        for file in self.path.get_files():
            file_name = file.basename()
            if file_name.endswith(".properties"):
                property_set = PropertySet(self.locale, file_name[:-11])
                self.all_properties.update(property_set.properties)
                self.properties[file_name[:-11]] = property_set

    def get_key(self, property: str, key: str) -> str:
        return self.properties[property].get_key(key)

    def search_key(self, key: str) -> str:
        return self.all_properties[key]

    @staticmethod
    def from_config() -> "LocalManager":
        return LocalManager(io.config.Config().get(io.config.Key.LOCALE))
