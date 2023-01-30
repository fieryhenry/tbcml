import enum
from typing import Any
from bcml.core.io import path, yaml


class Key(enum.Enum):
    MOD_FOLDER = "mod_folder"
    APK_FOLDER = "apk_folder"
    APK_COPY_PATH = "apk_copy_path"
    KEYSTORE_PASSWORD = "keystore_password"
    UPDATE = "update"
    UPDATE_TO_BETA = "update_to_beta"
    DEFAULT_AUTHOR = "default_author"
    LIB_GADGETS_FOLDER = "lib_gadgets_folder"
    SELECTED_APK = "selected_apk"


class Config:
    def __init__(self):
        config = yaml.YamlFile(path.Path.get_appdata_folder().add("config.yaml"))
        self.config: dict[Key, Any] = {}
        for key, value in config.yaml.items():
            try:
                self.config[Key(key)] = value
            except ValueError:
                pass
        self.config_object = config
        self.initialize_config()

    def __getitem__(self, key: Key) -> Any:
        return self.config[key]

    def __setitem__(self, key: Key, value: Any) -> None:
        self.config[key] = value

    def __contains__(self, key: Key) -> bool:
        return key in self.config

    def initialize_config(self):
        initial_values = {
            Key.MOD_FOLDER: path.Path.get_appdata_folder().add("Mods").path,
            Key.APK_FOLDER: path.Path.get_appdata_folder().add("APKs").path,
            Key.APK_COPY_PATH: "",
            Key.KEYSTORE_PASSWORD: "BCML_CUSTOM_APK",
            Key.UPDATE: True,
            Key.UPDATE_TO_BETA: False,
            Key.DEFAULT_AUTHOR: "",
            Key.LIB_GADGETS_FOLDER: path.Path.get_appdata_folder()
            .add("LibGadgets")
            .path,
            Key.SELECTED_APK: "",
        }
        for key, value in initial_values.items():
            if key not in self.config:
                self.config[key] = value
        self.save()

    def save(self):
        for key, value in self.config.items():
            self.config_object.yaml[key.value] = value
        self.config_object.save()

    def get(self, key: Key) -> Any:
        return self.config[key]

    def reset(self):
        self.config.clear()
        self.config_object.remove()
        self.initialize_config()

    def set(self, key: Key, value: Any):
        self.config[key] = value
        self.save()
