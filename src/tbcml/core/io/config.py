import enum
from typing import Any
from tbcml import core


class ConfigKey(enum.Enum):
    MOD_FOLDER = "mod_folder"
    APK_FOLDER = "apk_folder"
    APK_COPY_PATH = "apk_copy_path"
    KEYSTORE_PASSWORD = "keystore_password"
    UPDATE = "update"
    UPDATE_TO_BETA = "update_to_beta"
    DEFAULT_AUTHOR = "default_author"
    LIB_GADGETS_FOLDER = "lib_gadgets_folder"
    LOCALE = "locale"
    THEME = "theme"
    ALLOW_SCRIPT_MODS = "allow_script_mods"


class Config:
    def __init__(self):
        config = core.YamlFile(core.Path.get_appdata_folder().add("config.yaml"))
        if config.yaml is None:  # type: ignore
            config.yaml = {}
        self.config: dict[ConfigKey, Any] = {}
        for key, value in config.yaml.items():
            try:
                self.config[ConfigKey(key)] = value
            except ValueError:
                pass
        self.config_object = config
        self.initialize_config()

    def __getitem__(self, key: ConfigKey) -> Any:
        return self.config[key]

    def __setitem__(self, key: ConfigKey, value: Any) -> None:
        self.config[key] = value

    def __contains__(self, key: ConfigKey) -> bool:
        return key in self.config

    def initialize_config(self):
        initial_values = {
            ConfigKey.MOD_FOLDER: core.Path.get_appdata_folder().add("Mods").path,
            ConfigKey.APK_FOLDER: core.Path.get_appdata_folder().add("APKs").path,
            ConfigKey.APK_COPY_PATH: "",
            ConfigKey.KEYSTORE_PASSWORD: "TBCML_CUSTOM_APK",
            ConfigKey.UPDATE: True,
            ConfigKey.UPDATE_TO_BETA: False,
            ConfigKey.DEFAULT_AUTHOR: "",
            ConfigKey.LIB_GADGETS_FOLDER: core.Path.get_appdata_folder()
            .add("LibGadgets")
            .path,
            ConfigKey.LOCALE: "en",
            ConfigKey.THEME: "default",
            ConfigKey.ALLOW_SCRIPT_MODS: False,
        }
        for key, value in initial_values.items():
            if key not in self.config:
                self.config[key] = value
        self.save()

    def save(self):
        for key, value in self.config.items():
            self.config_object.yaml[key.value] = value
        self.config_object.save()

    def get(self, key: ConfigKey) -> Any:
        return self.config[key]

    def reset(self):
        self.config.clear()
        self.config_object.remove()
        self.initialize_config()

    def set(self, key: ConfigKey, value: Any):
        self.config[key] = value
        self.save()
