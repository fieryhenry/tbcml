from typing import Optional
from bcml.core import io
from bcml.core.mods import bc_mod


class ModManager:
    def __init__(self):
        self.mods: dict[str, bc_mod.Mod] = {}
        self.mod_folder = io.path.Path(io.config.Config().get(io.config.Key.MOD_FOLDER))
        self.mod_folder.generate_dirs()
        self.mod_info_json = self.mod_folder.add("mod_info.json")
        self.load_mod_json()
        self.load_mods()

    def load_mods(self):
        for path in self.mod_folder.get_files():
            if path.get_extension() != "bcmod":
                continue
            mod = bc_mod.Mod.load(path)
            if mod is not None:
                self.mods[mod.get_file_name()] = mod

    def load_mod_json(self):
        if self.mod_info_json.exists():
            self.json_file = io.json_file.JsonFile.from_path(self.mod_info_json)
        else:
            self.init_new_json()
            self.save_mod_json()

    def init_new_json(self):
        self.json_file = io.json_file.JsonFile.from_json({"mods": {}})

    def save_mod_json(self):
        self.json_file.save(self.mod_info_json)

    def enable_mod(self, mod: bc_mod.Mod):
        self.save_mod(mod)
        self.json_file.get_json()["mods"][mod.get_file_name()] = True
        self.save_mod_json()

    def disable_mod(self, mod: bc_mod.Mod):
        self.save_mod(mod)
        self.json_file.get_json()["mods"][mod.get_file_name()] = False
        self.save_mod_json()

    def is_mod_enabled(self, mod: bc_mod.Mod) -> bool:
        if mod.get_file_name() not in self.json_file.get_json()["mods"]:
            return True
        return self.json_file.get_json()["mods"][mod.get_file_name()]

    def get_enabled_mods(self) -> list[bc_mod.Mod]:
        return [mod for mod in self.mods.values() if self.is_mod_enabled(mod)]

    def get_disabled_mods(self) -> list[bc_mod.Mod]:
        return [mod for mod in self.mods.values() if not self.is_mod_enabled(mod)]

    def increase_priority(self, mod: bc_mod.Mod):
        if mod.get_file_name() not in self.json_file.get_json()["mods"]:
            return
        self.json_file.get_json()["mods"].insert(
            0,
            mod.get_file_name(),
            self.json_file.get_json()["mods"].pop(mod.get_file_name()),
        )
        self.save_mod_json()

    def decrease_priority(self, mod: bc_mod.Mod):
        if mod.get_file_name() not in self.json_file.get_json()["mods"]:
            return
        self.json_file.get_json()["mods"].append(
            mod.get_file_name(),
            self.json_file.get_json()["mods"].pop(mod.get_file_name()),
        )
        self.save_mod_json()

    def get_mods(self) -> list[bc_mod.Mod]:
        return list(self.mods.values())

    def get_mod(self, id: str) -> Optional[bc_mod.Mod]:
        return self.mods.get(id)

    def get_mod_by_full_name(self, full_name: str) -> Optional[bc_mod.Mod]:
        for mod in self.mods.values():
            if mod.get_full_mod_name() == full_name:
                return mod
        return None

    def add_mod(self, mod: bc_mod.Mod):
        self.mods[mod.get_file_name()] = mod
        self.save_mod(mod)

    def save_mod(self, mod: bc_mod.Mod):
        self.mods[mod.get_file_name()] = mod
        mod.save(self.mod_folder.add(mod.get_file_name()))

    def remove_mod(self, mod: bc_mod.Mod):
        self.mods.pop(mod.get_file_name())
        self.mod_folder.add(mod.get_file_name()).remove()

    def get_mod_folder(self) -> io.path.Path:
        return self.mod_folder

    def save_mods(self):
        for mod in self.mods.values():
            self.save_mod(mod)
