import sys
from typing import Optional
from bcml.cli import color, option, mod_editor
from bcml.core import io, mods, game_version, country_code, game_data

class BackException(Exception):
    pass

class MainCLI:
    def __init__(self):
        pass
    
    def run(self):
        while True:
            try:
                self.first_menu()
            except KeyboardInterrupt:
                sys.exit()

    def select_cc(self) -> Optional["country_code.CountryCode"]:
        ccs = country_code.CountryCode.get_all()
        cc_items = option.Item.name_list_to_item_list(ccs)
        cc_selector = option.ListSelector(cc_items, "Select a country code:")
        cc_index = cc_selector.get_index()
        if cc_index is None:
            return None
        return ccs[cc_index]
    
    def select_gv(self, cc: "country_code.CountryCode") -> "game_version.GameVersion":
        gv = color.ColoredInput().get("Enter a game version: (e.g 11.8.0, latest)")
        return game_version.GameVersion.from_string_latest(gv, cc)
    
    def select_apk_downloaded(self) -> Optional["io.apk.Apk"]:
        all_apks = io.apk.Apk.get_all_downloaded()
        items = option.Item.name_list_to_item_list(all_apks)
        selector = option.ListSelector(items, "Select an APK:")
        index = selector.get_index()
        if index is None:
            return None
        return all_apks[index]
    
    def download_apk(self) -> Optional["io.apk.Apk"]:
        cc = self.select_cc()
        if cc is None:
            return None
        gv = self.select_gv(cc)
        apk = io.apk.Apk(gv, cc)
        apk.download_apk()
        return apk
    
    def add_apk_from_file(self) -> Optional["io.apk.Apk"]:
        path = option.FileSelector("Select an APK file:", [("APK files", "*.apk")]).get()
        if path is None:
            return None
        return io.apk.Apk.from_apk_path(path)
    
    def select_apk(self) -> Optional["io.apk.Apk"]:
        items = [
            option.Item("Download APK", func=self.download_apk),
            option.Item("Add APK from file", func=self.add_apk_from_file),
            option.Item("Select APK from currently downloaded apks", func=self.select_apk_downloaded),
            option.Item("Cancel", color="dark_red")
        ]
        selector = option.ListSelector(items, "Select an APK:")
        apk: Optional["io.apk.Apk"] = selector.run()
        if apk is None:
            return None
        apk.extract()
        apk.download_server_files()
        game_packs = game_data.pack.GamePacks.from_apk(apk)
        while True:
            try:
                self.second_menu(apk, game_packs)
            except BackException:
                return apk
    
    def select_mod_downloaded(self) -> Optional["mods.bc_mod.Mod"]:
        mds = mods.mod_manager.ModManager().get_mods()
        md_items = option.Item.name_list_to_item_list(mds)
        md_selector = option.ListSelector(md_items, "Select a mod:")
        md_index = md_selector.get_index()
        if md_index is None:
            return None
        return mds[md_index]
    
    def add_mod_from_file(self) -> Optional["mods.bc_mod.Mod"]:
        path = option.FileSelector("Select a mod file:", [("Mod files", mods.bc_mod.Mod.get_extension())]).get()
        if path is None:
            return None
        return mods.bc_mod.Mod.load(path)
    
    def create_mod(self) -> Optional["mods.bc_mod.Mod"]:
        name = color.ColoredInput().get("Enter a name for the mod:")
        if not name:
            return None
        author = io.config.Config().get(io.config.Key.DEFAULT_AUTHOR)
        if not author:
            author = color.ColoredInput().get("Enter an author for the mod:")
        if not author:
            return None
        description = color.ColoredInput().get("Enter a description for the mod:")
        cc = io.config.Config().get(io.config.Key.DEFAULT_COUNTRY_CODE)
        if not cc:
            cc = self.select_cc()
        if not cc:
            return None
        if not isinstance(cc, country_code.CountryCode):
            cc = country_code.CountryCode.from_code(cc)
        gv = io.config.Config().get(io.config.Key.DEFAULT_GAME_VERSION)
        if not gv:
            gv = self.select_gv(cc)
        if not gv:
            return None
        if not isinstance(gv, game_version.GameVersion):
            gv = game_version.GameVersion.from_string_latest(gv, cc)

        return mods.bc_mod.Mod(name, author, description, cc, gv, mods.bc_mod.Mod.create_mod_id())
    
    def select_mod(self) -> Optional["mods.bc_mod.Mod"]:
        items = [
            option.Item("Add mod from file", func=self.add_mod_from_file),
            option.Item("Create mod", func=self.create_mod),
            option.Item("Select mod from currently downloaded mods", func=self.select_mod_downloaded),
            option.Item("Cancel", color="dark_red")
        ]
        selector = option.ListSelector(items, "Select a mod:")
        return selector.run()
    
    def go_back(self):
        raise BackException()
    
    def first_menu(self):
        items = [
            option.Item("Select APK", func=self.select_apk),
            option.Item("Open mod folder", func=self.open_mod_folder),
            option.Item("Open APK folder", func=self.open_apk_folder),
            option.Item("Exit", func=self.exit),
        ]
        selector = option.ListSelector(items, "Select an option:")
        return selector.run()
    
    def second_menu(self, apk: "io.apk.Apk", game_packs: "game_data.pack.GamePacks"):
        items = [
            option.Item("Select mod", func=self.mod_option_runner, args=[game_packs]),
            option.Item("Load mods into APK", func=self.load_mods, args=[apk]),
            option.Item("Remove APK", func=self.apk_delete, args=[apk]),
            option.Item("Back", color="dark_red", func=self.go_back)
        ]
        selector = option.ListSelector(items, "Select an option:")
        return selector.run()
    
    def apk_delete(self, apk: "io.apk.Apk"):
        apk.delete()
        self.go_back()
    
    def mod_option_runner(self, game_packs: "game_data.pack.GamePacks"):
        mod = self.select_mod()
        if mod is None:
            return
        mods.mod_manager.ModManager().enable_mod(mod)
        while True:
            try:
                self.mod_options(game_packs, mod)
            except BackException:
                return
    
    def mod_options(self, game_packs: "game_data.pack.GamePacks", mod: "mods.bc_mod.Mod"):
        items = [
            option.Item("Enable mod", func=self.enable_mod, args=[mod]),
            option.Item("Disable mod", func=self.disable_mod, args=[mod]),
            option.Item("Remove mod", func=self.remove_mod, args=[mod]),
            option.Item("Import mods into this mod", func=self.import_mods, args=[mod]),
            option.Item("Edit Mod", func=self.edit_mod, args=[mod, game_packs]),
            option.Item("Back", color="dark_red", func=self.go_back)
        ]
        selector = option.ListSelector(items, "Select an option:")
        return selector.run()
    
    def enable_mod(self, mod: "mods.bc_mod.Mod"):
        mods.mod_manager.ModManager().enable_mod(mod)
    
    def disable_mod(self, mod: "mods.bc_mod.Mod"):
        mods.mod_manager.ModManager().disable_mod(mod)
    
    def remove_mod(self, mod: "mods.bc_mod.Mod"):
        mods.mod_manager.ModManager().remove_mod(mod)
    
    def import_mods(self, mod: "mods.bc_mod.Mod"):
        mds = self.select_mods()
        if not mds:
            return
        mod.import_mods(mds)
    
    def edit_mod(self, mod: "mods.bc_mod.Mod", game_packs: "game_data.pack.GamePacks"):
        mod_editor.ModEditor(mod, game_packs).run()

    def select_mods(self) -> list["mods.bc_mod.Mod"]:
        all_mds = mods.mod_manager.ModManager().get_mods()
        items: list["option.Item"] = []
        for md in all_mds:
            items.append(option.Item(md))
        selector = option.ListSelector(items, "Select mods to import:")
        selected_items = selector.get_multi()
        if selected_items is None:
            return []
        mds: list["mods.bc_mod.Mod"] = []
        for item in selected_items:
            mds.append(item.name)
        return mds

    def load_mods(self, apk: "io.apk.Apk"):
        mds = mods.mod_manager.ModManager().get_enabled_mods()
        data = game_data.pack.GamePacks.from_apk(apk)
        data.apply_mods(mds)
        apk.load_packs_into_game(data)
    
    def open_mod_folder(self):
        io.path.Path(io.config.Config().get(io.config.Key.MOD_FOLDER)).open()
    
    def open_apk_folder(self):
        io.path.Path(io.config.Config().get(io.config.Key.APK_FOLDER)).open()
    
    def exit(self):
        leave = color.ColoredInput().get_bool("Are you sure you want to exit? (y/n):")
        if leave:
            sys.exit(0)
        
