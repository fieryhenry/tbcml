from bcml.core import mods, game_data
from bcml.cli import option, color, main, cat_editor


class ModEditor:
    def __init__(self, mod: "mods.bc_mod.Mod", game_packs: "game_data.pack.GamePacks"):
        self.mod = mod
        self.game_data = game_packs
    
    def run(self):
        while True:
            try:
                self.edit_options()
            except main.BackException:
                return
    
    def edit_options(self):
        items = [
            option.Item("Edit Mod Info", func=self.edit_mod_info),
            option.Item("Edit Mod Data", func=self.edit_mod_data),
            option.Item("Back", color="dark_red", func=self.go_back)
        ]
        selector = option.ListSelector(items, "Select an option:")
        return selector.run()
    
    def edit_mod_info(self):
        items = [
            option.Item("Name", func=self.edit_mod_name),
            option.Item("Author", func=self.edit_mod_author),
            option.Item("Description", func=self.edit_mod_description),
            option.Item("Country Code", func=self.edit_mod_country_code),
            option.Item("Game Version", func=self.edit_mod_game_version),
            option.Item("Back", color="dark_red", func=self.go_back)
        ]
        selector = option.ListSelector(items, "Select an option:")
        return selector.run()
    
    def go_back(self):
        raise main.BackException()
    
    def edit_mod_name(self):
        new_name = color.ColoredInput().get("Enter new name:")
        self.mod.name = new_name
        self.save_mod()
    
    def edit_mod_author(self):
        new_author = color.ColoredInput().get("Enter new author:")
        self.mod.author = new_author
        self.save_mod()
    
    def edit_mod_description(self):
        new_desc = color.ColoredInput().get("Enter new description:")
        self.mod.description = new_desc
        self.save_mod()
    
    def edit_mod_country_code(self):
        new_cc = main.MainCLI().select_cc()
        if new_cc is None:
            return
        self.mod.country_code = new_cc
        self.save_mod()
    
    def edit_mod_game_version(self):
        new_ver = main.MainCLI().select_gv(self.mod.country_code)
        if new_ver is None:
            return
        self.mod.game_version = new_ver
        self.save_mod()
    
    def edit_mod_data(self):
        while True:
            try:
                self.edit_mod_data_options()
            except main.BackException:
                return
            
    def edit_mod_data_options(self):
        items = [
            option.Item("Import BCU Data", func=self.import_bcu_data),
            option.Item("Edit Cats", func=self.edit_cats),
            option.Item("Back", color="dark_red", func=self.go_back)
        ]
        selector = option.ListSelector(items, "Select an option:")
        return selector.run()
    
    def import_bcu_data(self):
        pass

    def load_cats(self):
        cats = game_data.cat_base.cats.Cats.from_game_data(self.game_data)
        if cats is None:
            print("No cats found.")
            return
        return cats

    def edit_cats(self):
        if self.game_data.catbase is None:
            return
        cat_id = color.ColoredInput().get_int("Enter cat ID:")
        cat = self.game_data.catbase.cats.get_cat(cat_id)
        if cat is None:
            print("Cat not found.")
            return
        cat_editor.CatEditor(cat, self.mod, self.game_data).run()  
    
    def save_mod(self):
        mods.mod_manager.ModManager().save_mod(self.mod)
    
    


