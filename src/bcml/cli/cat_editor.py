from bcml.core import mods, game_data, io
from bcml.cli import option, color, main, anim_editor

class CatEditor:
    def __init__(self, cat: "game_data.cat_base.cats.Cat", mod: "mods.bc_mod.Mod", game_data: "game_data.pack.GamePacks"):
        self.cat = cat
        self.mod = mod
        self.game_data = game_data
    
    def run(self):
        while True:
            try:
                self.edit_options()
            except main.BackException:
                return

    def edit_options(self):
        items = [
            option.Item("Edit Form Data", func=self.select_form),
            option.Item("Edit Upgrade / Purchase Stats", func=self.edit_upgrade_stats),
            option.Item("Edit talents", func=self.edit_talents),
            option.Item("Edit evolve text", func=self.edit_evolve_text),
            option.Item("Edit catguide data", func=self.edit_catguide_data),
            option.Item("Back", color="dark_red", func=self.go_back)
        ]
        selector = option.ListSelector(items, "Select an option:")
        return selector.run()
    
    def edit_talents(self):
        pass

    def edit_evolve_text(self):
        new_text = color.ColoredInput().get("Enter new evolve text: (<br> for new line):").split("<br>")
        self.cat.evolve_text = new_text
        self.save_mod()
    
    def edit_catguide_data(self):
        pass
    
    def select_form_runner(self):
        while True:
            try:
                self.select_form()
            except main.BackException:
                return

    def select_form(self):
        items: list["option.Item"] = []
        for form_type, form in self.cat.forms.items():
            items.append(option.Item(form_type.name, form.name, func=self.edit_form_data, args=[form]))
        items.append(option.Item("Back", color="dark_red", func=self.go_back))
        selector = option.ListSelector(items, "Select a form:")
        return selector.run()
    
    def go_back(self):
        raise main.BackException()

    def edit_form_data_runner(self, form: "game_data.cat_base.cats.Form"):
        while True:
            try:
                self.edit_form_data(form)
            except main.BackException:
                return
    
    def edit_form_data(self, form: "game_data.cat_base.cats.Form"):
        items = [
            option.Item("Edit Name", func=self.edit_form_name, args=[form]),
            option.Item("Edit Description", func=self.edit_form_description, args=[form]),
            option.Item("Edit Stats", func=self.edit_form_stats, args=[form]),
            option.Item("Edit Animations", func=self.edit_form_animations, args=[form]),
            option.Item("Edit Icons", func=self.edit_form_icons_runner, args=[form]),
            option.Item("Back", color="dark_red", func=self.go_back)
        ]
        selector = option.ListSelector(items, "Select an option:")
        return selector.run()
    
    def edit_form_name(self, form: "game_data.cat_base.cats.Form"):
        new_name = color.ColoredInput().get("Enter new name:")
        form.name = new_name
        self.save_mod()
    
    def edit_form_description(self, form: "game_data.cat_base.cats.Form"):
        new_desc = color.ColoredInput().get("Enter new description: (<br> for new line):").split("<br>")
        form.description = new_desc
        self.save_mod()
    
    def edit_form_stats(self, form: "game_data.cat_base.cats.Form"):
        pass

    def edit_form_animations(self, form: "game_data.cat_base.cats.Form"):
        an_edit = anim_editor.AnimEditor(form.anim.anim)
        an_edit.run()
        anim = an_edit.get_anim()
        form.anim.anim = anim
        self.save_mod()


    def edit_form_icons_runner(self, form: "game_data.cat_base.cats.Form"):
        while True:
            try:
                self.edit_form_icons(form)
            except main.BackException:
                return

    def edit_form_icons(self, form: "game_data.cat_base.cats.Form"):
        items = [
            option.Item("Edit Deploy Icon", func=self.edit_deploy_icon, args=[form]),
            option.Item("Edit Upgrade Icon", func=self.edit_upgrade_icon, args=[form]),
            option.Item("Back", color="dark_red", func=self.go_back)
        ]
        selector = option.ListSelector(items, "Select an option:")
        return selector.run()
    
    def edit_deploy_icon(self, form: "game_data.cat_base.cats.Form"):
        new_icon = option.FileSelector("Select a new deploy icon:", [("PNG", "*.png")]).get()
        if new_icon is None:
            return
        image = io.bc_image.BCImage(new_icon.read())
        form.deploy_icon = image
        form.format_deploy_icon()
    
    def edit_upgrade_icon(self, form: "game_data.cat_base.cats.Form"):
        new_icon = option.FileSelector("Select a new upgrade icon:", [("PNG", "*.png")]).get()
        if new_icon is None:
            return
        image = io.bc_image.BCImage(new_icon.read())
        form.upgrade_icon = image
        form.format_upgrade_icon()
    
    def save_mod(self):
        self.mod.cat_base.cats.set_cat(self.cat)
        mods.mod_manager.ModManager().save_mod(self.mod)
    
    def edit_upgrade_stats(self):
        pass