from bcml.core import mods, game_data, io
from bcml.cli import option, color, main

class AnimEditor:
    def __init__(self, anim: game_data.bc_anim.Anim):
        self.anim = anim
    
    def run(self):
        while True:
            try:
                self.edit_options()
            except main.BackException:
                return
    
    def get_anim(self):
        return self.anim

    def edit_options(self):
        items = [
            option.Item("Edit Sprite", func=self.edit_sprite),
            option.Item("Edit Model", func=self.edit_model),
            option.Item("Edit Animations", func=self.edit_animations),
            option.Item("Back", color="dark_red", func=self.go_back)
        ]
        selector = option.ListSelector(items, "Select an option:")
        return selector.run()
    
    def edit_sprite_runner(self):
        while True:
            try:
                self.edit_sprite()
            except main.BackException:
                return

    def edit_sprite(self):
        items = [
            option.Item("Edit Sprite Sheet", func=self.edit_sprite_sheet),
            option.Item("Edit Sprite Cuts", func=self.edit_sprite_cuts),
            option.Item("Back", color="dark_red", func=self.go_back)
        ]
        selector = option.ListSelector(items, "Select an option:")
        return selector.run()
    
    def edit_sprite_sheet(self):
        sprite_sheet = option.FileSelector("Select a sprite sheet:", [("PNG", "*.png")]).get()
        if sprite_sheet is None:
            return
        image = io.bc_image.BCImage(sprite_sheet.read())
        self.anim.imgcut.image = image

    def edit_sprite_cuts(self):
        pass

    
    def edit_model(self):
        pass

    def edit_animations(self):
        pass

    def go_back(self):
        raise main.BackException()
