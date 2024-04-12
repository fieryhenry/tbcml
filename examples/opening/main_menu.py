import tbcml


def grayscale_texture(texture: tbcml.Texture | None):
    if texture is None:
        return
    for i in range(len(texture.rects)):
        cut = texture.get_cut(i)
        if cut is None:
            continue
        cut.grayscale()
        texture.set_cut(i, cut)


class MainMenu(tbcml.MainMenu):
    def __init__(self, game_packs: tbcml.GamePacks):
        super().__init__()
        self.read(game_packs)
        self.inquiry_code_text_2 = "Hi :3 %@"
        self.inquiry_code_text_3 = "Please record???"
        self.inquiry_code_text_4 = "LOST"
        self.inquiry_code_text_6 = "Data Loss?"

        # Grayscale all textures (just an example)

        grayscale_texture(self.logo_texture)

        for collab_logo in self.collab_logo_textures or []:
            grayscale_texture(collab_logo)

        grayscale_texture(self.main_bg)
        grayscale_texture(self.itf_bg)
        grayscale_texture(self.cotc_bg)

        for collab_bg in self.main_collab_bgs or []:
            grayscale_texture(collab_bg)
        for collab_bg in self.itf_collab_bgs or []:
            grayscale_texture(collab_bg)
        for collab_bg in self.cotc_collab_bgs or []:
            grayscale_texture(collab_bg)

        grayscale_texture(self.chapter_button_texture)
        grayscale_texture(self.settings_texture)
        grayscale_texture(self.button_texture)


loader = tbcml.ModLoader("en", "13.2.0")
loader.initialize_apk()

mod = tbcml.Mod()
mod.add_modification(MainMenu(loader.get_game_packs()))

loader.apply(mod)

loader.initialize_adb()
loader.install_adb(run_game=True)
