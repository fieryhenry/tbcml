import tbcml


class CustomLoadingScreen(tbcml.LoadingScreen):
    def __init__(self, game_data: tbcml.GamePacks, pkg: tbcml.PKG):
        super().__init__()
        self.read(game_data, pkg)

        self.inquiry_code_text = "Inquiry Code Down there: vvv"
        self.loading_text = "Loading???"

        if self.loading_texture is not None:
            self.loading_texture.rects.reverse()


loader = tbcml.ModLoader("en", "13.2.0")
loader.initialize()

mod = tbcml.Mod()
mod.add_modification(CustomLoadingScreen(loader.get_game_packs(), loader.get_apk()))
