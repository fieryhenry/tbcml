from __future__ import annotations

from marshmallow_dataclass import dataclass
import tbcml


@dataclass
class LoadingScreen(tbcml.Modification):
    inquiry_code_text: str | None = None
    loading_text: str | None = None
    loading_texture: tbcml.Texture | None = None

    def apply_pkg(self, pkg: tbcml.Pkg, lang: str | None):
        if self.inquiry_code_text is not None:
            pkg.set_string("autoSave_txt6", self.inquiry_code_text, True, lang)
        if self.loading_text is not None:
            pkg.set_string("loading", self.loading_text, True, lang)

    def apply_game_data(self, game_data: tbcml.GamePacks):
        if self.loading_texture is None:
            return
        self.loading_texture.apply(game_data)

    def read(self, game_data: tbcml.GamePacks, pkg: tbcml.Pkg):
        self.loading_texture = tbcml.Texture()

        self.loading_texture.read_from_game_file_names(
            game_data, "download.png", "download.imgcut"
        )

        lang = game_data.lang
        if lang is not None:
            lang = lang.value

        self.inquiry_code_text = pkg.get_string("autoSave_txt6", True, lang)
        self.loading_text = pkg.get_string("loading", True, lang)

    def get_cuts(self) -> list[tbcml.BCImage | None] | None:
        if self.loading_texture is None:
            return None
        return self.loading_texture.get_cuts()

    def pre_to_json(self) -> None:
        if self.loading_texture is not None:
            self.loading_texture.save_b64()
