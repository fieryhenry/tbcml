from __future__ import annotations

from marshmallow_dataclass import dataclass

import tbcml


@dataclass
class MainMenu(tbcml.Modification):
    inquiry_code_text_1: str | None = None
    """Inquiry Code\\n%@\\nThis code is required to recover your data.\\nBe sure to keep it safely recorded!"""

    inquiry_code_text_2: str | None = None
    """Inquiry Code: %@"""

    inquiry_code_text_3: str | None = None
    """Please record and save your inquiry code!"""

    inquiry_code_text_4: str | None = None
    """Without this information, your progress cannot be recovered if lost."""

    inquiry_code_text_5: str | None = None
    """Inquiry Code"""

    inquiry_code_text_6: str | None = None
    """Record and save this number to prevent data loss!"""

    logo_texture: tbcml.Texture | None = None
    # cut 1 is the main image and 21 is the cutout of the tail of the cat (used for the tail anim i assume)

    collab_logo_textures: list[tbcml.Texture] | None = None

    main_bg: tbcml.Texture | None = None
    itf_bg: tbcml.Texture | None = None
    cotc_bg: tbcml.Texture | None = None

    main_collab_bgs: list[tbcml.Texture] | None = None
    itf_collab_bgs: list[tbcml.Texture] | None = None
    cotc_collab_bgs: list[tbcml.Texture] | None = None

    chapter_button_texture: tbcml.Texture | None = None

    settings_texture: tbcml.Texture | None = None

    button_texture: tbcml.Texture | None = None

    def get_collab_ids(self) -> list[int]:  # TODO: Find these programmatically
        return [
            31,
            65,
            107,
            208,
        ]

    def read(self, game_data: tbcml.GamePacks):
        iq_text = game_data.localizable.get_string("autoSave_txt1")
        if iq_text is not None:
            self.inquiry_code_text_1 = iq_text

        iq_text = game_data.localizable.get_string("autoSave_txt2")
        if iq_text is not None:
            self.inquiry_code_text_2 = iq_text

        iq_text = game_data.localizable.get_string("autoSave_txt3")
        if iq_text is not None:
            self.inquiry_code_text_3 = iq_text

        iq_text = game_data.localizable.get_string("autoSave_txt4")
        if iq_text is not None:
            self.inquiry_code_text_4 = iq_text

        iq_text = game_data.localizable.get_string("autoSave_txt5")
        if iq_text is not None:
            self.inquiry_code_text_5 = iq_text

        iq_text = game_data.localizable.get_string("autoSave_txt6")
        if iq_text is not None:
            self.inquiry_code_text_6 = iq_text

        self.read_logos(game_data)
        self.read_bgs(game_data)

        self.chapter_button_texture = tbcml.Texture()
        self.chapter_button_texture.read_from_game_file_names(
            game_data, "img011_00_chapter_button.png", "img011_00_chapter_button.imgcut"
        )

        lang = game_data.localizable.get_lang()

        self.settings_texture = tbcml.Texture()
        self.settings_texture.read_from_game_file_names(
            game_data, f"img100_{lang}.png", f"img100_{lang}.imgcut"
        )

        self.button_texture = tbcml.Texture()
        self.button_texture.read_from_game_file_names(
            game_data, f"img101_{lang}.png", f"img101_{lang}.imgcut"
        )

    def read_logos(self, game_data: tbcml.GamePacks):
        logo = tbcml.Texture()
        logo.read_from_game_file_names(
            game_data, "img011_logo.png", "img011_logo.imgcut"
        )
        self.logo_texture = logo

        self.collab_logo_textures = []
        collab_ids = self.get_collab_ids()
        for collab_id in collab_ids:
            file_name = f"img011_logo_C_{collab_id:03}.png"
            cut_name = f"img011_logo_C_{collab_id:03}.imgcut"
            if not game_data.find_file(cut_name):
                cut_name = f"img011_logo.imgcut"
            logo = tbcml.Texture()
            logo.read_from_game_file_names(game_data, file_name, cut_name)
            self.collab_logo_textures.append(logo)

    def apply_logos(self, game_data: tbcml.GamePacks):
        if self.logo_texture is not None:
            self.logo_texture.apply(game_data)

        if self.collab_logo_textures is not None:
            for collab_logo in self.collab_logo_textures:
                collab_logo.apply(game_data)

    def read_bgs(self, game_data: tbcml.GamePacks):
        lang = game_data.localizable.get_lang()

        self.cotc_collab_bgs = []
        self.itf_collab_bgs = []
        self.main_collab_bgs = []

        collab_ids = self.get_collab_ids()
        for collab_id in collab_ids:
            file_name = f"img012_space_C_{collab_id:03}.png"
            # cut_name = f"img012_space_C_{collab_id:03}.imgcut"
            # if not game_data.find_file(cut_name):
            cut_name = f"img012_space.imgcut"
            bg = tbcml.Texture()
            bg.read_from_game_file_names(game_data, file_name, cut_name)
            self.cotc_collab_bgs.append(bg)

            file_name = f"img012_w_C_{collab_id:03}.png"
            cut_name = f"img012_w_C_{collab_id:03}.imgcut"
            # if not game_data.find_file(cut_name):
            cut_name = f"img012_w.imgcut"

            bg = tbcml.Texture()
            bg.read_from_game_file_names(game_data, file_name, cut_name)
            self.itf_collab_bgs.append(bg)

            file_name = f"img012_{lang}_C_{collab_id:03}.png"
            cut_name = f"img012_{lang}_C_{collab_id:03}.imgcut"
            # if not game_data.find_file(cut_name):
            cut_name = f"img012_{lang}.imgcut"

            bg = tbcml.Texture()
            bg.read_from_game_file_names(game_data, file_name, cut_name)
            self.main_collab_bgs.append(bg)

        self.main_bg = tbcml.Texture()
        self.main_bg.read_from_game_file_names(
            game_data, f"img012_{lang}.png", f"img012_{lang}.imgcut"
        )

        self.itf_bg = tbcml.Texture()
        self.itf_bg.read_from_game_file_names(
            game_data, f"img012_w.png", f"img012_w.imgcut"
        )

        self.cotc_bg = tbcml.Texture()
        self.cotc_bg.read_from_game_file_names(
            game_data, f"img012_space.png", f"img012_space.imgcut"
        )

    def apply_bgs(self, game_data: tbcml.GamePacks):
        if self.main_bg is not None:
            self.main_bg.apply(game_data)

        if self.itf_bg is not None:
            self.itf_bg.apply(game_data)

        if self.cotc_bg is not None:
            self.cotc_bg.apply(game_data)

        if self.main_collab_bgs is not None:
            for main_collab_bg in self.main_collab_bgs:
                main_collab_bg.apply(game_data)

        if self.itf_collab_bgs is not None:
            for itf_collab_bg in self.itf_collab_bgs:
                itf_collab_bg.apply(game_data)

        if self.cotc_collab_bgs is not None:
            for cotc_collab_bg in self.cotc_collab_bgs:
                cotc_collab_bg.apply(game_data)

    def apply_game_data(self, game_data: tbcml.GamePacks):
        if self.inquiry_code_text_1 is not None:
            game_data.localizable.set_string("autoSave_txt1", self.inquiry_code_text_1)

        if self.inquiry_code_text_2 is not None:
            game_data.localizable.set_string("autoSave_txt2", self.inquiry_code_text_2)

        if self.inquiry_code_text_3 is not None:
            game_data.localizable.set_string("autoSave_txt3", self.inquiry_code_text_3)

        if self.inquiry_code_text_4 is not None:
            game_data.localizable.set_string("autoSave_txt4", self.inquiry_code_text_4)

        if self.inquiry_code_text_5 is not None:
            game_data.localizable.set_string("autoSave_txt5", self.inquiry_code_text_5)

        if self.inquiry_code_text_6 is not None:
            game_data.localizable.set_string("autoSave_txt6", self.inquiry_code_text_6)

        self.apply_logos(game_data)
        self.apply_bgs(game_data)

        if self.chapter_button_texture is not None:
            self.chapter_button_texture.apply(game_data)

        if self.settings_texture is not None:
            self.settings_texture.apply(game_data)

        if self.button_texture is not None:
            self.button_texture.apply(game_data)
