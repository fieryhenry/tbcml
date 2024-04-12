import tbcml


class UltraForm(tbcml.CatForm):
    def __init__(self, parent_cat: tbcml.Cat):
        super().__init__(form_type=tbcml.CatFormType.FOURTH)
        self.sync(
            parent_cat, tbcml.CatFormType.THIRD
        )  # copy data from third form, not necessary if creating all original data

        stats = self.get_stats()
        stats.hp = 100000
        stats.cost = 100
        stats.attack_1_damage = 8000
        stats.speed = 100
        stats.attack_interval = 0
        stats.target_aku = True
        stats.wave_prob = 100
        stats.wave_level = 20

        self.name = "Cat Machine Mk 4"
        self.description = [
            "description line 1",
            "description line 2",
            "description line 3!",
        ]

        # just an example to see visually obvious changes
        self.get_deploy_icon().flip_x()
        self.get_upgrade_icon().flip_y()

        self.get_anim().flip_y()


class NewCat(tbcml.Cat):
    def __init__(self, game_data: tbcml.GamePacks):
        super().__init__(cat_id=43)  # Cat Machine
        self.read(game_data)

        ultra = UltraForm(self)
        evolve_items = [
            (44, 10),
            (161, 1),
        ]  # 10 gold catfruit, 1 aku catfruit, find item id from GatyaitemName.csv. If item id is not a valid catfruit, the game will crash when you try to evolve the cat
        self.add_ultra_form_catfruit_evol(
            ultra,
            evolve_items,
            evolve_id=25000,  # can be anything over 25000 i think
            evolve_cost=1000,
            evolve_level=35,
            evolve_text=["Evolve line 1", "Evolve line 2", "Evolve line 3!"],
            cat_guide_text=[
                "Once Lvl 35 is reached, use",
                "XP and Catfruit to Evolve.",
            ],
        )


loader = tbcml.ModLoader("en", "13.1.1")
loader.initialize_apk()

game_packs = loader.get_game_packs()

mod = tbcml.Mod()
mod.add_modification(NewCat(game_packs))
