import tbcml


class AssassinBearForm(tbcml.CatForm):
    def __init__(self, cat_id: int, game_data: "tbcml.GamePacks"):
        super().__init__(
            form_type=tbcml.CatFormType.THIRD
        )  # form type can be changed to change what form to replace

        enemy_release_id = 18  # enemy id is from enemy release order page of wiki, other enemy ids may be -2 this.

        deploy_icon_offset = (
            -35,
            30,
        )  # deploy icon offset specifies how many pixels (x,y) to offset the enemy icon inside the deploy icon box
        deploy_icon_scale = 3  # scale to increase enemy icon by.

        self.import_enemy_from_release_id(
            cat_id,
            enemy_release_id,
            game_data,
            deploy_icon_offset=deploy_icon_offset,
            deploy_icon_scale=deploy_icon_scale,
            # upgrade_icon_offset=... You can also reposition the upgrade icon offset and scale
            # upgrade_icon_scale=...
        )
        """
        I recommend creating your own deploy (especially upgrade) icon rather than
        using the default enemy icons, as the enemy icons are 64x64 and the
        deploy icons are 128x128 and the upgrade icons are 512x128, so they don't look too good

        ```
        self.deploy_icon = tbcml.BCImage.from_file("enter_path_here")
        self.upgrade_icon = tbcml.BCImage.from_file("enter_path_here")
        ```

        enemies don't have a recharge or cost value associated with them, so
        they have to be set manually if you want them to be different from
        the base cat

        ```python
        stats = self.get_stats()

        stats.recharge_time = 0
        stats.cost = 0
        ```
        """


class AssassinBear(tbcml.Cat):
    def __init__(self, game_data: "tbcml.GamePacks"):
        super().__init__(
            cat_id=0
        )  # cat id can be changed to change what cat to replace

        custom_form = AssassinBearForm(self.cat_id, game_data)
        self.set_form(custom_form)


loader = tbcml.ModLoader("en", "13.1.1")  # can be changed for other versions
loader.initialize()

game_data = loader.get_game_packs()
apk = loader.get_apk()

mod = tbcml.Mod()

mod.add_modification(AssassinBear(game_data))
