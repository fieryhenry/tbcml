from tbcml import core


class AssassinBearForm(core.CatForm):
    def __init__(self, cat_id: int, game_data: "core.GamePacks"):
        super().__init__(
            form_type=core.CatFormType.FIRST
        )  # form type can be changed to change what form to replace

        enemy_release_id = 18  # enemy id is from renemy elease order page of wiki, other enemy ids may be -2 this.

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
        )
        """
        I recommend creating your own deploy icon rather than using the
        default enemy icons, as the enemy icons are 64x64 and the deploy
        icons are 128x128, so they don't look too good

        ```
        self.deploy_icon = core.NewBCImage.from_file("enter_path_here")
        ```

        enemies don't have a recharge or cost value associated with them, so
        they have to be set manually if you want them to be different from
        the base cat

        ```python
        stats = self.get_stats()

        stats.recharge_time.set(0)
        stats.cost.set(0)
        ```
        """


class AssassinBear(core.Cat):
    def __init__(self, game_data: "core.GamePacks"):
        super().__init__(
            cat_id=0
        )  # cat id can be changed to change what cat to replace

        custom_form = AssassinBearForm(self.cat_id, game_data)
        self.set_form(custom_form)


loader = core.ModLoader("en", "12.3.0")  # can be changed for other versions
loader.initialize()

game_data = loader.get_game_packs()
apk = loader.get_apk()

mod = core.Mod(
    "Assassin Bear Cat",
    "fieryhenry",
    "Replaces basic cat first form to be the assassin bear enemy",
)

cat = AssassinBear(game_data)
mod.add_modification(cat)

apk.set_app_name("Assassin Bear")
apk.set_package_name("jp.co.ponos.battlecats.assassinbear")

loader.apply(mod)
# loader.initialize_adb()
# loader.install_adb(run_game=True)
