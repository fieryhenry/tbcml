from tbcml import core


class NewForm(core.CustomForm):
    def __init__(self):
        super().__init__(form_type=core.CatFormType.FIRST)

        self.name.set("cool name")
        self.description.set(["cat that does stuff...", "example cat for tbcml"])


class NewCat(core.CustomCat):
    def __init__(self):
        super().__init__(cat_id=0)

        self.set_form(NewForm())


loader = core.NewModLoader("en", "12.3.0")
loader.initialize()


mod = core.NewMod(
    "Modded Cat Info Example",
    "fieryhenry",
    "Changes basic cat first form name and description",
)

mod.add_modification(NewCat())

apk = loader.get_apk()

apk.set_app_name("Modded Cat")
apk.set_package_name("jp.co.ponos.battlecats.moddedcat")

loader.apply(mod)

loader.initialize_adb()
loader.install_adb(run_game=True)
