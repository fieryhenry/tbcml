import tbcml


class NewForm(tbcml.CatForm):
    def __init__(self):
        super().__init__(form_type=tbcml.CatFormType.FIRST)

        self.name = "cool name"
        self.description = ["cat that does stuff...", "example cat for tbcml"]


class NewCat(tbcml.Cat):
    def __init__(self):
        super().__init__(cat_id=0)

        self.set_form(NewForm())


loader = tbcml.ModLoader("en", "12.3.0")
loader.initialize()


mod = tbcml.Mod(
    "Modded Cat Info Example",
    "fieryhenry",
    "Changes basic cat first form name and description",
)

mod.add_modification(NewCat())

apk = loader.get_apk()

apk.set_app_name("Modded Cat")
apk.set_package_name("jp.co.ponos.battlecats.moddedcat")

loader.apply(mod)

# loader.initialize_adb()
# loader.install_adb(run_game=True)
