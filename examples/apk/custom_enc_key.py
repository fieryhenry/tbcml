import tbcml

# following code is just an example of a modification:


class NewForm(tbcml.CatForm):
    def __init__(self):
        super().__init__(form_type=tbcml.CatFormType.FIRST)

        self.name = "cool name"
        self.description = ["cat that does stuff...", "example cat for tbcml"]


class NewCat(tbcml.Cat):
    def __init__(self):
        super().__init__(cat_id=0)

        self.set_form(NewForm())


loader = tbcml.ModLoader("en", "12.3.0")  # can be changed for other versions
loader.initialize_apk()

game_data = loader.get_game_packs()
apk = loader.get_apk()


mod = tbcml.Mod(
    "Custom Key Example",
    "fieryhenry",
    "Changes basic cat first form name and description + apk encryption key and iv",
)
cat = NewCat()
mod.add_modification(cat)

apk.set_app_name("Custom Key")
apk.set_package_name("jp.co.ponos.battlecatsen.customkey")

# this code is where you can customize iv and key:
# strings are sha256 hashed so they are the correct length
key = apk.create_key("somesupersecretkey")
iv = apk.create_iv("somesupersecretiv")

loader.apply(mod, custom_enc_key=key, custom_enc_iv=iv)

# loader.initialize_adb()
# loader.install_adb(run_game=True)
