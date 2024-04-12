import tbcml

loader = tbcml.ModLoader("en", "13.1.1")
loader.initialize_apk()

mod = tbcml.Mod(
    "Antiban",
    "fieryhenry",
    "A mod that prevents bans by preventing the game from sending item data to the server.",
)

script_path = tbcml.Path(__file__).parent().add("antiban.js")

script = tbcml.FridaScript(
    "Antiban",
    script_path.read().to_str(),
    architectures="all",
    description="Intercepts the libc open call when reading BACKUP_META_DATA to always return -1, preventing writes and reads to the file, so the game can't send the item data to the server.",
)
mod.add_script(script)

apk = loader.get_apk()
apk.set_package_name("jp.co.ponos.battlecats.antiban")
apk.set_app_name("Antiban")

loader.apply(mod)

# loader.initialize_adb()
# loader.install_adb(run_game=True)
