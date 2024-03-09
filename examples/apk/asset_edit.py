import tbcml

loader = tbcml.ModLoader("en", "12.3.0")
loader.initialize()


mod = tbcml.Mod(
    "Modded apk asset Example",
    "fieryhenry",
    "Changes user info screen",
)
local_path = (
    tbcml.Path(__file__).parent().add("modded_user_info.html")
)  # modded_user_info.html is in the same folder
mod.add_pkg_asset(
    asset_path="user_info_en.html",
    local_f=local_path,
)

apk = loader.get_apk()

apk.set_app_name("Modded Asset")
apk.set_package_name("jp.co.ponos.battlecatsen.moddedasset")

loader.apply(mod)

# loader.initialize_adb()
# loader.install_adb(run_game=True)
