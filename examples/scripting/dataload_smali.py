import tbcml

loader = tbcml.ModLoader("en", "12.3.0")
loader.initialize()

mod = tbcml.Mod(
    "Smali Code Injection",
    authors="fieryhenry",
    description="Injects DataLoad.smali into onCreate, loads 99999 cf save file",
)

apk = loader.get_apk()

smali_set = tbcml.SmaliHandler.java_to_smali(
    tbcml.Path("java").add(
        "com", "tbcml", "DataLoad.java"
    ),  # java is in java folder of repo
    "com.tbcml.DataLoad",
    "Start(Landroid/content/Context;)V",
)
if smali_set is None:
    raise ValueError("Failed to convert java code to smali code")

mod.add_smali_set(smali_set)
mod.add_apk_file(
    "assets/data.zip",
    local_path=tbcml.Path.get_asset_file_path(
        "data.zip"
    ),  # DataLoad loads data.zip into game folder on startup
)

apk.set_app_name("DataLoad Smali Injection")
apk.set_package_name("jp.co.ponos.battlecatsen.injection")

loader.apply(mod)

# loader.initialize_adb()
# loader.install_adb(run_game=False)
