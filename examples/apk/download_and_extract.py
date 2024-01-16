import tbcml


apk = tbcml.Apk(game_version="12.3.0", country_code="en")

# if you want to disable scripting, smali injection or binary patching, for security reasons if you are loading untrusted mods then do:
# apk = tbcml.Apk(game_version="12.3.0", country_code="en", allowed_script_mods=False)

# if you want to change where the apks are stored and extracted to (default is Documents/tbcml/APKs/), then do:
# apk = tbcml.Apk(game_version="12.3.0", country_code="en", apk_folder=r"path_goes_here")

apk.download()

# if you don't want to display the progress bar do:
# apk.download(progress=None)

# if you want to always download the apk, even if one was already downloaded previously, do:
# apk.download(force=True)

apk.extract()

# if you don't want to decode resources (AndroidManifest.xml and resources.arsc) because packing the apk doesn't work, then do:
# apk.extract(decode_resources=False)

# if you want to always extract the apk, even if one was already extracted previously, do:
# apk.extract(force=True)

print(apk.output_path)
apk.output_path.open()

# not needed, but prints and opens the apk output path in a file manager
