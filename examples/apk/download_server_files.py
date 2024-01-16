import tbcml

apk = tbcml.Apk(game_version="12.3.0", country_code="en")

apk.download()
apk.extract()

apk.download_server_files()
# if you want to display download progress do:
# apk.download_server_files(display=True)

# if you want to download server files even if the files exist do:
# apk.download_server_files(force=True)

print(apk.get_server_path())
apk.get_server_path().open()
# not needed, but prints and opens the apk output path in a file manager
