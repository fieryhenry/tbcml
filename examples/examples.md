# Examples

Collection of examples for using tbcml.

Note that not all examples show the loader initialization or mod applying as it
is basically the same for all examples. The following code is used to initialize
the loader and apply the mod:

```python
import tbcml

loader = tbcml.ModLoader("en", "13.1.1") # Change to your language and version
loader.intialize_apk()

...
# Apply mod
loader.apply(mod)
```

## Examples

### Apk

- [Downloading and Extracting APKs](apk/download_and_extract.py)
- [Custom Encryption Key](apk/custom_enc_key.py)
- [Downloading Server Files](apk/download_server_files.py)
- [Asset Editing](apk/asset_edit.py)

### Cats

- [Edit Name and Description of Unit](cats/name_desc_edit.py)
- [Import Enemy as Unit](cats/import_enemy.py)
- [Edit Unit Stats](cats/stats_edit.py)
- [Add Ultra Form](cats/ultra_form.py)

### Scripting

- [Mailbox Hack Script](scripting/mailbox_hack.py)
- [Smali Injection](scripting/dataload_smali.py)
- [Antiban Script](scripting/antiban.py)

### BCU

- [Import BCU Cat](bcu/import_bcu_pack_cat.py)

### Map

- [Basic Stage Edit](map/basic_stage_edit.py)
- [Advanced Stage Edit](map/advanced_edit.py)

### Misc

- [Custom Shop Item](itemshop/catfood_item.py)
- [Custom Startup PONOS Logo](opening/custom_ponos_logo.py)
- [Custom Startup Loading Screen](opening/loading_screen.py)
- [Custom Main Menu Stuff](opening/main_menu.py)
