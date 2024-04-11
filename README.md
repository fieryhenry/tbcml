# TBCML

The Battle Cats Modding Library (TBCML) is a python library designed to make
modding The Battle Cats easier, more automated, and more powerful.

Because the package is a library and you will need to have
programming experience if you want to use it effectively.

Most features are not documented yet and many may not work properly atm.

## Credits

- EasyMoneko for the original keys for decrypting/encrypting:
  <https://www.reddit.com/r/battlecats/comments/41e4l1/is_there_anyone_able_to_access_bc_files_your_help/>
- Battle Cats Ultimate for what some of the numbers mean in various csvs,
  helping me to figure out animation rendering, and for providing the empty form
  icons:  <https://github.com/battlecatsultimate>
- This resource for unit csvs: <https://pastebin.com/JrCTPnUV>
- Vi for enemy csvs

## Functionality

Note that most of these features are a work in progress and may not work
properly.

- [Downloading and extracting apks](examples/apk/download_and_extract.py)
- [Downloading server files](examples/apk/download_server_files.py) and event data
- Decryption and encryption of pack files
- Parsing of various game data files
- [Modification of game data](examples/cats/name_desc_edit.py)
- [Frida gadget hooking](examples/scripting/mailbox_hack.py)
- [Smali code injection](examples/scripting/dataload_smali.py)
- [Java to smali code conversion](examples/scripting/dataload_smali.py)
- [Patching of libnative-lib.so file](examples/scripting/mailbox_ps.py)
- [Modification of apk assets](examples/apk/asset_edit.py)
- [BCU Pack Imports](examples/bcu/import_bcu_pack_cat.py)
- Repacking and signing of modified apks
- [Custom encryption key and iv](examples/apk/custom_enc_key.py)

Note that the scripting functionality is very limited, especially in later
game versions (> 8.4.0) as function and class names have been stripped from the
binary.

Discord: <https://discord.gg/DvmMgvn5ZB> (The server is the same one which is
used for save editing as I haven't made a modding specific one
yet)

I've spent so much time working on this project because I've changed my mind on
what this library should do and how to structure it, but due to all of the
re-writes, it really doesn't look like it. So I would really appricate it if you
considered donating to my kofi:

[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/fieryhenry)

[![wakatime](https://wakatime.com/badge/github/fieryhenry/tbcml.svg)](https://wakatime.com/badge/github/fieryhenry/tbcml)

## Getting Started

### Installation

To install on android see [Install on Android](#install-on-android)

- Install [python](https://www.python.org/downloads/) (3.9 or later)

#### From source (recommended)

- Install [git](https://git-scm.com/downloads)

```bash
git clone https://github.com/fieryhenry/tbcml.git
cd tbcml
pip install -r requirements_scripting.txt
pip install -e .
```

You don't need to install the requirements_scripting.txt if you don't want to
use the scripting features.

#### From pypi

```bash
pip install tbcml
```

If you want scripting (frida scripting or libnative patching), you will
also need to install tbcml[scripting]

```bash
pip install tbcml[scripting]
```

### Basic Usage

You can obviously do more advanced things with this library, but this is just a
basic example of how to use it.

I don't have time to create a bunch of examples and the documentation is not
finished, so you'll probably have to read the source code to figure out how to
do more advanced things.

Create `script.py`

```python
import tbcml


class BasicCustomForm(tbcml.CatForm):
    """For better organization, these classes could be defined in
    another / separate files and then imported.

    See game_data/cat_base/cats.py for documetation of cats
    """

    def __init__(self):
        super().__init__(form_type=tbcml.CatFormType.FIRST, name="Cool Cat")

        # you can either set properties in the constructor as shown above, or
        # like this:

        self.description = ["First line!", "Second Line!", "Third description line!"]
        
        # note that if you use .read() it will overwrite any previously defined
        # values, so you may not be able to put the values in the constructor
        # if you want to use .read()


class BasicCustomCat(tbcml.Cat):
    def __init__(self):
        super().__init__(cat_id=0)

        first_form = BasicCustomForm()
        self.set_form(first_form)


loader = tbcml.ModLoader(
    "en", "12.3.0"
)  # these can be changed for the version you want
loader.initialize()

apk = loader.get_apk()

mod = tbcml.Mod(
    name="Test Mod",
    authors="fieryhenry",  # can be a list of authors e.g ["person 1", "person 2"]
    short_description="Test Description",
)

cat = BasicCustomCat()
mod.add_modification(cat)

mod.save("test.zip") # save the mod to a zip file (optional)

apk.set_app_name("The Battle Cats Basic Mod")

# package name should be different to base game if you want your modded app
# to not replace the normal app.
apk.set_package_name("jp.co.ponos.battlecats.basicmod")

# set open_path to True if you want to open the containg folder of the modded apk
loader.apply(mod, open_path=False)

print(apk.final_pkg_path)
```

If apktool isn't supported for your achitecture, you can set
`use_apktool=False` when creating the apk object / initializing the loader. This
will just extract the apk like a zip file and then repackage it like a zip file.

However, this does not decode the resources, so you will not be able to modify
stuff such as the app name, package name, or other resources. You can still
modify the game data though. In the future, I may add support for decoding and
encoding resources without apktool.

```python
loader.initialize(use_apktool=False)
```

If you want to modify a different langauge and you are using an en apk, you can
change the language when you initialize the loader. Valid langs are "fr", "it",
"de", "es", and "th".

```python
loader.initialize(lang="fr")
```

If you don't want to use inheritance, then you can structure the code like this:

```python
...
cat = tbcml.Cat(cat_id=0)
form = tbcml.CatForm(form_type=tbcml.CatFormType.FIRST, name="Cool Cat")
form.description = ["First line!", "Second Line!", "Third description line!"]
cat.set_form(form)
mod.add_modification(cat)
...
```

If you want to do disable script modding (e.g for security reasons), you will
need to set `allowed_script_mods` to `False` when creating the apk object /
initializing the loader

```python
loader.initialize(allowed_script_mods=False)
```

If you have a large mod, you may want to compile the modifications into raw game
files so that it is faster to load the mod (Also useful when debugging). You can
do this by running the following code:

```python
target = tbcml.CompilationTarget(
    target_country_codes="en", target_game_versions="12.3.0"
)
mod.compile_modifications(loader.get_game_packs(), existing_target=target)
```

Note that at the moment, this does not merge changes from multiple mods, so if 2
mods have changes to the same file, only the changes from the last mod will be
used.

The target_country_codes is a list of country codes (e.g "en,jp,kr,tw")
or you can put a `!` in front of the country code to exclude it (e.g
`!jp`). You can put a `*`in front of the country code to match any country code.

The target_game_versions is a list of game versions (e.g "11.3.0,12.3.0") or
you can put a `!` in front of the game version to exclude it (e.g `!11.3.0`).
You can put a `*`in front of the game version to match any game version. You can
also use the `>` and `<` operators to match any version greater than or less
than the specified version (and `>=` and `<=`).

There is some basic support for iOS ipa files:
  
```python
loader = tbcml.IpaModLoader("en", "12.3.0")

# you need to specify the path to the ipa as it can't be downloaded
loader.initialize(pkg_path="path/to/ipa")

ipa = loader.get_ipa()

# ... rest of the code is the same
```

Run the script

Windows

```bash
py script.py
```

Everything else

```bash
python3 script.py
```

You can then install the apk on your device. If the apk fails to install, you
may need to uninstall the previous version first.

## Install on Android

- Termux (via [F-Droid](https://f-droid.org/en/packages/com.termux/)) You cannot
  use the play store version as it doesn't work
- Make sure you download "Termux Terminal emulator with packages"
- Then run the following commands:
  
  ```bash
  termux-setup-storage
  termux-change-repo
  pkg upgrade
  ```

  When prompted for a mirror, any of them should work (pick recommended
  mirrors if they exist, but if they don't, then I picked "GH Mirrors
  by Kcubeterm" and it seemed to work fine)

  Then run the following commands:

  ```bash
  pkg install python
  pkg install binutils
  pkg install rust
  pkg install openjdk-17
  pkg install aapt
  pkg install apksigner
  pkg install git
  pkg install cmake
  ```

  rust and binutils are needed to build the cryptography package btw, the library
  is not written in it. cmake is used to build leif and so is only needed if you
  want scripting capabilities. git is not strictly necessary but is needed to
  instal the library from source.

  If you want scripting you may have to manually install lief
  with pip (`pip install lief`) as newer versions of those libraries don't exist
  on termux for some reason. Lief may take a very long time to compile.

  Also to get lief working you may need to run the following commands:

  ```bash
  pkg install patchelf
  patchelf --add-needed libpython3.11.so /data/data/com.termux/files/usr/lib/python3.11/site-packages/lief.cpython-311.so
  patchelf --add-needed libandroid.so /data/data/com.termux/files/usr/lib/python3.11/site-packages/lief.cpython-311.so
  ```

  You may need to change the python version in the above commands if you are
  using a different version of python.

  You can then install the library from source [here](#from-source-recommended)
  (recommended) or from pypi [here](#from-pypi).
  
  I recommend adding
  
  ```python
  loader.copy_to_android_download_folder()
  ```

  to the end of your script so that the final apk is copied to your downloads
  folder. Then you can install it with a file manager.

## Documentation (Not Finished)

For examples see [examples.md](examples/examples.md). Note that some may need the
latest commit to work (see [install from source](#from-source-recommended))

<https://tbcml-docs.readthedocs.io/en/latest/>
