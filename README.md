# TBCModLoader

The Battle Cats Mod Loader (TBCML) is a python module for easily creating and managing mods for the mobile game The Battle Cats.

At the moment the tool is just a library, but I plan to make a GUI for it in the future.

Join my [discord server](https://discord.gg/MZUYbQAzMZ) for help, getting the latest updates, reporting bugs, and suggesting features.

I've spent so much time working on this project, but due to all of the re-writes and refactors, it really doesn't look like it. So I would really appricate it if you considered donating to my kofi:

[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/fieryhenry)

[![wakatime](https://wakatime.com/badge/user/ab1fc9e5-e285-49d1-8dc6-2f2e0198c8f6/project/0350bd63-7366-48f1-8a0d-72dab553a007.svg)](https://wakatime.com/badge/user/ab1fc9e5-e285-49d1-8dc6-2f2e0198c8f6/project/0350bd63-7366-48f1-8a0d-72dab553a007)

## Getting Started

### Installation

#### From pypi

```bash
pip install tbcml
```

#### From source

```bash
git clone https://github.com/fieryhenry/tbcml.git
cd tbcml
pip install -e .
```

### Basic Usage

Create `script.py`

```python
from tbcml.core import (
    CountryCode,
    GameVersion,
    Apk,
    GamePacks,
    Mod,
    ModEdit,
    CatFormType,
    Cat,
    CatForm,
)

# Choose the country code
cc = CountryCode.EN

# Choose a game version
gv = GameVersion.from_string("12.3.0")

# Get the apk
apk = Apk(gv, cc)
apk.download_apk()
apk.extract()

# Download server files data
apk.download_server_files()
apk.copy_server_files()

# Get the game data
game_packs = GamePacks.from_apk(apk)

# Create a mod id, or use an existing one
mod_id = Mod.create_mod_id()

# Create a mod, not all information is required
mod = Mod(
    name="Test Mod",
    author="Test Author",
    description="Test Description",
    mod_id=mod_id,
    mod_version="1.0.0",
    password="test",
)

# Define cat information
cat_id = 0
cat_form_type = CatFormType.FIRST

# Create a form with the name "Test Cat"
form = CatForm(cat_id, cat_form_type, name="Test Cat")

# Create a cat
cat = Cat(cat_id)

# Set the form
cat.set_form(cat_form_type, form)

# Create a mod edit
mod_edit = ModEdit(["cats", cat_id], cat.to_dict())

# Add the mod edit to the mod
mod.add_mod_edit(mod_edit)

# Add the mod to the game packs
apk.load_mods([mod], game_packs)

# open the apk folder in the file explorer (optional)
apk.output_path.open()

```

Run the script

Windows

```bash
py script.py
```

Everything else

```bash
python script.py
```

## Documentation

<https://tbcml-docs.readthedocs.io/en/latest/>
