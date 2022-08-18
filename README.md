# Battle Cats Mod Manager

## Introduction

The battle cats mod manager is a tool for easily loading and managing mods into The Battle Cats APK.

Join the [discord server](https://discord.gg/DvmMgvn5ZB) if you want to suggest new features, report bugs or get help on how to use the modding tool (please read the below tutorials first before asking for help).

[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/M4M53M4MN)

## Thanks to:

- EasyMoneko for the original keys for decrypting/encrypting: https://www.reddit.com/r/battlecats/comments/41e4l1/is_there_anyone_able_to_access_bc_files_your_help/

## Getting Started

#### Prerequisites

To get started loading mods The Battle Cats you will also need the following software:

###### Download

- [Python](https://www.python.org/downloads/)

- [Java JDK](https://www.oracle.com/uk/java/technologies/javase/jdk11-archive-downloads.html)

- [Apktool](https://ibotpeaches.github.io/Apktool/install/)

###### Installation

Run the following command:

```batch
python -m pip install -U bcgm_mod_manager
```

If you are using windows you will most likely need to use `py` instead of `python`.

###### Run

Run the following command:

```batch
python -m bcgm_mod_manager
```

If you are using windows you will most likely need to use `py` instead of `python`.



## Mods and Mod Packs

### Mods

Mods are in the format of a `.bcmod` file and can be shared and imported with the `Load mods from .bcmod files` option.

You can find examples of mods here: [link]()

All mods are automatically enabled when they are loaded, but can be disabled with the option to `Disable mods`. These won't be loaded into the game apk.

You can view your mods with the `Display mods` option.

##### Create a Mod

To create a mod you will need some game files. To get them you can use the `Decrypt all local game files` option. At the moment, this only includes local files (Contains all game data except the majority of the images and animations).

Then you will need to modify those files, to do this you can use this tool here: [BCGM-Python](https://github.com/fieryhenry/BCGM-Python) to edit cat, enemy and stage data. In the future this will be moved into this tool as well as with the ability to edit a wider variety of game files.

Once you have your modded files, use the option in the tool to `Create mod from game files`. Then input the required information and select your custom files.



##### Load Mods Into the Game

To load your mods into the game, first select what mods you want by enabling / disabling certain mods by using the options in the tool.

Then select the option to `Load enabled mods into apk`, and say whether or not you are using the jp version of the game.

You will need to wait a while for it to download the apk, extract files, encrypt mods and sign the apk.

Once finished you can say `y` to open the containing folder. It will be called `modded.apk`.

You can then install the apk like normal.

The opening text will have information about what mods are currently loaded

---

### Mod Packs

Mod Packs are in the form of a `.bcmodpack` file and are collections of mods.

They can be imported with the `Load mod packs from .bcmodpack files as mods` option and the mods will be unpacked and enabled

At the moment they don't really have much functionality, but in the future they could act as a group that can be added to, removed from and show separately in the opening game text.

##### Create a Mod Pack

To create a mod pack, first enable the mods you want and disable the mods you don't want in the mod pack with the `Enable mods` and `Disable mods` options.

Then select the option to `Create mod pack of enabled mods`. Enter all of the required information.

Once finished you can say `y` to open the containing folder. It will be called `{author}-{name}.bcmodpack`.



### Todo

- [ ] Download and decrypt server pack files

- [ ] Ability to modify some game files

- [ ] Add more functionality to mod packs

- [ ] Mod browser
