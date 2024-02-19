# Changelog

## 2.0.0 (???)

Feature list is not complete, but here are some of the changes:

### Added

- ModLoader class to reduce boilerplate code when creating mods
- Support for different languages when using an en apk (e.g fr, es, it, de, th)
- Way to compile the mod to raw game files. This is useful to reduce the time it
  takes to apply the mod to the game and is useful when debugging mods
- Options to extract and pack the apk without using apktool
- More examples in the examples folder
- Different sources of apks to download from (e.g apkpure uptodown and
  archive.org)
- ADB support to install the modded apk to a device

### Changed

- Rewrote lots of the code to make the library easier to use and more
  maintainable
- The way you create game data mods, now you can create / inherit a class that
  is a subclass of Modifcation and set attributes on it to modify the object
  (e.g. `self.hp = 100`). These classes can be added to a mod easily with
  `mod.add_modification(modification)`.
- The code is more efficient, for example instead of copying the whole
  original_extracted folder to extracted, it now only copies the files that
  have been modified, also pack files are only read and decrypted when they are
  needed.

### Fixed

- Probably a lot of bugs due to the rewrite

## 1.1.0 (2023-11-22)

### Added

- Way to force extraction even if the apk is already extracted (1cc0de7)
- Option to not decode resources, should be used if apktool fails to pack the apk
  (7803877) and (608ddd8)

### Changed

- Moved lib file patching and smali injection to optional dependencies,
  tbcml[scripting]. Also moved any ui related dependencies to tbcml[ui].
  So now you can install tbcml without any of the optional dependencies
  if you don't need them. (3a593a6)
- In the CatStats class, renamed unknwon_52-55 to gatya_offset_y_1-4
  (9366cab)
- Added counter surge ability (e2d7e64)
- Defualt Apk folder is now in the documents folder 1e150ca
- Allow custom keys and ivs to be used when encrypting instead of being random
  (8444407)
- Apks can now be downloaded from a url specified in the BCData git repo instead
  of scraping from uptodown and other sites (download_v2()) (c6522df)

## 1.0.1.1 (2023-10-06)

### Fixed

- Downloading from uptodown (1aa400b), they keep changing their website
- moviepy not being installed (b784640)

## 1.0.1 (2023-10-04)

### Fixed

- Various animation and model related errors (ff7c7c8, cdd433a, bd775fe,
  9eb4c0a, 686460e)
- Downloading from uptodown (129c48a)

### Added

- dex2jar related features (64fb93a)
