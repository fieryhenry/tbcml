# Changelog

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
  of scraping from uptodown and other sites (download_v2()) (b1b5b3a)

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
