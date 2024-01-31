from typing import Any, Optional
import tbcml


class CompilationTarget:
    def __init__(
        self,
        target_country_codes: str,
        target_game_versions: str,
        files: Optional[dict[str, "tbcml.Data"]] = None,
    ):
        """Initialize compilation target

        Args:
            target_country_codes (str): country codes this targets e.g `*` `en,jp,kr` `en` `!en,!kr`
            target_game_versions (str): game version this targets e.g `*` `12.3.0,13.0` `>13` `<=8.4`
            files (dict[str, tbcml.Data]): dictionary of file names and contents
        """
        self.target_country_codes = target_country_codes
        self.target_game_versions = target_game_versions
        if files is None:
            files = {}
        self.files = files

    def set_file(self, name: str, data: "tbcml.Data"):
        self.files[name] = data

    def add_to_zip(self, index: int, zipfile: "tbcml.Zip"):
        target_path = tbcml.Path(tbcml.ModPath.COMPILATION_TARGETS.value).add(
            f"{index}"
        )
        metadata_file_path = target_path.add("metadata.json")

        metadata: dict[str, Any] = {
            "target_country_codes": self.target_country_codes,
            "target_game_versions": self.target_game_versions,
        }

        metadata_dt = tbcml.JsonFile.from_object(metadata).to_data()

        zipfile.add_file(metadata_file_path, metadata_dt)

        files_path = target_path.add("files")

        for file_name, data in self.files.items():
            path = files_path.add(file_name)
            zipfile.add_file(path, data)

    @staticmethod
    def from_zip(index: int, zipfile: "tbcml.Zip"):
        target_path = tbcml.Path(tbcml.ModPath.COMPILATION_TARGETS.value).add(
            f"{index}"
        )
        metadata_file_path = target_path.add("metadata.json")

        metadata_file = zipfile.get_file(metadata_file_path)
        if metadata_file is None:
            return None

        metadata_obj = tbcml.JsonFile.from_data(metadata_file).get_json()

        target_country_codes = metadata_obj.get("target_country_codes")
        target_game_versions = metadata_obj.get("target_game_versions")
        if target_country_codes is None or target_game_versions is None:
            return None

        files: dict[str, "tbcml.Data"] = {}

        files_path = target_path.add("files")

        for path in zipfile.get_paths_in_folder(files_path):
            file = zipfile.get_file(path)
            if file is None:
                continue
            name = path.basename()

            files[name] = file

        return CompilationTarget(target_country_codes, target_game_versions, files)

    def check_country_code(self, cc: "tbcml.CountryCode"):
        cc_code = cc.get_code()
        cc_requesting_code = cc.get_request_code()
        codes = self.target_country_codes.split(",")
        for code in codes:
            code = code.lower().strip()
            if code == "*":
                return True
            if code.startswith("!"):
                exclude = code.split("!")[1]
                if exclude == cc_code or exclude == cc_requesting_code:
                    return False
            if code == cc_code or code == cc_requesting_code:
                return True

        return False

    def check_game_version(self, gv: "tbcml.GameVersion"):
        versions = self.target_game_versions.split(",")
        for version in versions:
            version = version.lower().strip()
            if version == "*":
                return True
            try:
                if version.startswith(">="):
                    version_gv = tbcml.GameVersion.from_string(
                        version[2:], raise_error=True
                    )
                    if gv >= version_gv:
                        return True
                elif version.startswith(">"):
                    version_gv = tbcml.GameVersion.from_string(
                        version[1:], raise_error=True
                    )
                    if gv > version_gv:
                        return True
                elif version.startswith("=="):
                    version_gv = tbcml.GameVersion.from_string(
                        version[2:], raise_error=True
                    )
                    if gv == version_gv:
                        return True
                elif version.startswith("="):
                    version_gv = tbcml.GameVersion.from_string(
                        version[1:], raise_error=True
                    )
                    if gv == version_gv:
                        return True
                elif version.startswith("<="):
                    version_gv = tbcml.GameVersion.from_string(
                        version[2:], raise_error=True
                    )
                    if gv <= version_gv:
                        return True
                elif version.startswith("<"):
                    version_gv = tbcml.GameVersion.from_string(
                        version[1:], raise_error=True
                    )
                    if gv < version_gv:
                        return True
                elif version.startswith("!="):
                    version_gv = tbcml.GameVersion.from_string(
                        version[2:], raise_error=True
                    )
                    if gv != version_gv:
                        return True
                elif version.startswith("!"):
                    version_gv = tbcml.GameVersion.from_string(
                        version[1:], raise_error=True
                    )
                    if gv != version_gv:
                        return True
                else:
                    version_gv = tbcml.GameVersion.from_string(
                        version, raise_error=True
                    )
                    if gv == version_gv:
                        return True
            except ValueError:
                return False
        return False

    def check_game_data(self, game_packs: "tbcml.GamePacks"):
        return self.check_country_code(
            game_packs.country_code
        ) and self.check_game_version(game_packs.gv)
