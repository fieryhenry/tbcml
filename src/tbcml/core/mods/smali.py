from typing import Optional
from androguard.core.bytecodes.apk import APK  # type: ignore
from tbcml.core import io


class Smali:
    """Represents a smali class to inject into the main activity's onCreate method"""

    def __init__(self, class_code: str, class_name: str, function_sig_to_call: str):
        """Initializes the Smali

        Args:
            class_code (str): The actual smali code
            class_name (str): The name of the class
            function_sig_to_call (str): The signature of the function to call in onCreate
        """
        self.class_code = class_code
        self.class_name = class_name
        self.function_sig_to_call = function_sig_to_call

    @staticmethod
    def from_file(path: io.path.Path, class_name: str, function_sig_to_call: str):
        data = path.read().to_str()
        return Smali(data, class_name, function_sig_to_call)


class SmaliSet:
    def __init__(self, smali_edits: dict[str, Smali]):
        self.smali_edits = smali_edits

    @staticmethod
    def create_empty() -> "SmaliSet":
        return SmaliSet({})

    def add_to_zip(self, zip_file: "io.zip.Zip"):
        base_path = io.path.Path("smali")
        for smali in self.smali_edits.values():
            json_data = io.json_file.JsonFile.from_object(
                {"function_sig_to_call": smali.function_sig_to_call}
            )
            file_data = io.data.Data(smali.class_code)
            path = base_path.add(*smali.class_name.split(".")[:-1])
            path = path.add(smali.class_name.split(".")[-1] + ".smali")
            zip_file.add_file(path, file_data)
            zip_file.add_file(path.change_extension("json"), json_data.to_data())

    @staticmethod
    def from_zip(zip_file: "io.zip.Zip") -> "SmaliSet":
        base_path = io.path.Path("smali")
        smali_edits = {}
        for file in zip_file.get_paths():
            if not file.path.startswith(base_path.to_str_forwards()):
                continue
            if not file.path.endswith(".smali"):
                continue

            path = io.path.Path(file.path)
            class_name = path.remove_extension().to_str_forwards()
            json_file = zip_file.get_file(path.change_extension("json"))
            if json_file is None:
                continue

            json_data = io.json_file.JsonFile.from_data(json_file)
            function_sig_to_call = json_data.get("function_sig_to_call")
            if function_sig_to_call is None:
                continue

            smali_edits[class_name] = Smali(
                file.to_str(), class_name, function_sig_to_call
            )
        return SmaliSet(smali_edits)

    def import_smali(self, other: "SmaliSet"):
        self.smali_edits.update(other.smali_edits)

    def add(self, smali: Smali):
        self.smali_edits[smali.class_name] = smali

    def get_list(self) -> list[Smali]:
        return list(self.smali_edits.values())


class SmaliHandler:
    """Injects smali code into the main activity's onCreate method. Some code and inspiration from
    https://github.com/ksg97031/frida-gadget"""

    def __init__(self, apk: "io.apk.Apk"):
        """Initializes the SmaliHandler

        Args:
            apk (io.apk.Apk): The apk to inject into

        Raises:
            FileNotFoundError: If the main activity could not be found
        """
        self.apk = apk
        self.apk.extract_smali()
        self.andro_apk = APK(self.apk.apk_path.path)
        main_activity: str = self.andro_apk.get_main_activity()  # type: ignore
        if main_activity is None:  # type: ignore
            raise FileNotFoundError("Could not find main activity")
        main_activity_list = main_activity.split(".")
        main_activity_list[-1] += ".smali"
        self.main_activity = main_activity_list

    def find_main_activity_smali(self) -> Optional[io.path.Path]:
        """Finds the main activity smali file

        Returns:
            Optional[io.path.Path]: The path to the main activity smali file
        """
        target_smali = None
        for smali_dir in self.apk.extracted_path.glob("smali*/"):
            target_smali = smali_dir.add(*self.main_activity)
            if target_smali.exists():
                break
        return target_smali

    def inject_into_on_create(self, smali_codes: list[Smali]):
        """Injects the smali code into the main activity's onCreate method

        Args:
            smali_codes (list[Smali]): The smali code to inject

        Raises:
            FileNotFoundError: If the main activity smali could not be found
        """
        target_smali = self.find_main_activity_smali()
        if target_smali is None:
            raise FileNotFoundError(
                f"Could not find main activity smali: {self.main_activity}"
            )
        text = target_smali.read().to_str()
        text = text.split("\n")

        path = self.apk.extracted_path.add("smali").add("com").add("tbcml")
        path.generate_dirs()
        for smali_code in smali_codes:
            path = path.add(smali_code.class_name + ".smali")
            path.write(io.data.Data(smali_code.class_code))

        for i, line in enumerate(text):
            if line.startswith(".method") and "onCreate(" in line:
                for j, smali in enumerate(smali_codes):
                    text.insert(
                        i + 2 + j,
                        f"    invoke-static {{p0}}, Lcom/tbcml/{smali.class_name};->{smali.function_sig_to_call}",
                    )
                break

        text = "\n".join(text)
        target_smali.write(io.data.Data(text))

    def get_data_load_smali(self) -> Smali:
        """Gets the smali code for the DataLoad class which is used to extract data.zip into the
        /data/data/jp.co.ponos.battlecats/files directory

        Returns:
            Smali: The smali code for the DataLoad class
        """
        path = io.asset_loader.AssetLoader.from_config().get_asset_file_path(
            "DataLoad.smali"
        )
        data = path.read().to_str()
        return Smali(data, "DataLoad", "Start(Landroid/content/Context;)V")
