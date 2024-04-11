"""A module for injecting smali code into the APK."""

from __future__ import annotations

import tbcml


class Smali:
    """A class to represent a smali file."""

    def __init__(
        self,
        class_code: str,
        class_name: str,
        function_sig_to_call: str | None,
    ):
        """Initializes the Smali

        Args:
            class_code (str): The actual smali code
            class_name (str): The name of the class
            function_sig_to_call (str | None): The signature of the function to call in onCreate
        """
        self.class_code = class_code
        self.class_name = class_name
        self.function_sig_to_call = function_sig_to_call

    @staticmethod
    def from_file(
        path: tbcml.Path, class_name: str, function_sig_to_call: str
    ) -> Smali:
        """Creates a Smali from a smali file.

        Args:
            path (tbcml.Path): Path to the smali file
            class_name (str): Class name to use
            function_sig_to_call (str): The signature of the function to call to run the class code

        Returns:
            Smali: The created Smali
        """
        data = path.read().to_str()
        return Smali(data, class_name, function_sig_to_call)


class SmaliSet:
    """A class to represent a set of smali files."""

    def __init__(self, smali_edits: dict[str, Smali]):
        """Initializes the SmaliSet

        Args:
            smali_edits (dict[str, Smali]): The smali edits
        """
        self.smali_edits = smali_edits

    def is_empty(self) -> bool:
        """Checks if the SmaliSet is empty.

        Returns:
            bool: Whether the SmaliSet is empty
        """
        return len(self.smali_edits) == 0

    @staticmethod
    def create_empty() -> SmaliSet:
        """Creates an empty SmaliSet.

        Returns:
            SmaliSet: The created SmaliSet
        """
        return SmaliSet({})

    def add_to_zip(self, zip_file: tbcml.Zip):
        """Adds the SmaliSet to a mod zip.

        Args:
            zip_file (tbcml.Zip): The zip file to add the SmaliSet to
        """
        base_path = tbcml.Path(tbcml.ModPath.SMALI.value)
        for smali in self.smali_edits.values():
            json_data = tbcml.JsonFile.from_object(
                {"function_sig_to_call": smali.function_sig_to_call}
            )
            file_data = tbcml.Data(smali.class_code)
            path = base_path.add(*smali.class_name.split(".")[:-1])
            path = path.add(smali.class_name.split(".")[-1] + ".smali")
            zip_file.add_file(path, file_data)
            zip_file.add_file(path.change_extension("json"), json_data.to_data())

    @staticmethod
    def from_zip(zip_file: tbcml.Zip) -> SmaliSet:
        """Creates a SmaliSet from a mod zip.

        Args:
            zip_file (tbcml.Zip): The zip file to create the SmaliSet from

        Returns:
            SmaliSet: The created SmaliSet
        """
        base_path = tbcml.Path(tbcml.ModPath.SMALI.value)
        smali_edits: dict[str, Smali] = {}
        for file in zip_file.get_paths():
            if not file.path.startswith(base_path.to_str_forwards()):
                continue
            if not file.path.endswith(".smali"):
                continue

            path = tbcml.Path(file.path)
            class_name = path.remove_extension().to_str_forwards()
            json_file = zip_file.get_file(path.change_extension("json"))
            if json_file is None:
                continue

            json_data = tbcml.JsonFile.from_data(json_file)
            function_sig_to_call = json_data.get("function_sig_to_call")

            smali_edits[class_name] = Smali(
                file.to_str(), class_name, function_sig_to_call
            )
        return SmaliSet(smali_edits)

    def import_smali(self, other: SmaliSet):
        """Imports the smali from another SmaliSet.

        Args:
            other (SmaliSet): The SmaliSet to import from
        """
        self.smali_edits.update(other.smali_edits)

    def add(self, smali: Smali):
        """Adds a Smali to the SmaliSet.

        Args:
            smali (Smali): The Smali to add
        """
        self.smali_edits[smali.class_name] = smali

    def get_list(self) -> list[Smali]:
        """Gets the SmaliSet as a list.

        Returns:
            list[Smali]: The SmaliSet as a list
        """
        return list(self.smali_edits.values())


class SmaliHandler:
    """Injects smali into an apk.
    https://github.com/ksg97031/frida-gadget"""

    def __init__(self, apk: tbcml.Apk):
        """Initializes the SmaliHandler

        Args:
            apk (tbcml.Apk): The apk to inject into
        """
        self.apk = apk
        self.apk.extract_smali(decode_resources=self.apk.has_decoded_resources())
        self.main_activity = ["jp", "co", "ponos", "battlecats", "MyActivity.smali"]

    def find_main_activity_smali(self) -> tbcml.Path | None:
        """Finds the main activity smali file

        Returns:
            tbcml.Path | None: The path to the main activity smali file
        """
        target_smali = None
        for smali_dir in self.apk.extracted_path.glob("smali*/"):
            target_smali = smali_dir.add(*self.main_activity)
            if target_smali.exists():
                break
        return target_smali

    def setup_injection(self) -> tuple[list[str], tbcml.Path]:
        """Sets up the injection by finding the main activity smali file and reading it

        Raises:
            FileNotFoundError: If the main activity smali could not be found

        Returns:
            tuple[list[str], tbcml.Path]: The main activity smali code and the path to the smali file
        """
        target_smali = self.find_main_activity_smali()
        if target_smali is None:
            raise FileNotFoundError(
                f"Could not find main activity smali: {self.main_activity}"
            )
        text = target_smali.read().to_str()
        text = text.split("\n")

        return text, target_smali

    def inject_into_on_create(self, smali_codes: list[Smali]):
        """Injects the smali code into the main activity's onCreate method

        Args:
            smali_codes (list[Smali]): The smali code to inject

        Raises:
            FileNotFoundError: If the main activity smali could not be found
        """
        text, target_smali = self.setup_injection()

        smali_path = self.apk.extracted_path.add("smali")
        smali_path.generate_dirs()
        for smali_code in smali_codes:
            path = smali_path.add(*smali_code.class_name.split(".")[:-1])
            path = path.add(smali_code.class_name.split(".")[-1] + ".smali")
            path.parent().generate_dirs()
            path.write(tbcml.Data(smali_code.class_code))

        for i, line in enumerate(text):
            if line.startswith(".method") and "onCreate(" in line:
                for j, smali in enumerate(smali_codes):
                    if smali.function_sig_to_call is None:
                        continue
                    text.insert(
                        i + 2 + j,
                        f"    invoke-static {{p0}}, L{smali.class_name.replace('.', '/')};->{smali.function_sig_to_call}",
                    )
                break

        text = "\n".join(text)
        target_smali.write(tbcml.Data(text))

    def inject_load_library(self, library_name: str):
        """Injects the code to load a native library into the main activity's onCreate method

        Args:
            library_name (str): The name of the library to load
        """
        if library_name.startswith("lib"):
            library_name = library_name[3:]
        library_name = library_name.replace(".so", "")

        text, target_smali = self.setup_injection()

        inject_text = f"""
    const-string v0, "{library_name}"
    invoke-static {{v0}}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V

    const-string v0, "tbcml"
    const-string v1, "Loaded {library_name}"
    invoke-static {{v0, v1}}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I
    """

        for i, line in enumerate(text):
            if line.startswith(".method") and "onCreate(" in line:
                text.insert(i + 3, inject_text)

                # find .locals
                for j, line in enumerate(text[i:]):
                    if line.strip().startswith(".locals"):
                        current_count = int(line.strip().split(" ")[1])
                        text[i + j] = f"    .locals {current_count + 1}"
                        break

                break

        text = "\n".join(text)
        target_smali.write(tbcml.Data(text))

    def get_all_smali_files(self) -> list[tbcml.Path]:
        """Gets all smali files in the apk

        Returns:
            list[tbcml.Path]: The list of smali files
        """
        smali_files: list[tbcml.Path] = []
        for item in self.apk.extracted_path.recursive_glob("*.smali"):
            smali_files.append(item)
        return smali_files

    def replace_all_strings(self, old: str, new: str):
        """Replaces all instances of a string in the apk

        Args:
            old (str): The string to replace
            new (str): The string to replace it with
        """
        for smali_file in self.get_all_smali_files():
            orig_text = smali_file.read().to_str()
            new_text = orig_text.replace(old, new)
            if orig_text != new_text:
                smali_file.write(tbcml.Data(new_text))

    @staticmethod
    def get_data_load_smali() -> Smali:
        """Gets the smali code for the DataLoad class which is used to extract data.zip into the
        /data/data/jp.co.ponos.battlecats/files directory

        Returns:
            Smali: The smali code for the DataLoad class
        """
        path = tbcml.Path.get_asset_file_path("DataLoad.smali")
        data = path.read().to_str()
        return Smali(data, "com.tbcml.DataLoad", "Start(Landroid/content/Context;)V")

    @staticmethod
    def java_to_smali(
        java_code_path: tbcml.Path,
        class_name: str,
        func_sig: str,
        display_errors: bool = True,
        javac_class_path: tbcml.Path | None = None,
    ) -> SmaliSet | None:
        """Compiles java code into smali code

        Args:
            java_code (str): The java code to compile
            class_name (str): The name of the class
            func_sig (str): The function signature to call to start the class code
            display_errors (bool, optional): Whether to display errors if the compilation fails. Defaults to True.

        Returns:
            Smali | None: The compiled smali code. None if the compilation failed
        """
        if javac_class_path is not None:
            if not javac_class_path.is_valid():
                raise ValueError(f"Class path is invalid: {javac_class_path}")
        with tbcml.TempFolder() as temp_folder:
            java_path = temp_folder.add(*class_name.split(".")[:-1]).add(
                class_name.split(".")[-1] + ".java"
            )
            if not java_path.is_valid():
                raise ValueError(f"Java path is invalid: {java_path}")

            java_path.parent().generate_dirs()
            parents = len(class_name.split("."))
            top_level_path = java_code_path
            for _ in range(parents):
                top_level_path = top_level_path.parent()
            top_level_path.copy(temp_folder)
            if javac_class_path is not None:
                class_path_str = f"--class-path '{javac_class_path}'"
            else:
                class_path_str = ""

            cmd = f"javac --source 8 --target 8 '{java_path}' -d '{temp_folder}' {class_path_str}"
            command = tbcml.Command(
                cmd,
                cwd=temp_folder,
            )
            result = command.run()
            if result.exit_code != 0:
                if display_errors:
                    print(result.result)
                return None

            all_class_files = temp_folder.add(
                *class_name.split(".")[:-1]
            ).recursive_glob("*.class")
            class_files: list[str] = []
            classes_string = ""
            for class_file in all_class_files:
                if not class_file.is_valid():
                    raise ValueError(f"class file is invalid: {class_file}")
                full_class_name = class_file.path.replace(temp_folder.path, "")[1:]
                class_files.append(full_class_name)
                classes_string += f"'{full_class_name}' "
            classes_string = classes_string.strip()

            dex_folder = temp_folder.add("classes").generate_dirs()

            command = tbcml.Command(
                f"d8 --output '{dex_folder}' {classes_string}",
                cwd=temp_folder,
            )
            result = command.run()
            if result.exit_code != 0:
                if display_errors:
                    print(result.result)
                return None

            dex_path = temp_folder.add("classes.dex")
            dex_folder.add("classes.dex").copy(dex_path)

            dex_folder.remove()

            smali_path = temp_folder.add("smali")

            baksmali_path = tbcml.Path.get_lib("baksmali.jar")
            if not baksmali_path.is_valid():
                raise ValueError(f"Baksmali path is invalid: {baksmali_path}")
            command = tbcml.Command(
                f"java -jar '{baksmali_path}' d '{dex_path}' -o '{smali_path}'",
                cwd=temp_folder,
            )
            result = command.run()
            if result.exit_code != 0:
                if display_errors:
                    print(result.result)
                return None

            smali_objects: dict[str, Smali] = {}
            for class_ in class_files:
                class_name_ = class_.replace(".class", "")
                smali_path_ = smali_path.add(*class_name_.split(".")[:-1]).add(
                    class_name_.split(".")[-1] + ".smali"
                )
                smali_code = smali_path_.read().to_str()
                if class_name_ == class_name.replace(".", "/"):
                    smali_object = Smali(smali_code, class_name_, func_sig)
                else:
                    smali_object = Smali(smali_code, class_name_, None)
                smali_objects[class_name_] = smali_object
            return SmaliSet(smali_objects)

    def get_dex2jar_classes_jar_path_original(self) -> tbcml.Path:
        """Gets the path to the dex2jar classes.jar file

        Returns:
            tbcml.Path: The path to the dex2jar classes.jar file
        """
        return self.apk.smali_original_path.generate_dirs().add("d2j-classes.jar")

    def get_dex2jar_classes_jar_path_new(self) -> tbcml.Path:
        """Gets the path to the dex2jar classes.jar file

        Returns:
            tbcml.Path: The path to the dex2jar classes.jar file
        """
        return self.apk.smali_non_original_path.generate_dirs().add("d2j-classes.jar")

    def copy_original_smali(self):
        """Copies the original smali files to the smali_non_original folder"""
        self.apk.smali_original_path.generate_dirs().copy(
            self.apk.smali_non_original_path.generate_dirs()
        )

    def get_dex2jar_classes_path_original(self) -> tbcml.Path:
        """Gets the path to the dex2jar classes directory

        Returns:
            tbcml.Path: The path to the dex2jar classes directory
        """
        path = self.apk.smali_original_path.add("d2j-classes")
        path.generate_dirs()
        return path

    def get_dex2jar_classes_path_new(self) -> tbcml.Path:
        """Gets the path to the dex2jar classes directory

        Returns:
            tbcml.Path: The path to the dex2jar classes directory
        """
        path = self.apk.smali_non_original_path.add("d2j-classes")
        path.generate_dirs()
        return path

    def set_dex2jar_script_path(self, dex2jar_script_path: tbcml.Path):
        """Sets the path to the dex2jar script

        Args:
            dex2jar_script_path (tbcml.Path): The path to the dex2jar script
        """
        self.dex2jar_script_path = dex2jar_script_path

    def dex2jar(self):
        """Converts the apk to a jar file

        Args:
            dex2jar_script (tbcml.Path): The path to the dex2jar script
        """
        if self.get_dex2jar_classes_jar_path_original().exists():
            return
        if not self.dex2jar_script_path.is_valid():
            raise ValueError(
                f"Dex2jar script path is invalid: {self.dex2jar_script_path}"
            )
        command = tbcml.Command(
            f"'{self.dex2jar_script_path}' -f -o '{self.get_dex2jar_classes_jar_path_original()}' '{self.apk.pkg_path}'"
        )
        res = command.run()
        if res.exit_code != 0:
            print(res.result)
            raise RuntimeError("dex2jar failed")

    def java_folder_to_dot_class(
        self, java_folder: tbcml.Path, android_sdk_path: tbcml.Path
    ):
        for java_file in java_folder.recursive_glob("*.java"):
            self.java_to_dot_class(java_file, android_sdk_path)

    def java_to_dot_class(
        self, java_code_path: tbcml.Path, android_sdk_path: tbcml.Path
    ):
        """Converts java code to dot class files

        Args:
            java_code_path (tbcml.Path): The path to the java code
            class_name (str): The name of the class
        """
        if not android_sdk_path.is_valid():
            raise ValueError(f"Android SDK path is invalid: {android_sdk_path}")

        # find package {package name} in java code
        java_code_str = java_code_path.read().to_str()
        package_name = ""
        for line in java_code_str.split("\n"):
            if line.startswith("package "):
                package_name = line.split(" ")[1].replace(";", "")
                break
        package_name += "." + java_code_path.get_file_name_without_extension()

        with tbcml.TempFolder() as temp_folder:
            java_path = temp_folder.add(*package_name.split(".")[:-1]).add(
                package_name.split(".")[-1] + ".java"
            )

            if not java_path.is_valid():
                raise ValueError(f"Java path is invalid: {java_path}")

            java_path.parent().generate_dirs()
            parents = len(package_name.split("."))
            top_level_path = java_code_path
            for _ in range(parents):
                top_level_path = top_level_path.parent()
            top_level_path.copy(temp_folder)
            files_to_not_compile: list[str] = []
            for file in temp_folder.recursive_glob("*.java"):
                if file.read().to_str().splitlines()[0].strip() == "// DO NOT COMPILE":
                    files_to_not_compile.append(
                        file.path.replace(temp_folder.path, "").replace(".java", "")
                    )

            command = tbcml.Command(
                f"javac --source 7 --target 7 '{java_path}' -d '{temp_folder}' -bootclasspath '{android_sdk_path.add('android.jar')}' -classpath '{self.get_dex2jar_classes_jar_path_new()}'",
                cwd=temp_folder,
            )
            result = command.run()
            if result.exit_code != 0:
                print(result.result)
                raise RuntimeError("javac failed")

            class_files = temp_folder.recursive_glob("*.class")
            for class_file in class_files:
                class_name = (
                    class_file.path.replace(temp_folder.path, "")[1:]
                    .split("$")[0]
                    .replace(".class", "")
                )
                class_name = "/" + class_name
                if class_name in files_to_not_compile:
                    print(f"Skipping {class_name}")
                    continue

                path = self.get_dex2jar_classes_path_new().add(
                    *class_name.split("/")[:-1]
                )

                class_file.copy(path)

    def dex2jar_to_dot_class(self):
        """Converts the dex2jar jar file to dot class files"""
        if self.get_dex2jar_classes_path_original().get_files():
            return
        zip_file = tbcml.Zip.from_file(self.get_dex2jar_classes_jar_path_original())
        zip_file.extract(self.get_dex2jar_classes_path_original())

    def jar_to_dex(self, jar_path: tbcml.Path):
        """Converts a jar file to dex files

        Args:
            jar_path (tbcml.Path): The path to the jar file
        """
        zip_file = tbcml.Zip.from_file(jar_path)
        zip_file.extract(self.get_dex2jar_classes_path_new())

        self.classes_to_dex()

    def classes_to_dex(self):
        """Converts dot class files to dex files

        Args:
            path (tbcml.Path): The path to the dot class files
        """
        with tbcml.TempFolder() as temp_folder:
            command = tbcml.Command(
                f"d8 output '{temp_folder}' '{self.get_dex2jar_classes_path_new()}'"
            )
            res = command.run()
            if res.exit_code != 0:
                print(res.result)
                raise RuntimeError("d8 failed")

            for dex_file in temp_folder.recursive_glob("*.dex"):
                dex_file.copy(self.apk.extracted_path)
