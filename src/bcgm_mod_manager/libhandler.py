import hashlib
import os
import shutil

from . import config_handler, helper


def match(
    lib_hashes: list[str],
    real_hashes: list[str],
    real_files: list[str],
) -> dict[int, str]:
    """
    Match the hashes of the files in the library to the hashes of the files in the apk

    Args:
        lib_hashes (list[str]): The hashes of the files in the library
        real_hashes (list[str]): The hashes of the files in the apk
        real_files (list[str]): The paths to the files in the apk

    Returns:
        dict[int, str]: A dictionary mapping the index of the file in the library to the path to the file in the apk
    """
    indexes: dict[int, str] = {}
    for i in range(len(real_hashes)):
        if real_hashes[i] in lib_hashes:
            indexes[lib_hashes.index(real_hashes[i])] = os.path.basename(real_files[i])
    return indexes


def order_dict(d: dict[int, str]) -> dict[int, str]:
    """
    Order a dictionary by its keys

    Args:
        d (dict[int, str]): The dictionary

    Returns:
        dict[int, str]: The ordered dictionary
    """
    return {k: v for k, v in sorted(d.items(), key=lambda item: item[0])}


def search(data: bytes) -> tuple[list[str], list[tuple[int, str]]]:
    """
    Search for pack and list files in a byte array

    Args:
        data (bytes): The byte array

    Returns:
        tuple[list[str], list[tuple[int, str]]]: A list of file names and hashes
    """

    index = 0
    previous_index = 0
    files: list[str] = []
    for _ in range(1000):
        index = data.find(b".pack", index + 1)
        if index == -1:
            break
        if index - previous_index > 100 and previous_index != 0:
            break
        previous_index = index
        files.append(read_null_separated_string(data, index).decode("utf-8"))

    index = 0
    for _ in range(1000):
        index = data.find(b".list", index + 1)
        if index == -1:
            break
        files.append(read_null_separated_string(data, index).decode("utf-8"))

    hashes: list[tuple[int, str]] = []
    index = previous_index + 5
    for _ in range(1000):
        hash = read_null_separated_string(data, index)
        if len(hash) != 32:
            break
        hashes.append((index, hash.decode("utf-8")))
        index += 33

    return files, hashes


def read_null_separated_string(data: bytes, index: int) -> bytes:
    """
    Read a null-separated string from a byte array

    Args:
        data (bytes): The byte array
        index (int): The index to start reading from

    Raises:
        ValueError: If the string is too long

    Returns:
        bytes: The string
    """
    start = find_start_null(data, index)
    end = data.find(b"\0", start)
    if end == -1:
        raise ValueError("No null found")
    return data[start:end]


def find_start_null(data: bytes, index: int) -> int:
    """
    Find the index of the first null byte before the given index

    Args:
        data (bytes): The byte array
        index (int): The index to start searching from

    Returns:
        int: The index of the first null byte before the given index
    """

    while data[index] != 0:
        index -= 1
    return index + 1


def find_files_in_dir_pack(dir: str) -> tuple[list[str], list[str]]:
    """
    Find all the files in a directory and its subdirectories and return a list of their paths and hashes

    Args:
        dir (str): The path to the directory

    Returns:
        tuple[list[str], list[str]]: A list of the paths to the files and a list of their hashes
    """
    files: list[str] = []
    hashes: list[str] = []
    for root, _, names in os.walk(dir):
        for name in names:
            if name.endswith(".pack") or name.endswith(".list"):
                hashes.append(get_md5_hash(os.path.join(root, name)))
                files.append(os.path.join(root, name))
    return files, hashes


def get_md5_hash(path: str) -> str:
    """
    Get the md5 hash of a file

    Args:
        path (str): The path to the file

    Returns:
        str: The md5 hash
    """
    with open(path, "rb") as f:
        return hashlib.md5(f.read()).hexdigest()


def get_md5_hash_bytes(data: bytes) -> str:
    """
    Get the md5 hash of a byte array

    Args:
        data (bytes): The byte array

    Returns:
        str: The md5 hash
    """

    return hashlib.md5(data).hexdigest()


def get_orders(version: str, is_jp: bool, packs_path: str) -> dict[str, list[str]]:
    """
    Get the order of the files in the library for the given version and region

    Args:
        version (str): The version of the game
        is_jp (bool): True if the game is in Japan, False if not
        packs_path (str): The path to the packs folder

    Returns:
        dict[str, list[str]]: The order of the files in the library
    """
    lib_paths = get_lib_paths(version, is_jp)
    orders: dict[str, list[str]] = {}
    for arc, lib_path in lib_paths.items():
        data = helper.read_file_bytes(lib_path)
        _, lib_hashes = search(data)
        lib_hashes = [h[1] for h in lib_hashes]
        real_files, real_hashes = find_files_in_dir_pack(packs_path)
        order = list(order_dict(match(lib_hashes, real_hashes, real_files)).values())
        orders[arc] = order
    return orders


def get_lib_paths(version: str, is_jp: bool) -> dict[str, str]:
    """
    Get the paths to the library files for the given version and region

    Args:
        version (str): The version of the game
        is_jp (bool): True if the game is in Japan, False if not

    Returns:
        dict[str, str]: The paths to the library files
    """
    apk_folder = config_handler.get_config_setting("apk_folder")
    version_path = version + "jp" if is_jp else version

    lib_dir = os.path.join(apk_folder, version_path, "extracted", "lib")
    lib_folders = [
        os.path.join(lib_dir, f)
        for f in os.listdir(lib_dir)
        if os.path.isdir(os.path.join(lib_dir, f))
    ]
    lib_files: dict[str, str] = {}
    for folder in lib_folders:
        for file in os.listdir(folder):
            if file == "libnative-lib.so":
                lib_files[os.path.basename(folder)] = os.path.join(folder, file)
                break
    return lib_files


def get_packs_path(version: str, is_jp: bool) -> str:
    """
    Get the path to the packs folder for the given version and region

    Args:
        version (str): The version of the game
        is_jp (bool): True if the game is in Japan, False if not

    Returns:
        str: The path to the packs folder
    """
    apk_folder = config_handler.get_config_setting("apk_folder")
    version_path = version + "jp" if is_jp else version
    return os.path.join(apk_folder, version_path, "extracted", "assets")


def is_identical(file_name: str) -> bool:
    """
    Check if a file is identical to another file

    Args:
        file_name (str): The name of the file to check

    Returns:
        bool: True if the files are identical, False if not
    """
    langs = ["it", "es", "fr", "de"]
    base_hash = ""
    for lang in langs:
        name = f"{file_name[:-5]}_{lang}{file_name[-5:]}"
        if not os.path.exists(name):
            return False
        file_hash = get_md5_hash(name)
        if base_hash == "":
            base_hash = file_hash
        if base_hash != file_hash:
            return False
    return True


def patch_lib_file(version: str, is_jp: bool, pack_lists: list[str]) -> None:
    """
    Patch the library file for the given version and region

    Args:
        version (str): The version of the game
        is_jp (bool): True if the game is in Japan, False if not
        pack_lists (list[str]): The list of pack lists to use
    """
    pack_lists_data = [helper.read_file_bytes(pack_list) for pack_list in pack_lists]
    orders = get_orders(version, is_jp, get_packs_path(version, is_jp))
    langs = ["it", "es", "fr", "de"]
    lib_file_paths = get_lib_paths(version, is_jp)

    for arc, order in orders.items():
        arc = os.path.basename(arc)
        lib_file_path = lib_file_paths[arc]
        lib_file_data = helper.read_file_bytes(lib_file_path)
        _, hashes = search(lib_file_data)
        for i, pack_list_data in enumerate(pack_lists_data):
            index = -1
            try:
                index = order.index(os.path.basename(pack_lists[i]))
            except ValueError:
                try:
                    for lang in langs:
                        file_name = (
                            os.path.basename(pack_lists[i])[:-5]
                            + f"_{lang}"
                            + os.path.basename(pack_lists[i])[-5:]
                        )
                        index = order.index(file_name)
                        break
                except ValueError:
                    continue
            if index == -1:
                continue
            hash_index = hashes[index][0]
            # old_hash = hashes[index][1]
            new_hash = get_md5_hash_bytes(pack_list_data)
            lib_file_data = set_bytes(
                lib_file_data, hash_index + 1, new_hash.encode("utf-8")
            )
        files_to_copy: list[str] = []
        for file in pack_lists:
            if file.endswith(".pack") and file.split("_")[1][:2] not in langs:
                if is_identical(file):
                    files_to_copy.append(file)
                    files_to_copy.append(file.replace(".pack", ".list"))
        for file in files_to_copy:
            for lang in langs:
                file_name = f"{file[:-5]}_{lang}{file[-5:]}"
                shutil.copy(file, os.path.join(os.path.dirname(file), file_name))
        helper.write_file_bytes(lib_file_path, lib_file_data)


def set_bytes(data: bytes, index: int, value: bytes) -> bytes:
    """
    Set the bytes in a byte array to the given value

    Args:
        data (bytes): The byte array to modify
        index (int): The index to start modifying at
        value (bytes): The value to set the bytes to

    Returns:
        bytes: The modified byte array
    """
    data = data[:index] + value + data[index + len(value) :]
    return data
