from enum import Enum
from multiprocessing import Process
import os
from typing import Any, Optional
import zipfile
from Cryptodome.Cipher import AES
import hashlib
import yaml
import colored  # type: ignore

from tkinter import filedialog, Tk
import requests


class Color(Enum):
    GREEN = "#008000"
    RED = "#FF0000"
    DARK_YELLOW = "#D7C32A"
    BLACK = "#000000"
    WHITE = "#FFFFFF"
    CYAN = "#00FFFF"


def read_file_bytes(file_path: str) -> bytes:
    """
    Read a file and return its contents as bytes

    Args:
        file_path (str): Path to file to read

    Returns:
        bytes: Contents of file
    """
    check_file_exists(file_path)
    with open(file_path, "rb") as fh:
        return fh.read()


def colored_input(
    message: str, base: Color = Color.WHITE, new: Color = Color.DARK_YELLOW
) -> str:
    """
    Get input from the user with colors

    Args:
        message (str): Message to display to user
        base (Color): Base color to use. Defaults to Color.WHITE.
        new (Color): New color to use. Defaults to Color.DARK_YELLOW.

    Returns:
        str: Input from user
    """
    colored_text(message, base, new, end="")
    return input()


def select_files(
    title: str,
    file_types: list[tuple[str, str]] = [("All Files", "*")],
    initial_dir: str = ".",
) -> list[str]:
    """
    Select files to open

    Args:
        title (str): Title of dialog
        file_types (list[tuple[str, str]], optional): File types to allow. Defaults to [("All Files", "*")].
        initial_dir (str, optional): Initial directory to open in. Defaults to ".".

    Returns:
        list[str]: Paths to files selected
    """
    root = Tk()
    root.withdraw()
    root.wm_attributes("-topmost", 1)  # type: ignore
    files = filedialog.askopenfilenames(
        title=title,
        filetypes=file_types,
        initialdir=initial_dir,
    )
    root.destroy()
    if files is None:
        return []
    return list(files)


def save_file(initial_file: str = "") -> str:
    """
    Get the path to a file to save to

    Returns:
        str: Path to file saved
    """
    root = Tk()
    root.withdraw()
    root.wm_attributes("-topmost", 1)  # type: ignore
    file_path = filedialog.asksaveasfilename(
        title="Save file",
        filetypes=[("All Files", "*")],
        initialdir=".",
        initialfile=initial_file,
    )
    root.destroy()
    return file_path


def check_file_exists(file_path: str) -> None:
    """
    Check if a file exists and raise an error if it doesn't

    Args:
        file_path (str): Path to file to check

    Raises:
        FileNotFoundError: If file doesn't exist
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(
            f"File {file_path} does not exist. Please check the path."
        )


def write_file_bytes(file_path: str, data: bytes) -> None:
    """
    Write bytes to a file

    Args:
        file_path (str): Path to file to write
        data (bytes): Bytes to write to file
    """
    check_file_exists(os.path.dirname(file_path))
    with open(file_path, "wb") as fh:
        fh.write(data)


def add_pkcs7_padding(data: bytes, block_size: int = 16) -> bytes:
    """
    Add PKCS#7 padding to data with error handling

    Args:
        data (bytes): Data to add padding to
        block_size (int, optional): Block size to pad to. Defaults to 16.

    Returns:
        bytes: Data with padding
    """
    padding_size = block_size - (len(data) % block_size)
    return data + bytes([padding_size] * padding_size)


def get_aes(jp: bool, pk_name: str) -> Any:
    """
    Get AES object based on whether or not we are using the jp version and the name of the pack file

    Args:
        jp (bool): Whether or not we are using the jp version
        pk_name (str): Name of the pack file

    Returns:
        Any: AES object
    """
    aes_mode = AES.MODE_CBC
    if jp:
        key = bytes.fromhex("d754868de89d717fa9e7b06da45ae9e3")
        iv = bytes.fromhex("40b2131a9f388ad4e5002a98118f6128")
    else:
        key = bytes.fromhex("0ad39e4aeaf55aa717feb1825edef521")
        iv = bytes.fromhex("d1d7e708091941d90cdf8aa5f30bb0c2")
    if "server" in pk_name.lower():
        aes_mode = AES.MODE_ECB
        iv = None
        key = get_md5("battlecats")[:16].encode("utf-8")
    if iv:
        cipher = AES.new(key, aes_mode, iv)  # type: ignore
    else:
        cipher = AES.new(key, aes_mode)  # type: ignore
    return cipher


def get_md5(string: str) -> str:
    """
    Get the md5 hash of a string

    Args:
        string (str): String to get md5 hash of

    Returns:
        str: MD5 hash of string
    """

    m = hashlib.md5()
    m.update(string.encode("utf-8"))
    return m.hexdigest()


def remove_pkcs7_padding(data: bytes) -> bytes:
    """
    Remove PKCS#7 padding from data

    Args:
        data (bytes): Data to remove padding from

    Returns:
        bytes: Data without padding
    """

    if len(data) % 16 != 0:
        return data
    padding_size = data[-1]
    if padding_size < 1 or padding_size > 16:
        return data
    if data[-padding_size:] != bytes([padding_size] * padding_size):
        return data
    return data[:-padding_size]


def list_to_csv(list_of_lists: list[list[Any]], delimiter: str = ",") -> str:
    """
    Convert a list of lists to a csv string

    Args:
        list_of_lists (list[list[Any]]): List of lists to convert to csv string
        delimiter (str, optional): Delimiter to use. Defaults to ",".

    Returns:
        str: CSV string
    """
    csv = ""
    for i in range(len(list_of_lists)):
        if type(list_of_lists[i]) != list:
            csv += f"{list_of_lists[i]}"
        else:
            for j in range(len(list_of_lists[i])):
                csv += str(list_of_lists[i][j])
                if j != len(list_of_lists[i]) - 1:
                    csv += delimiter
        csv += "\r\n"
    return csv


def check_dir(dir_path: str) -> None:
    """
    Check if a directory exists and create it if it doesn't

    Args:
        dir_path (str): Path to directory to check
    """
    if not os.path.exists(dir_path):
        os.makedirs(dir_path)

def download_file(url: str, file_path: str, headers: dict[str, Any], percentage: bool):
    """
    Download a file from a url to a file path

    Args:
        url (str): URL to download from
        file_path (str): Path to file to download to
        percentage (bool): Whether or not to print a percentage of the download progress
    """
    if headers:
        res = requests.get(url, stream=True, headers=headers)
    else:
        res = requests.get(url, stream=True)
    total_size = int(res.headers.get("content-length", 0))
    block_size = 1024
    wrote = 0
    with open(file_path, "wb") as f:
        for data in res.iter_content(block_size):
            wrote += len(data)
            f.write(data)
            if percentage:
                print("\rDownloaded: {}%".format(int(100 * wrote / total_size)), end="")
    print("\n")

def unzip_file(file_path: str, destination: str) -> None:
    """
    Unzip a file to a destination

    Args:
        file_path (str): Path to file to unzip
        destination (str): Path to unzip to
    """
    with zipfile.ZipFile(file_path, "r") as zip_ref:
        zip_ref.extractall(destination)

def parse_csv(
    file_path: Optional[str] = None,
    delimiter: str = ",",
    remove_padding: bool = True,
    parse_int: bool = True,
    r_comments: bool = True,
    r_empty: bool = True,
    file_data: Optional[bytes] = None,
) -> list[list[Any]]:
    """
    Parse a csv file and return its contents as a list of lists

    Args:
        file_path (Optional[str], optional): Path to csv file to parse. Defaults to None.
        delimiter (str, optional): Delimiter to use. Defaults to ",".
        remove_padding (bool, optional): Whether or not to remove padding. Defaults to True.
        parse_int (bool, optional): Whether or not to convert the data to intergers. Defaults to True.
        r_comments (bool, optional): Whether or not to remove comments. Defaults to True.
        r_empty (bool, optional): Whether or not to remove empty lines. Defaults to True.
        file_data (Optional[bytes], optional): Bytes to parse. Defaults to None.

    Raises:
        ValueError: If file_path is None and file_data is None

    Returns:
        list[list[Any]]: Parsed csv file
    """

    if file_path is not None:
        data = read_file_bytes(file_path)
    elif file_data is not None:
        data = file_data
    else:
        raise ValueError("No file path or data provided")
    if remove_padding:
        data = remove_pkcs7_padding(data)

    lines = data.decode("utf-8")
    if r_comments:
        lines = remove_comments(lines)
    lines = lines.split("\n")
    lines = [line.strip().split(delimiter) for line in lines]
    if r_empty:
        lines = remove_empty_items(lines)
    if parse_int:
        lines = parse_int_list(lines)
    return lines


def remove_comments(data: str) -> str:
    """
    Remove comments from a string

    Args:
        data (str): String to remove comments from

    Returns:
        str: String without comments
    """

    comments = ["#", "//"]
    data_l = data.split("\n")
    for comment in comments:
        data_l = [line.split(comment)[0] for line in data_l]
    data = "\n".join(data_l)
    return data


def remove_empty_items(list_of_lists: list[list[Any]]) -> list[list[Any]]:
    """
    Remove empty items from a list of lists`

    Args:
        list_of_lists (list[list[Any]]): List of lists to remove empty items from

    Returns:
        list[list[Any]]: List of lists without empty items
    """

    for i in range(len(list_of_lists)):
        list_of_lists[i] = list(filter(None, list_of_lists[i]))
    list_of_lists = remove_empty_lists(list_of_lists)
    return list_of_lists


def remove_empty_lists(list_of_lists: list[list[Any]]) -> list[list[Any]]:
    """
    Remove empty lists from a list of lists

    Args:
        list_of_lists (list[list[Any]]): List of lists to remove empty lists from

    Returns:
        list[list[Any]]: List of lists without empty lists
    """

    new_lists: list[list[Any]] = []
    for i in range(len(list_of_lists)):
        if len(list_of_lists[i]) != 0:
            new_lists.append(list_of_lists[i])
    return new_lists


def parse_int_list(list_of_lists: list[list[Any]]) -> list[list[Any]]:
    """
    Parse a list of lists to integers

    Args:
        list_of_lists (list[list[Any]]): List of lists to parse to integers

    Returns:
        list[list[Any]]: Parsed list of lists
    """

    for i in range(len(list_of_lists)):
        for j in range(len(list_of_lists[i])):
            try:
                list_of_lists[i][j] = int(list_of_lists[i][j])
            except ValueError:
                pass
    return list_of_lists


def check_int(value: str) -> bool:
    """
    Check if a string is an integer

    Args:
        value (str): String to check

    Returns:
        bool: Whether or not the string is an integer
    """

    try:
        int(value)
        return True
    except ValueError:
        return False


def str_to_gv(game_version: str) -> int:
    """
    Turn a game version with semantic versioning to integer representation

    Args:
        game_version (str): Game version with semantic versioning

    Returns:
        str: Game version in integer representation

    Raises:
        ValueError: If the game version is not in the correct format
    """
    split_gv = game_version.split(".")
    if len(split_gv) == 2:
        split_gv.append("0")
    final = ""
    for split in split_gv:
        final += split.zfill(2)

    if not check_int(final):
        raise ValueError("Invalid game version")

    return int(final.lstrip("0"))


def gv_to_str(game_version: int) -> str:
    """
    Turn a game version in integer representation to semantic versioning

    Args:
        game_version (int): Game version in integer representation

    Returns:
        str: Game version with semantic versioning
    """    

    split_gv = str(game_version).zfill(6)
    split_gv = [str(int(split_gv[i : i + 2])) for i in range(0, len(split_gv), 2)]
    return ".".join(split_gv)


def run_in_parallel(fns: list[Process]) -> None:
    """
    Run a list of functions in parallel

    Args:
        fns (list[Process]): List of functions to run in parallel
    """
    proc: list[Process] = []
    for fn in fns:
        fn.start()
        proc.append(fn)
    for p in proc:
        p.join()


def colored_text(
    text: str,
    base: Color = Color.WHITE,
    new: Color = Color.DARK_YELLOW,
    split_char: str = "&",
    end: str = "\n",
) -> None:
    """
    Color a text string

    Args:
        text (str): Text to color
        base (str, optional): Base color. Defaults to Colors.WHITE.value.
        new (str, optional): New color. Defaults to Colors.DARK_YELLOW.value.
        split_char (str, optional): Character to split the text on. Defaults to "&".
        end (str, optional): End character. Defaults to "\n".
    """
    color_new = colored.fg(new.value)  # type: ignore
    color_base = colored.fg(base.value)  # type: ignore
    color_reset = colored.fg(Color.WHITE.value)  # type: ignore

    text_split = text.split(split_char)
    for i, text_section in enumerate(text_split):
        if i % 2:
            print(f"{color_new}{text_section}{color_base}", end="")
        else:
            print(f"{color_base}{text_section}{color_base}", end="")
    print(color_reset, end=end)


def colored_list(
    items: list[str],
    extra_data: Any = None,
    index: bool = True,
    offset: Optional[int] = None,
    base: Color = Color.WHITE,
    new: Color = Color.DARK_YELLOW,
):
    """
    Color a list of items

    Args:
        items (list[str]): List of items to color
        extra_data (Any, optional): Extra data to print after each item. Defaults to None.
        index (bool, optional): Whether or not to print the index of the item. Defaults to True.
        offset (Optional[int], optional): Offset of the extra data. Defaults to None.
        base (Color, optional): Base color. Defaults to Color.WHITE.value.
        new (Color, optional): New color. Defaults to Color.DARK_YELLOW.value.
    """

    final = ""
    for i, item in enumerate(items):
        if index:
            final += f"{i+1}. "
        final += f"&{item}&"
        if extra_data:
            if extra_data[i] is not None:
                if isinstance(offset, int):
                    final += f" &:& {extra_data[i]+offset}"
                else:
                    final += f" &:& {extra_data[i]}"
        final += "\n"
    final = final.rstrip("\n")
    colored_text(final, base=base, new=new)


def get_int(value: str) -> Optional[int]:
    """
    Get an integer from a string

    Args:
        value (str): String to get an integer from

    Returns:
        int: Integer from the string
    """

    try:
        return int(value)
    except ValueError:
        return None


def load_config() -> dict[str, Any]:
    """
    Load the config file

    Returns:
        dict[str, Any]: Config file
    """
    with open(get_file("config.yaml"), "r") as f:
        config = yaml.safe_load(f)
    return config


def get_config_value(key: str) -> Any:
    """
    Get a config value

    Args:
        key (str): Key to get the value of

    Returns:
        Any: Config value
    """
    config = load_config()
    return config[key]


def get_files_path() -> str:
    """
    Get the path to the files folder

    Returns:
        str: Path to the files folder
    """
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "files")


def get_file(file_name: str) -> str:
    """
    Get the path of a file in the files folder

    Args:
        file_name (str): Name of the file to get the path of

    Returns:
        str: Path to the file
    """
    return os.path.join(get_files_path(), file_name)


def get_files(dir_name: str) -> list[str]:
    """
    Get the paths to all files in a folder

    Args:
        dir_name (str): Name of the folder to get the paths of all files in

    Returns:
        list[str]: Paths to all files in the folder
    """
    return [
        os.path.join(dir_name, file)
        for file in os.listdir(dir_name)
        if os.path.isfile(os.path.join(dir_name, file))
    ]
