"""Update the editor"""

import subprocess
from typing import Any

import requests

from . import config_handler, helper


def update(latest_version: str, command: str = "py") -> None:
    """
    Updates the mod manager

    Args:
        latest_version (str): Latest version
        command (str, optional): Command to run. Defaults to "py".
    """
    helper.colored_text("Updating...", base=helper.Color.GREEN)
    try:
        full_cmd = (
            f"{command} -m pip install --upgrade bcgm_mod_manager=={latest_version}"
        )
        subprocess.run(
            full_cmd,
            shell=True,
            capture_output=True,
            check=True,
        )
        helper.colored_text("Update successful", base=helper.Color.GREEN)
    except subprocess.CalledProcessError as err:
        helper.colored_text("Update failed", base=helper.Color.RED)
        if command == "py":
            helper.colored_text("Trying with python3 instead", base=helper.Color.RED)
            update(latest_version, "python3")
        else:
            helper.colored_text(
                f"Error: {err.stderr.decode('utf-8')}\nYou may need to manually update with py -m pip install -U bcgm_mod_manager",
                base=helper.Color.RED,
            )


def get_local_version() -> str:
    """
    Gets the local version of the program

    Returns:
        str: Local version
    """
    return helper.read_file_str(helper.get_file("version.txt"))


def get_version_info() -> tuple[str, str]:
    """
    Gets the version info from pypi

    Raises:
        Exception: If the request fails

    Returns:
        tuple[str, str]: Pypi version, latest prerelease version
    """
    package_name = "bcgm_mod_manager"
    try:
        response = requests.get(f"https://pypi.org/pypi/{package_name}/json")
        response.raise_for_status()
        data = response.json()
    except requests.exceptions.RequestException as err:
        raise Exception("Error getting pypi version") from err

    info = (
        get_pypi_version(data),
        get_latest_prerelease_version(data),
    )
    return info


def get_pypi_version(data: dict[str, Any]) -> str:
    """
    Gets the pypi version of the program

    Args:
        data (dict[str, Any]): Pypi data

    Returns:
        str: Pypi version
    """    
    return data["info"]["version"]


def get_latest_prerelease_version(data: dict[str, Any]) -> str:
    """
    Gets the latest prerelease version of the program

    Args:
        data (dict[str, Any]): Pypi data

    Returns:
        str: Latest prerelease version
    """    
    releases = list(data["releases"])
    releases.reverse()
    for release in releases:
        if "b" in release:
            return release
    return ""


def pypi_is_newer(local_version: str, pypi_version: str, remove_b: bool = True) -> bool:
    """
    Checks if the pypi version is newer than the local version

    Args:
        local_version (str): Local version
        pypi_version (str): Pypi version
        remove_b (bool, optional): Remove b from version. Defaults to True.

    Returns:
        bool: If the pypi version is newer
    """    
    if remove_b:
        if "b" in pypi_version:
            pypi_version = pypi_version.split("b")[0]
        if "b" in local_version:
            local_version = local_version.split("b")[0]

    return pypi_version > local_version


def check_update(version_info: tuple[str, str]) -> tuple[bool, str]:
    """
    Checks if there is an update

    Args:
        version_info (tuple[str, str]): Pypi version, latest prerelease version

    Returns:
        tuple[bool, str]: If there is an update, latest version
    """    
    local_version = get_local_version()
    pypi_version, latest_prerelease_version = version_info

    check_pre = "b" in local_version or config_handler.get_config_setting(
        "update_to_betas"
    )
    if check_pre and pypi_is_newer(
        local_version, latest_prerelease_version, remove_b=False
    ):
        helper.colored_text("Prerelease update available\n", base=helper.Color.GREEN)
        return True, latest_prerelease_version

    if pypi_is_newer(local_version, pypi_version):
        helper.colored_text("Stable update available\n", base=helper.Color.GREEN)
        return True, pypi_version

    helper.colored_text("No update available\n", base=helper.Color.GREEN)
    return False, local_version
