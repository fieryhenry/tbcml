from . import feature_handler, updater, helper
import argparse


def main() -> None:
    """
    Main function.
    """
    args = parse_args()
    handle_args(args)
    #check_update()
    feature_handler.menu()


def check_update() -> None:
    """Check if there is an update available and if so, ask the user if they want to update"""
    version_info = updater.get_version_info()
    stable_ver, pre_release_ver = version_info

    local_version = updater.get_local_version()

    helper.colored_text(
        f"Local version: &{local_version} | &Latest stable version: &{stable_ver}",
        base=helper.Color.CYAN,
        new=helper.Color.WHITE,
        end="",
    )
    if pre_release_ver > stable_ver:
        helper.colored_text(
            f"& | &Latest pre-release version: &{pre_release_ver}&",
            base=helper.Color.CYAN,
            new=helper.Color.WHITE,
            end="",
        )
    print()
    update_data = updater.check_update(version_info)
    if update_data[0]:
        helper.colored_text(
            "\nAn update is available, would you like to update? (&y&/&n&):",
            base=helper.Color.GREEN,
            new=helper.Color.WHITE,
            end="",
        )
        if input().lower() == "y":
            updater.update(update_data[1])
            helper.colored_text("Update successful", base=helper.Color.GREEN)
            feature_handler.exit_manager()


def parse_args() -> argparse.Namespace:
    """
    Parse command line arguments.

    Returns:
        argparse.Namespace: Parsed arguments.
    """
    parser = argparse.ArgumentParser(description="BCGM Mod Manager")
    parser.add_argument(
        "-d",
        "--decrypt",
        action="store_true",
        help="Decrypt the game files",
        default=False,
    )
    parser.add_argument(
        "-f",
        "--files",
        help="List of files to decrypt",
        nargs="+",
        type=str,
        default=[],
    )
    parser.add_argument(
        "-v",
        "--version",
        type=str,
        help="Version of the game to decrypt",
        default="latest",
    )
    parser.add_argument(
        "-j", "--jp", action="store_true", help="Decrypt jp files", default=False
    )
    parser.add_argument(
        "-o", "--output", type=str, help="Output directory", default="output"
    )
    parser.add_argument(
        "-e", "--exit", action="store_true", help="Exit after running", default=False
    )
    return parser.parse_args()


def handle_args(args: argparse.Namespace) -> None:
    """
    Handle command line arguments.

    Args:
        args (argparse.Namespace): Parsed arguments.
    """
    if args.decrypt:
        if args.files and args.version:
            feature_handler.decrypt_files(
                args.files, args.version, args.jp, args.output
            )
        else:
            print("You need to specify a list of files and a version to decrypt")
    if args.exit:
        exit()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        feature_handler.exit_manager()
