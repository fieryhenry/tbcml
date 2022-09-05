from . import feature_handler
import argparse

def main() -> None:
    """
    Main function.
    """
    args = parse_args()
    handle_args(args)
    feature_handler.menu()


def parse_args() -> argparse.Namespace:
    """
    Parse command line arguments.

    Returns:
        argparse.Namespace: Parsed arguments.
    """    
    parser = argparse.ArgumentParser(description="BCGM Mod Manager")
    parser.add_argument("-d", "--decrypt", action="store_true", help="Decrypt the game files", default=False)
    parser.add_argument("-f", "--files", help="List of files to decrypt", nargs="+", type=str, default=[])
    parser.add_argument("-v", "--version", type=str, help="Version of the game to decrypt", default="latest")
    parser.add_argument("-j", "--jp", action="store_true", help="Decrypt jp files", default=False)
    parser.add_argument("-o", "--output", type=str, help="Output directory", default="output")
    parser.add_argument("-e", "--exit", action="store_true", help="Exit after running", default=False)
    return parser.parse_args()

def handle_args(args: argparse.Namespace) -> None:
    """
    Handle command line arguments.

    Args:
        args (argparse.Namespace): Parsed arguments.
    """
    if args.decrypt:
        if args.files and args.version:
            feature_handler.decrypt_files(args.files, args.version, args.jp, args.output)
        else:
            print("You need to specify a list of files and a version to decrypt")
    if args.exit:
        exit()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        feature_handler.exit_manager()
