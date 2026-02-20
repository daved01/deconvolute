import argparse
import os
import sys

from deconvolute import __version__
from deconvolute.constants import DEFAULT_MCP_POLICY_FILENAME
from deconvolute.templates import DEFAULT_MCP_POLICY


def init_policy(args: argparse.Namespace) -> None:
    """
    Initializes the security policy configuration file.

    Creates a default 'deconvolute_policy.yaml' file in the current working directory.
    If the file already exists, the operation is aborted unless the --force flag is
    provided.

    Args:
        args (argparse.Namespace): The parsed command-line arguments. Expected
            attributes:
                output (str): Optional custom filename. Defaults to
                    'deconvolute_policy.yaml'.
                force (bool): If True, overwrites the existing file.

    Raises:
        SystemExit: If the file already exists and force is False, or if a write error
            occurs.
    """
    filename = args.output or DEFAULT_MCP_POLICY_FILENAME

    if os.path.exists(filename) and not args.force:
        print(f"❌ Error: '{filename}' already exists.")
        print("Use --force to overwrite it.")
        sys.exit(1)

    try:
        with open(filename, "w") as f:
            f.write(DEFAULT_MCP_POLICY)
        print(f"✅ Created '{filename}' in {os.getcwd()}")
        print("👉 Next step: Edit this file to define your allowed tools.")
    except Exception as e:
        print(f"❌ Error writing file: {e}")
        sys.exit(1)


def main() -> None:
    """
    The main entry point for the Deconvolute Security SDK CLI.

    Configures the argument parser, including version information and subcommands.
    Currently supports the 'init policy' command to generate a default security policy.
    Routes execution to the appropriate handler function based on the provided arguments
    """
    parser = argparse.ArgumentParser(
        description=f"Deconvolute Security SDK CLI v{__version__}"
    )

    # Add version argument
    parser.add_argument(
        "--version",
        "-v",
        action="version",
        version=f"Deconvolute Security SDK v{__version__}",
        help="Show program's version number and exit",
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Command Group: init
    init_parser = subparsers.add_parser("init", help="Initialize configuration files")
    init_subparsers = init_parser.add_subparsers(
        dest="init_type", required=True, help="What to initialize"
    )

    # Sub-command: init policy
    policy_parser = init_subparsers.add_parser(
        "policy", help="Create a new security policy file"
    )
    policy_parser.add_argument(
        "--force", "-f", action="store_true", help="Overwrite existing file"
    )
    policy_parser.add_argument(
        "--output",
        "-o",
        help="Custom output filename (default: deconvolute_policy.yaml)",
    )
    policy_parser.set_defaults(func=init_policy)

    args = parser.parse_args()

    # Execute the function associated with the command
    if hasattr(args, "func"):
        args.func(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
