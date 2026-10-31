# src/encryptor_tool/cli.py

import argparse
import getpass
import os
import sys

from .crypto import decrypt_file, encrypt_file


def main():
    parser = argparse.ArgumentParser(
        prog="encryptor-tool",
        description="Secure chunked file encryption using AES-256-GCM.",
    )

    # Create subcommands (encrypt / decrypt)
    subparsers = parser.add_subparsers(dest="command", required=True)

    # --- Encrypt Command ---
    enc_parser = subparsers.add_parser("encrypt", help="Encrypt a file")
    enc_parser.add_argument("input", help="Path to the file to encrypt")
    enc_parser.add_argument("output", nargs="?", help="Output path (default: <input>.enc)")
    enc_parser.add_argument("-f", "--force", action="store_true", help="Overwrite output if it exists")
    enc_parser.add_argument("-s", "--shred", action="store_true", help="Securely delete original file after encryption")

    # --- Decrypt Command ---
    dec_parser = subparsers.add_parser("decrypt", help="Decrypt a file")
    dec_parser.add_argument("input", help="Path to the encrypted file")
    dec_parser.add_argument("output", nargs="?", help="Output path (default: strips .enc)")
    dec_parser.add_argument("-f", "--force", action="store_true", help="Overwrite output if it exists")
    dec_parser.add_argument("-s", "--shred", action="store_true", help="Securely delete encrypted file after decryption")

    args = parser.parse_args()

    # Handle default output paths
    if args.command == "encrypt":
        if not os.path.exists(args.input):
            print(f"Error: Input file '{args.input}' not found.", file=sys.stderr)
            sys.exit(1)
        output = args.output or (args.input + ".enc")
        action_func = encrypt_file
        is_encrypt = True
    elif args.command == "decrypt":
        if not os.path.exists(args.input):
            print(f"Error: Input file '{args.input}' not found.", file=sys.stderr)
            sys.exit(1)
        output = args.output or (
            args.input[:-4] if args.input.endswith(".enc") else args.input + ".dec"
        )
        action_func = decrypt_file
        is_encrypt = False

    # Check if output file exists
    if os.path.exists(output) and not args.force:
        print(
            f"Error: Output file '{output}' already exists. Use -f to overwrite.",
            file=sys.stderr,
        )
        sys.exit(1)

    # Get password securely (no echo)
    try:
        if is_encrypt:
            password = getpass.getpass("Enter password: ")
            confirm = getpass.getpass("Confirm password: ")
            if password != confirm:
                print("\nError: Passwords do not match.", file=sys.stderr)
                sys.exit(1)
        else:
            password = getpass.getpass("Enter password: ")
    except KeyboardInterrupt:
        print("\nAborted.", file=sys.stderr)
        sys.exit(1)

    # Run the action
    try:
        print(f"Processing '{args.input}'...")
        action_func(args.input, output, password, show_progress=True)
        print(f"Success! Output written to '{output}'")

        # this shredding logic
        if args.shred:
            print(f"Shredding original file '{args.input}'...")
            from .crypto import shred_file  # Import the new function
            shred_file(args.input)
            print("Original file securely deleted.")


    except ValueError as e:
        print(f"\nError: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:  # noqa: BLE001
        print(f"\nUnexpected error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
