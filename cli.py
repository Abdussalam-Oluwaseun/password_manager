#!/usr/bin/env python3
"""
cli.py
Command-line interface for the password generator and manager.

Run `python cli.py --help` to see all commands.
"""

import argparse
import getpass
import sys

import generator
import strength
import vault


def cmd_init(args):
    if vault.vault_exists():
        print("A vault already exists here. Delete vault.db if you want to start over.")
        return
    print("Setting up a new vault.")
    try:
        master_password = vault.prompt_master_password(confirm=True)
    except ValueError as e:
        print(f"Error: {e}")
        return
    if len(master_password) < 8:
        print("Warning: a short master password weakens the security of everything stored in the vault.")
    vault.init_vault(master_password)
    print("Vault created. Keep your master password safe — it cannot be recovered if lost.")


def cmd_generate(args):
    try:
        pwd = generator.generate_password(
            length=args.length,
            use_upper=not args.no_upper,
            use_lower=not args.no_lower,
            use_digits=not args.no_digits,
            use_symbols=not args.no_symbols,
            exclude_ambiguous=args.exclude_ambiguous,
        )
    except ValueError as e:
        print(f"Error: {e}")
        return

    result = strength.check_strength(pwd)
    print(f"\nGenerated password: {pwd}")
    print(
        f"Strength: {result['label']} ({result['score']}/{result['max_score']}) "
        f"— ~{result['entropy_bits']} bits of entropy"
    )
    for note in result["feedback"]:
        print(f"  - {note}")

    if args.save:
        if not vault.vault_exists():
            print("\nNo vault found. Run 'init' first to save passwords.")
            return
        site = args.save
        username = args.username or input("Username: ")
        master_password = vault.prompt_master_password()
        try:
            fernet = vault.unlock_vault(master_password)
            vault.add_entry(fernet, site, username, pwd)
            print(f"Saved to vault under '{site}'.")
        except ValueError as e:
            print(f"Error: {e}")


def cmd_passphrase(args):
    phrase = generator.generate_passphrase(num_words=args.words, separator=args.separator)
    result = strength.check_strength(phrase)
    print(f"\nGenerated passphrase: {phrase}")
    print(
        f"Strength: {result['label']} ({result['score']}/{result['max_score']}) "
        f"— ~{result['entropy_bits']} bits of entropy"
    )


def cmd_check(args):
    pwd = args.password or getpass.getpass("Password to check: ")
    result = strength.check_strength(pwd)
    print(
        f"\nStrength: {result['label']} ({result['score']}/{result['max_score']}) "
        f"— ~{result['entropy_bits']} bits of entropy"
    )
    for note in result["feedback"]:
        print(f"  - {note}")


def cmd_add(args):
    if not vault.vault_exists():
        print("No vault found. Run 'init' first.")
        return
    site = args.site
    username = args.username or input("Username: ")

    if args.generate:
        password = generator.generate_password(length=args.length)
        print(f"Generated password: {password}")
    else:
        password = getpass.getpass("Password to store: ")

    master_password = vault.prompt_master_password()
    try:
        fernet = vault.unlock_vault(master_password)
        vault.add_entry(fernet, site, username, password, notes=args.notes or "")
        print(f"Saved entry for '{site}'.")
    except ValueError as e:
        print(f"Error: {e}")


def cmd_get(args):
    if not vault.vault_exists():
        print("No vault found. Run 'init' first.")
        return
    master_password = vault.prompt_master_password()
    try:
        fernet = vault.unlock_vault(master_password)
    except ValueError as e:
        print(f"Error: {e}")
        return

    entries = vault.get_entry(fernet, args.site)
    if not entries:
        print(f"No entries found for '{args.site}'.")
        return
    for entry in entries:
        print(f"\nSite: {entry['site']}")
        print(f"Username: {entry['username']}")
        print(f"Password: {entry['password']}")
        if entry["notes"]:
            print(f"Notes: {entry['notes']}")


def cmd_list(args):
    if not vault.vault_exists():
        print("No vault found. Run 'init' first.")
        return
    entries = vault.list_entries()
    if not entries:
        print("Vault is empty.")
        return
    print(f"\n{'Site':<25}{'Username':<25}Notes")
    print("-" * 70)
    for entry in entries:
        print(f"{entry['site']:<25}{(entry['username'] or ''):<25}{entry['notes'] or ''}")


def cmd_delete(args):
    if not vault.vault_exists():
        print("No vault found.")
        return
    confirm = input(f"Delete all entries for '{args.site}'? (y/N): ")
    if confirm.lower() != "y":
        print("Cancelled.")
        return
    deleted = vault.delete_entry(args.site, args.username)
    print(f"Deleted {deleted} entry(ies).")


def build_parser():
    parser = argparse.ArgumentParser(
        description="A simple password generator and encrypted password manager."
    )
    sub = parser.add_subparsers(dest="command")

    p_init = sub.add_parser("init", help="Create a new vault protected by a master password.")
    p_init.set_defaults(func=cmd_init)

    p_gen = sub.add_parser("generate", help="Generate a random password.")
    p_gen.add_argument("--length", type=int, default=16)
    p_gen.add_argument("--no-upper", action="store_true")
    p_gen.add_argument("--no-lower", action="store_true")
    p_gen.add_argument("--no-digits", action="store_true")
    p_gen.add_argument("--no-symbols", action="store_true")
    p_gen.add_argument(
        "--exclude-ambiguous", action="store_true",
        help="Exclude visually similar characters (I, l, 1, O, 0).",
    )
    p_gen.add_argument("--save", metavar="SITE", help="Save the generated password to the vault under SITE.")
    p_gen.add_argument("--username", help="Username to store alongside the saved password.")
    p_gen.set_defaults(func=cmd_generate)

    p_phrase = sub.add_parser("passphrase", help="Generate a memorable Diceware-style passphrase.")
    p_phrase.add_argument("--words", type=int, default=4)
    p_phrase.add_argument("--separator", default="-")
    p_phrase.set_defaults(func=cmd_passphrase)

    p_check = sub.add_parser("check", help="Check the strength of a password.")
    p_check.add_argument("password", nargs="?", help="Password to check (omit to be prompted securely).")
    p_check.set_defaults(func=cmd_check)

    p_add = sub.add_parser("add", help="Add a new entry to the vault.")
    p_add.add_argument("site")
    p_add.add_argument("--username")
    p_add.add_argument("--generate", action="store_true", help="Auto-generate the password.")
    p_add.add_argument("--length", type=int, default=16)
    p_add.add_argument("--notes")
    p_add.set_defaults(func=cmd_add)

    p_get = sub.add_parser("get", help="Retrieve an entry from the vault.")
    p_get.add_argument("site")
    p_get.set_defaults(func=cmd_get)

    p_list = sub.add_parser("list", help="List all sites stored in the vault (no passwords shown).")
    p_list.set_defaults(func=cmd_list)

    p_delete = sub.add_parser("delete", help="Delete an entry from the vault.")
    p_delete.add_argument("site")
    p_delete.add_argument("--username")
    p_delete.set_defaults(func=cmd_delete)

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(1)
    args.func(args)


if __name__ == "__main__":
    main()
