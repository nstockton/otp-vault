# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.


# Future Modules:
from __future__ import annotations

# Built-in Modules:
import argparse
import ctypes
import os
import sys
from typing import Any, Callable, Optional
from typing_extensions import Literal
from typing_extensions import get_args as get_type_args

# Local Modules:
from . import __version__, otp
from .clipboard import set_clipboard
from .database import Database, Secret


DESCRIPTION: str = "OTP Vault"
VERSION: str = (
	f"%(prog)s V{__version__} "
	+ f"(Python {'.'.join(str(i) for i in sys.version_info[:3])} {sys.version_info.releaselevel})"
)
ERROR_TYPE = Callable[[str], None]
LITERAL_TOKEN_TYPES = Literal["hotp", "motp", "totp"]
TOKEN_TYPES: tuple[LITERAL_TOKEN_TYPES, ...] = get_type_args(LITERAL_TOKEN_TYPES)


def change_password(database: Database, error_handler: ERROR_TYPE, password: str) -> None:
	"""
	Changes the password of an existing database.

	Args:
		database: The database to perform the change password operation on.
		error_handler: A callback function to be called when an exception is raised.
		password: The replacement password for the database.
	"""
	try:
		database.save(password)
	except ValueError as e:
		error_handler(str(e))
	else:
		print("Password successfully changed.")


def add_secret(
	database: Database,
	error_handler: ERROR_TYPE,
	password: str,
	label: str,
	key: str,
	token_type: str,
	length: int,
	initial_input: str,
) -> None:
	"""
	Adds a secret to a database.

	Args:
		database: The database where the secret should be added.
		error_handler: A callback function to be called when an exception is raised.
		password: The password for the database.
		label: A label for the secret.
		key: The key for the secret.
		token_type: A valid OTP token type.
		length: The desired length of the generated code.
		initial_input: A moving factor value, such as MOTP pin, HOTP counter, or TOTP start time.
	"""
	try:
		database.add_secret(password, label, key, token_type, length, initial_input)
	except ValueError as e:
		error_handler(str(e))
	else:
		print(f"Secret {label} added to database.")


def search_secrets(
	database: Database,
	error_handler: ERROR_TYPE,
	password: str,
	text: str,
	*,
	copy: Optional[int] = None,
	delete: Optional[int] = None,
	update: Optional[tuple[int, str]] = None,
) -> None:
	"""
	Searches secrets in a database by label.

	Args:
		database: The database to search.
		error_handler: A callback function to be called when an exception is raised.
		password: The password for the database.
		text: The search text to match against secret labels.
		copy: Copy the corresponding search result to the clipboard.
		delete: Delete the corresponding search result from the database.
		update: Update the corresponding search result with a new label.
	"""
	exclusive_args: tuple[Any, ...] = (copy, delete, update)
	exclusive_args_not_specified: bool = all(i is None for i in exclusive_args)
	results: tuple[Secret, ...] = database.search_secrets(text)
	if not results:
		sys.exit("No results found.")  # Prints to STDERR and exits with status code 1.
	for i, result in enumerate(results):
		label, key, token_type, length, initial_input = result
		if exclusive_args_not_specified:
			# User is searching for matching labels.
			print(f"{i + 1}: {label}")
		elif copy is not None and not 1 <= copy <= len(results):
			# Item user wants to copy is out of range.
			error_handler(f"Item {copy} to copy not in range 1-{len(results)}")
			break
		elif copy is not None and i + 1 == copy:
			# User has selected a valid item to be copied to the clipboard.
			otp_function: Callable[..., str] = getattr(otp, token_type)
			token: str = otp_function(key, initial_input, length=length)
			if token_type == "hotp":
				# The HOTP counter needs to be incremented after every use.
				database.increment_initial_input(password, result, amount=1)
			status: bool = set_clipboard(token)
			if status:
				# Item was successfully copied to the clipboard.
				print(f"Item {copy} ({label}) copied to clipboard.")
			else:
				# An exception was raised, or clipboard module doesn't support the OS.
				print(token)
			break
		elif delete is not None and not 1 <= delete <= len(results):
			# Item user wants to delete is out of range.
			error_handler(f"Item {delete} to delete not in range 1-{len(results)}")
			break
		elif delete is not None and i + 1 == delete:
			# User has selected a valid item to be deleted.
			database.delete_secret(password, label)
			print(f"Item {delete} ({label}) deleted.")
			break
		elif update is not None and not 1 <= update[0] <= len(results):
			# Item user wants to update is out of range.
			error_handler(f"Item {update[0]} to update not in range 1-{len(results)}")
			break
		elif update is not None and i + 1 == update[0]:
			# User has selected a valid item to be updated.
			selected_item, new_label = update
			database.update_secret(password, label, new_label)
			print(f"Item {selected_item} ({label}) updated to {new_label}.")
			break


class ArgumentNamespace(argparse.Namespace):
	password: str
	change_password: Optional[str] = None
	add: Optional[tuple[str, str]] = None
	type: LITERAL_TOKEN_TYPES = "totp"
	length: int = 6
	initial_input: str = "0"
	search: Optional[str] = None
	copy: Optional[int] = None
	delete: Optional[int] = None
	update: Optional[tuple[int, str]] = None


def process_args(*args: str) -> tuple[ArgumentNamespace, ERROR_TYPE]:
	"""
	Parses command-line arguments into an ArgumentNamespace instance.

	Args:
		*args: Arguments to parse. If no arguments are given, arguments are taken from sys.argv.

	Returns:
		A tuple containing the resulting ArgumentNamespace instance, and a callback for error handling.
	"""
	parser = argparse.ArgumentParser(description=DESCRIPTION, add_help=False)
	parser._positionals.title = "Required Positional Arguments"
	parser._positionals.description = "All must be provided."
	parser.add_argument(
		"password", metavar="password", help="The password for creating or accessing the secrets database."
	)
	parser._optionals.title = "Required Named Arguments"
	parser._optionals.description = "Mutually exclusive, 1 must be provided."
	exclusive_commands = parser.add_mutually_exclusive_group(required=True)
	exclusive_commands.add_argument(
		"--change-password", metavar="new_password", help="Changes an existing password."
	)
	exclusive_commands.add_argument(
		"-a", "--add", nargs=2, metavar=("label", "key"), help="Adds a secret to the secrets database."
	)
	exclusive_commands.add_argument("-s", "--search", metavar="text", help="Searches for a secret by label.")
	exclusive_commands.add_argument("-h", "--help", action="help", help="Shows program help.")
	exclusive_commands.add_argument(
		"-v", "--version", action="version", version=VERSION, help="Shows program version."
	)
	add_options = parser.add_argument_group("Add Options", "Relevant when the add argument is provided.")
	add_options.add_argument(
		"-t",
		"--type",
		metavar="type",
		choices=TOKEN_TYPES,
		help="Specifies the algorithm to use when adding a secret.",
	)
	add_options.add_argument(
		"-l", "--length", metavar="length", type=int, help="Specifies the desired token length."
	)
	add_options.add_argument(
		"-i",
		"--initial-input",
		metavar="value",
		help="Specifies the pin / counter / start-time used as the moving factor.",
	)
	search_options = parser.add_argument_group(
		"Search Options", "Relevant when the search argument is provided."
	)
	search_options.add_argument(
		"-c",
		"--copy",
		metavar="result_item",
		type=int,
		help="Copies the token of a search result to the clipboard.",
	)
	search_options.add_argument(
		"-d",
		"--delete",
		metavar="result_item",
		type=int,
		help="Deletes a search result from the secrets database.",
	)
	search_options.add_argument(
		"-u",
		"--update",
		nargs=2,
		metavar=("result_item", "new_label"),
		help="Updates a search result with a new label.",
	)
	namespace = ArgumentNamespace()
	parsed: ArgumentNamespace = parser.parse_args(args=args or None, namespace=namespace)
	if parsed.add is not None:
		# Convert list to tuple.
		label, key = parsed.add
		parsed.add = (label, key)
	if parsed.update is not None:
		# Convert list to tuple and first item to int.
		result_item, new_label = parsed.update
		try:
			result_item = int(result_item)
		except ValueError:
			parser.error(f"argument -u/--update: invalid int value in result_item: {result_item!r}")
		parsed.update = (result_item, new_label)
	return parsed, parser.error


def main() -> None:  # pragma: no cover
	parsed_args, error = process_args()
	database = Database(parsed_args.password)
	if parsed_args.change_password is not None:
		change_password(database, error, parsed_args.change_password)
	elif parsed_args.add is not None:
		label, key = (i.strip() for i in parsed_args.add)
		add_secret(
			database,
			error,
			parsed_args.password,
			label,
			key,
			parsed_args.type,
			parsed_args.length,
			parsed_args.initial_input,
		)
	elif parsed_args.search is not None:
		search_secrets(
			database,
			error,
			parsed_args.password,
			parsed_args.search,
			copy=parsed_args.copy,
			delete=parsed_args.delete,
			update=parsed_args.update,
		)
	else:
		error("Please specify an option")


def run() -> None:  # pragma: no cover
	if sys.platform == "win32":
		# Set the title of the console window.
		ctypes.windll.kernel32.SetConsoleTitleW(DESCRIPTION)
	main()
	if sys.platform == "win32":
		# Reset the title.
		ctypes.windll.kernel32.SetConsoleTitleW(os.getenv("COMSPEC", "cmd"))
