# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.


# Future Modules:
from __future__ import annotations

# Built-in Modules:
import sys
from collections.abc import Callable
from typing import Any, Literal, Optional

# Third-party Modules:
from tap import Tap

# Local Modules:
from . import __version__, otp
from .clipboard import set_clipboard
from .database import Database, Secret


DESCRIPTION: str = "An authenticator app."
TOKEN_FUNCTIONS: tuple[str, ...] = ("hotp", "motp", "totp")


def get_token(token_type: str, *args: Any, **kwargs: Any) -> str:
	if token_type not in TOKEN_FUNCTIONS:
		raise ValueError(f"{token_type} not in {TOKEN_FUNCTIONS}.")
	otp_function: Callable[..., str] = getattr(otp, token_type)
	return otp_function(*args, **kwargs)


class ArgumentParser(Tap):  # pragma: no cover
	password: str
	"""The password for decrypting the database."""
	change_password: Optional[str] = None
	"""Change an existing password."""
	add: Optional[str] = None
	"""Add a secret key."""
	type: Literal["hotp", "motp", "totp"] = "totp"
	"""The type of OTP used (used with --add)."""
	length: int = 6
	"""The length of the output token (used with --add)."""
	initial_input: str = "0"
	"""The pin / counter / start time used as the moving factor (used with --add)."""
	search: Optional[str] = None
	"""Search for a secret key."""
	copy: Optional[int] = None
	"""Copy a secret key to the clipboard (requires --search)."""
	delete: Optional[int] = None
	"""Delete a secret key (requires --search)."""
	update: Optional[tuple[int, str]] = None
	"""Update a secret key with a new label (requires --search)."""

	def process_args(self) -> None:
		# Work around for defining a mutually exclusive group in TAP.configure throws
		# an exception if the argument is also defined as a class variable.
		exclusive_args: list[str] = [
			"change_password",
			"add",
			"search",
		]
		for arg in exclusive_args:
			if arg not in self.argument_buffer:
				raise ValueError(f"{arg} not in argument buffer.")
		exclusive_args.sort(key=list(self.argument_buffer).index)
		specified_exclusive_args: list[str] = [i for i in exclusive_args if getattr(self, i) is not None]
		specified_exclusive_search_args: list[str] = [
			i for i in ("copy", "delete", "update") if getattr(self, i) is not None
		]
		if len(specified_exclusive_search_args) > 1:
			self.error(f"{specified_exclusive_search_args} are mutually exclusive")
		elif specified_exclusive_search_args and "".join(specified_exclusive_args) != "search":
			self.error(
				f"--{specified_exclusive_search_args[0]} {'can only' if specified_exclusive_args else 'must'} "
				+ "be used with --search"
			)
		elif len(specified_exclusive_args) > 1:
			self.error(f"{specified_exclusive_args} are mutually exclusive")

	def configure(self) -> None:
		version: str = (
			f"%(prog)s V{__version__} "
			+ f"(Python {'.'.join(str(i) for i in sys.version_info[:3])} {sys.version_info.releaselevel})"
		)
		self.add_argument(
			"-v",
			"--version",
			help="Print the program version as well as the Python version.",
			action="version",
			version=version,
		)
		self.add_argument("password", metavar="password")
		self.add_argument("--change-password", metavar="new_password")
		self.add_argument("-a", "--add", nargs=2, metavar=("label", "key"))
		self.add_argument("-t", "--type", metavar="type")
		self.add_argument("-l", "--length", metavar="length")
		self.add_argument("-i", "--initial-input", metavar="value")
		self.add_argument("-s", "--search", metavar="text")
		self.add_argument("-c", "--copy", metavar="item")
		self.add_argument("-d", "--delete", metavar="item")
		self.add_argument("-u", "--update", nargs=2, metavar=("item", "new_label"))


def change_password(database: Database, error_handler: Callable[[str], None], password: str) -> None:
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
	error_handler: Callable[[str], None],
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
	error_handler: Callable[[str], None],
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
			token: str = get_token(token_type, key, initial_input, length=length)
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


def main(parsed_args: ArgumentParser) -> None:  # pragma: no cover
	database = Database(parsed_args.password)
	if parsed_args.change_password is not None:
		change_password(database, parsed_args.error, parsed_args.change_password)
	elif parsed_args.type not in TOKEN_FUNCTIONS:
		parsed_args.error(f"{parsed_args.type} not in {list(TOKEN_FUNCTIONS)}")
	elif parsed_args.add is not None:
		label, key = (i.strip() for i in parsed_args.add)
		add_secret(
			database,
			parsed_args.error,
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
			parsed_args.error,
			parsed_args.password,
			parsed_args.search,
			copy=parsed_args.copy,
			delete=parsed_args.delete,
			update=parsed_args.update,
		)
	else:
		parsed_args.error("Please specify an option")


def run() -> None:  # pragma: no cover
	parser: ArgumentParser = ArgumentParser(underscores_to_dashes=True, description=DESCRIPTION)
	args: ArgumentParser = parser.parse_args()
	main(args)
