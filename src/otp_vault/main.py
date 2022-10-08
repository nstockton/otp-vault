# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.


# Future Modules:
from __future__ import annotations

# Built-in Modules:
import sys
from collections.abc import Callable
from typing import Optional

# Third-party Modules:
from tap import Tap

# Local Modules:
from . import __version__
from .clipboard import set_clipboard
from .database import Database
from .otp import totp


DESCRIPTION: str = "An authenticator app."


class ArgumentParser(Tap):  # pragma: no cover
	password: str
	"""The password for decrypting the database."""
	change_password: Optional[str] = None
	"""Change an existing password."""
	add: Optional[str] = None
	"""Add a secret key."""
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
			f"%(prog)s v{__version__} "
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
	database: Database, error_handler: Callable[[str], None], password: str, label: str, key: str
) -> None:
	"""
	Adds a secret to a database.

	Args:
		database: The database where the secret should be added.
		error_handler: A callback function to be called when an exception is raised.
		password: The password for the database.
		label: A label for the secret.
		key: The key for the secret.
	"""
	try:
		database.add_secret(password, label, key)
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
	results: tuple[tuple[str, str], ...] = database.search_secrets(text)
	if not results:
		sys.exit("No results found.")  # Prints to STDERR and exits with status code 1.
	for i, result in enumerate(results):
		label, key = result
		if copy is not None:
			if not 1 <= copy <= len(results):
				error_handler(f"Item {copy} to copy not in range 1-{len(results)}")
				break
			elif i + 1 == copy:
				set_clipboard(totp(key))
				print(f"Item {copy} ({label}) copied to clipboard.")
				break
		elif delete is not None:
			if not 1 <= delete <= len(results):
				error_handler(f"Item {delete} to delete not in range 1-{len(results)}")
				break
			elif i + 1 == delete:
				database.delete_secret(password, label)
				print(f"Item {delete} ({label}) deleted.")
				break
		elif update is not None:
			# update is a list containing the item number and the new label.
			if not 1 <= update[0] <= len(results):
				error_handler(f"Item {update[0]} to update not in range 1-{len(results)}")
				break
			elif i + 1 == update[0]:
				database.update_secret(password, label, update[1])
				print(f"Item {update[0]} ({label}) updated to {update[1]}.")
				break
		else:
			# Just searching.
			print(f"{i + 1}: {label}, {totp(key)}")


def main(parsed_args: ArgumentParser) -> None:  # pragma: no cover
	database = Database(parsed_args.password)
	if parsed_args.change_password is not None:
		change_password(database, parsed_args.error, parsed_args.change_password)
	elif parsed_args.add is not None:
		label, key = (i.strip() for i in parsed_args.add)
		add_secret(database, parsed_args.error, parsed_args.password, label, key)
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
