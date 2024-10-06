"""Persistent storage to disk."""


# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# Future Modules:
from __future__ import annotations

# Built-in Modules:
import hashlib
import json
import os.path
import re
import threading
from typing import Any, Iterator, MutableMapping, NamedTuple

# Third-party Modules:
import fastjsonschema

# Local Modules:
from .encryption import decrypt, encrypt
from .utils import get_data_path


DATA_DIRECTORY: str = get_data_path()
SCHEMA_VERSION: int = 1
WHITE_SPACE_REGEX: re.Pattern[str] = re.compile(r"(?:\s+)", flags=re.UNICODE)
# Use negative look-ahead to exclude the space character from the \s character class.
# Another way to accomplish this would be to use negation (I.E. [^\S ]+).
WHITE_SPACE_EXCEPT_SPACE_REGEX: re.Pattern[str] = re.compile(r"(?:(?![ ])\s+)", flags=re.UNICODE)


class Secret(NamedTuple):
	"""A secret consisting of a label and a key."""

	label: str
	key: str
	type: str
	length: int
	input: str


class DatabaseError(Exception):
	"""Implements the base class for database exceptions."""


class Database(MutableMapping[str, Any]):
	"""Implements loading and saving of the database."""

	_database_lock: threading.RLock = threading.RLock()

	def __init__(self, password: str, name: str = "database") -> None:
		"""
		Defines the constructor for the object.

		Args:
			password: The password for decrypting the database.
			name: The name of the database.
		"""
		super().__init__()
		self._name: str = name
		self._database: dict[str, Any] = {}
		self.load(password)

	@property
	def name(self) -> str:
		"""The name of the database."""
		return self._name

	@property
	def file_path(self) -> str:
		"""The database file path."""
		return os.path.join(DATA_DIRECTORY, f"{self.name}.otp")

	@property
	def schema_path(self) -> str:
		"""The database json schema path."""
		return os.path.join(DATA_DIRECTORY, f"{self.name}.schema")

	@property
	def secrets(self) -> list[Secret]:
		"""The list of secrets."""
		secrets: list[Secret] = self._database.setdefault("secrets", [])
		return secrets

	def _get_checksum(self, data: bytes) -> str:
		return hashlib.sha256(data).hexdigest().lower()

	def _check_secret_label_whitespace(self, label: str) -> None:
		"""
		Checks a secret label for invalid use of white-space characters.

		Args:
			label: The label for the secret.

		Raises:
			ValueError: The label contains invalid white-space characters.
		"""
		if not label.strip():
			raise ValueError("label cannot contain only white-space characters.")
		if label.strip() != label:
			raise ValueError("label cannot start or end with white-space characters.")
		if WHITE_SPACE_EXCEPT_SPACE_REGEX.search(label) is not None:
			raise ValueError("label cannot contain white-space characters except for space.")

	def _validate_json(self) -> None:
		"""Validates json data against a schema."""
		with open(self.schema_path, "r", encoding="utf-8") as f:
			schema: dict[str, Any] = json.load(f)
		fastjsonschema.validate(schema, self._database)

	def load(self, password: str) -> None:
		"""
		Loads the database from disc.

		Args:
			password: The password for decrypting the database.
		"""
		self._database.clear()
		if not os.path.exists(self.file_path):
			return
		if os.path.isdir(self.file_path):
			raise DatabaseError(f"'{self.file_path}' is a directory, not a file.")
		with self._database_lock:
			with open(self.file_path, "rb") as f:
				checksum: str = str(f.readline(), "utf-8").strip()
				pw_hash: str = str(f.readline(), "utf-8").strip()
				enc_data: bytes = f.read().strip()
			if self._get_checksum(bytes(f"{pw_hash}\n", "utf-8") + enc_data) != checksum.lower():
				raise DatabaseError(f"Corrupted database file: {self.file_path}.")
			dec_data, needs_rehash = decrypt(password, pw_hash, enc_data)
			self._database.update(json.loads(dec_data))
			self._validate_json()
			schema_version: str = self._database.pop("schema_version")  # NOQA: F841
			# Sort and convert secret items from the lists that json saves them as.
			secrets = sorted(self.secrets, key=lambda secret: secret[0].lower())
			self.secrets.clear()
			self.secrets.extend(Secret(*s) for s in secrets)
		if needs_rehash:
			# Default values for the password hasher have been updated since the database was last saved.
			# Encrypt the database with the new values and save it to disk.
			self.save(password)

	def save(self, password: str) -> None:
		"""
		Saves the database to disc.

		Args:
			password: The password for encrypting the database.
		"""
		if not password.strip():
			raise ValueError("Password cannot contain only white-space characters.")
		if password.strip() != password:
			raise ValueError("Password cannot start or end with white-space characters.")
		if WHITE_SPACE_EXCEPT_SPACE_REGEX.search(password) is not None:
			raise ValueError("Password cannot contain white-space characters except for space.")
		with self._database_lock:
			self._database["schema_version"] = SCHEMA_VERSION
			dec_data: bytes = bytes(
				json.dumps(self._database, sort_keys=True, separators=(",", ":")), "utf-8"
			)
			pw_hash, enc_data = encrypt(password, dec_data)
			checksum: str = self._get_checksum(bytes(f"{pw_hash}\n", "utf-8") + enc_data)
			with open(self.file_path, "wb") as f:
				f.write(bytes(f"{checksum}\n", "utf-8"))
				f.write(bytes(f"{pw_hash}\n", "utf-8"))
				f.write(enc_data)

	def add_secret(
		self,
		password: str,
		label: str,
		key: str,
		token_type: str,
		length: int,
		initial_input: str,
	) -> None:
		"""
		Adds a secret to the database.

		Args:
			password: The password for encrypting the database.
			label: The label for the secret.
			key: The OTP key for the secret.
			token_type: A valid OTP token type.
			length: The desired length of the generated code.
			initial_input: A moving factor value, such as MOTP pin, HOTP counter, or TOTP start time.

		Raises:
			ValueError: A key with the same label already exists in the database.
		"""
		self._check_secret_label_whitespace(label)
		key = WHITE_SPACE_REGEX.sub("", key)
		token_type = WHITE_SPACE_REGEX.sub("", token_type)
		initial_input = WHITE_SPACE_REGEX.sub("", initial_input)
		input_requires_digits_types: tuple[str, ...] = ("hotp", "motp", "totp")
		if token_type in input_requires_digits_types and not initial_input.isdigit():
			raise ValueError(f"Initial input must be digits if token type is {token_type}.")
		if label in (secret.label for secret in self.secrets):
			raise ValueError(f"Secret with label {label} already exists in the database.")
		self.secrets.append(Secret(label, key, token_type, length, initial_input))
		self.save(password)

	def search_secrets(self, text: str, *, exact_match: bool = False) -> tuple[Secret, ...]:
		"""
		Searches the secret keys database.

		Args:
			text: The text to compare secret labels against.
			exact_match:
				If True, perform a case-sensitive, exact match against secret labels.
				If False, perform a case-insensitive, regular expression based search against secret labels.

		Returns:
			A tuple of secrets.
		"""
		text = text.strip()
		if not text:
			return ()
		if exact_match:
			return tuple(secret for secret in self.secrets if secret.label == text)
		text_regex: re.Pattern[str] = re.compile(text, flags=re.IGNORECASE | re.UNICODE)
		return tuple(secret for secret in self.secrets if text_regex.search(secret.label) is not None)

	def delete_secret(self, password: str, label: str) -> None:
		"""
		Deletes a secret from the database.

		Args:
			password: The password for encrypting the database.
			label: The label of the secret to be deleted.
		"""
		self._check_secret_label_whitespace(label)
		for secret in self.search_secrets(label, exact_match=True):
			self.secrets.remove(secret)
		self.save(password)

	def update_secret(self, password: str, label: str, new_label: str) -> None:
		"""
		Updates a secret with a new label.

		Args:
			password: The password for encrypting the database.
			label: The label of the secret to be updated.
			new_label: The new label to use for the secret.
		"""
		self._check_secret_label_whitespace(label)
		self._check_secret_label_whitespace(new_label)
		for secret in self.search_secrets(label, exact_match=True):
			index: int = self.secrets.index(secret)
			self.secrets[index] = Secret(new_label, *secret[1:])
		self.save(password)

	def increment_initial_input(self, password: str, secret: Secret, *, amount: int = 1) -> None:
		"""
		Increments the initial input of a secret.

		Args:
			password: The password for encrypting the database.
			secret: The secret to perform the operation on.
			amount: The amount to increment by.
		"""
		index: int = self.secrets.index(secret)
		initial_input: str = str(int(secret.input) + amount)
		self.secrets[index] = Secret(*secret[:-1], initial_input)
		self.save(password)

	def __getitem__(self, key: str) -> Any:
		return self._database[key]

	def __setitem__(self, key: str, value: Any) -> None:
		self._database[key] = value

	def __delitem__(self, key: str) -> None:
		del self._database[key]

	def __iter__(self) -> Iterator[str]:
		return iter(self._database)

	def __len__(self) -> int:
		return len(self._database)
