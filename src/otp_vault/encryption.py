"""OTP encryption."""


# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# Future Modules:
from __future__ import annotations

# Built-in Modules:
import base64

# Third-party Modules:
import argon2
from cryptography.fernet import Fernet, InvalidToken


class DecryptionError(Exception):
	"""Base class for decryption errors."""


class InvalidHashError(DecryptionError):
	"""Raised when a hash is invalid or corrupted."""


class WrongPasswordError(DecryptionError):
	"""Raised when a password does not match a hash."""


class InvalidEncryptedDataError(DecryptionError):
	"""Raised when data to be decrypted is malformed or lacks a valid signature."""


def generate_fernet_key(password: str, hash: str) -> bytes:
	"""
	Generates a Fernet key (required when instantiating the Fernet class).

	Args:
		password: A password in plain text.
		hash: The Argon2 hash of the password.

	Returns:
		The generated Fernet key.
	"""
	parameters: argon2.Parameters = argon2.extract_parameters(hash)
	salt: str = hash.split("$")[-2]
	raw_hash: bytes = argon2.low_level.hash_secret_raw(
		secret=bytes(password, "utf_16_le"),
		salt=bytes(salt, "utf_16_le"),
		time_cost=parameters.time_cost,
		memory_cost=parameters.memory_cost,
		parallelism=parameters.parallelism,
		hash_len=parameters.hash_len,
		type=parameters.type,
		version=parameters.version,
	)
	return base64.urlsafe_b64encode(raw_hash)


def encrypt(password: str, data: bytes) -> tuple[str, bytes]:
	"""
	Encrypts data using a password.

	Args:
		password: A password in plain text.
		data: The unencrypted data to be encrypted.

	Returns:
		A tuple containing an Argon2 hash and the associated encrypted data.
	"""
	hasher: argon2.PasswordHasher = argon2.PasswordHasher()
	hash: str = hasher.hash(password)
	key: bytes = generate_fernet_key(password, hash)
	fernet = Fernet(key)
	encrypted_data: bytes = fernet.encrypt(data)
	return hash, encrypted_data


def decrypt(password: str, hash: str, data: bytes) -> tuple[bytes, bool]:
	"""
	decrypts data using a password.

	Args:
		password: A password in plain text.
		hash: The Argon2 hash associated with the encrypted data.
		data: The encrypted data to be decrypted.

	Returns:
		A tuple containing the decrypted data, and a boolean representing if the password needs rehashing.

	Raises:
		WrongPasswordError: The data cannot be decrypted with password.
	"""
	hasher = argon2.PasswordHasher()
	try:
		hasher.verify(hash, password)
	except argon2.exceptions.VerifyMismatchError as e:
		raise WrongPasswordError("Password does not match hash.") from e
	except argon2.exceptions.InvalidHash as e:
		raise InvalidHashError("Invalid hash.") from e
	key: bytes = generate_fernet_key(password, hash)
	fernet = Fernet(key)
	try:
		decrypted_data: bytes = fernet.decrypt(data)
	except InvalidToken as e:
		raise InvalidEncryptedDataError("Data to be decrypted is invalid.") from e
	return decrypted_data, hasher.check_needs_rehash(hash)
