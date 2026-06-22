# Copyright (C) 2026 Nick Stockton
# SPDX-License-Identifier: MPL-2.0
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

"""Encryption."""

# Future Modules:
from __future__ import annotations

# Built-in Modules:
import base64
import secrets
from typing import Final

# Third-party Modules:
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from knickknacks.typedef import BytesOrStrType


SALT_LENGTH: Final[int] = 16


class DecryptionError(Exception):
	"""Base class for decryption errors."""


class WrongPasswordError(DecryptionError):
	"""Raised when a password does not match (decryption fails)."""


class InvalidEncryptedDataError(DecryptionError):
	"""Raised when data to be decrypted is malformed or lacks a valid signature."""


def decode_base64(text: BytesOrStrType) -> BytesOrStrType:
	"""
	Decodes base64 text.

	Args:
		text: The base64 encoded text.

	Returns:
		The base64 decoded text.
	"""
	if isinstance(text, str):
		data = base64.urlsafe_b64decode(bytes(text, "utf-8"))
		return str(data, "utf-8")
	return base64.urlsafe_b64decode(text)


def encode_base64(text: BytesOrStrType) -> BytesOrStrType:
	"""
	Encodes text in base64.

	Args:
		text: The text to encode in base64.

	Returns:
		The base64 encoded text.
	"""
	if isinstance(text, str):
		data = base64.urlsafe_b64encode(bytes(text, "utf-8"))
		return str(data, "utf-8")
	return base64.urlsafe_b64encode(text)


def _derive_fernet_key(password: str, salt: bytes) -> bytes:
	"""
	Derives a Fernet key using Argon2id from cryptography.

	Args:
		password: A password in plain text.
		salt: A 16+ byte random salt.

	Returns:
		The generated Fernet key (base64 urlsafe encoded).
	"""
	kdf = Argon2id(
		salt=salt,
		length=32,
		iterations=3,
		lanes=4,
		memory_cost=65536,
	)
	raw_key = kdf.derive(bytes(password, "utf-8"))
	return base64.urlsafe_b64encode(raw_key)


def encrypt(password: str, data: bytes) -> tuple[bytes, bytes]:
	"""
	Encrypts data using a password.

	Args:
		password: A password in plain text.
		data: The unencrypted data to be encrypted.

	Returns:
		A tuple containing a base64-encoded salt and the associated encrypted data.
	"""
	salt: bytes = secrets.token_bytes(SALT_LENGTH)
	key: bytes = _derive_fernet_key(password, salt)
	fernet = Fernet(key)
	encrypted_data: bytes = fernet.encrypt(data)
	return base64.urlsafe_b64encode(salt), encrypted_data


def decrypt(password: str, salt_b64: bytes | str, data: bytes) -> bytes:
	"""
	Decrypts data using a password.

	Args:
		password: A password in plain text.
		salt_b64: The base64-encoded salt returned by encrypt().
		data: The encrypted data to be decrypted.

	Returns:
		The decrypted data.

	Raises:
		WrongPasswordError: Incorrect password (decryption failed).
		InvalidEncryptedDataError: Data to be decrypted is invalid.
	"""
	try:
		salt: bytes = base64.urlsafe_b64decode(salt_b64)
	except ValueError as e:
		raise InvalidEncryptedDataError("Invalid salt format.") from e
	if len(salt) < SALT_LENGTH:
		raise InvalidEncryptedDataError("Salt too short.")
	key: bytes = _derive_fernet_key(password, salt)
	fernet = Fernet(key)
	try:
		decrypted_data: bytes = fernet.decrypt(data)
	except InvalidToken as e:
		raise WrongPasswordError("Incorrect password or corrupted data.") from e
	return decrypted_data
