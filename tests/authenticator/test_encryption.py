# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.


# Future Modules:
from __future__ import annotations

# Built-in Modules:
from unittest import TestCase

# Authenticator Modules:
from authenticator.encryption import (
	InvalidEncryptedDataError,
	InvalidHashError,
	WrongPasswordError,
	decrypt,
	encrypt,
)


class TestEncryption(TestCase):
	def test_encryption_decryption(self) -> None:
		password: str = "test_password"
		unencrypted: bytes = b"Some data in plain text."
		# Test encrypt.
		hash, encrypted_data = encrypt(password, unencrypted)
		self.assertTrue(hash.startswith("$argon2"))
		self.assertNotEqual(encrypted_data, unencrypted)
		# Test decrypt with valid password, hash, and data.
		self.assertEqual(decrypt(password, hash, encrypted_data), (unencrypted, False))
		# Test decrypt with invalid password.
		with self.assertRaises(WrongPasswordError):
			self.assertEqual(decrypt("invalid_password", hash, encrypted_data), (unencrypted, False))
		# Test decrypt with invalid hash.
		with self.assertRaises(InvalidHashError):
			self.assertEqual(decrypt(password, "invalid_hash", encrypted_data), (unencrypted, False))
		# Test decrypt with invalid encrypted data.
		with self.assertRaises(InvalidEncryptedDataError):
			self.assertEqual(decrypt(password, hash, b"invalid_encrypted_data"), (unencrypted, False))
