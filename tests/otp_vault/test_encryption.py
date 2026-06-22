# Copyright (C) 2026 Nick Stockton
# SPDX-License-Identifier: MPL-2.0
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# Future Modules:
from __future__ import annotations

# Built-in Modules:
from unittest import TestCase

# OTP Vault Modules:
from otp_vault.encryption import (
	InvalidEncryptedDataError,
	WrongPasswordError,
	decode_base64,
	decrypt,
	encode_base64,
	encrypt,
)


class TestEncryption(TestCase):
	def test_base64_encode_and_decode(self) -> None:
		decoded: str = "Hello world!"
		decoded_bytes: bytes = bytes(decoded, "utf-8")
		encoded: str = "SGVsbG8gd29ybGQh"
		encoded_bytes: bytes = bytes(encoded, "utf-8")
		self.assertEqual(decode_base64(encoded), decoded)
		self.assertEqual(decode_base64(encoded_bytes), decoded_bytes)
		self.assertEqual(encode_base64(decoded), encoded)
		self.assertEqual(encode_base64(decoded_bytes), encoded_bytes)

	def test_encryption_decryption(self) -> None:
		password: str = "test_password"  # NOQA: S105
		unencrypted: bytes = b"Some data in plain text."
		# Test encrypt.
		salt_b64, encrypted_data = encrypt(password, unencrypted)
		self.assertNotEqual(encrypted_data, unencrypted)
		# Test decrypt with valid password, hash, and data.
		self.assertEqual(decrypt(password, salt_b64, encrypted_data), unencrypted)
		# Test decrypt with invalid password.
		with self.assertRaises(WrongPasswordError):
			decrypt("invalid_password", salt_b64, encrypted_data)
		# Test decrypt with invalid base64 salt.
		with self.assertRaises(InvalidEncryptedDataError):
			decrypt(password, b"**junk123**", encrypted_data)
		# Test decrypt with empty salt.
		with self.assertRaises(InvalidEncryptedDataError):
			decrypt(password, b"", encrypted_data)
