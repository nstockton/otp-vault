# Copyright (C) 2025 Nick Stockton
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# Future Modules:
from __future__ import annotations

# Built-in Modules:
from unittest import TestCase
from unittest.mock import Mock, patch

# OTP Vault Modules:
from otp_vault.otp import hotp, motp, totp


# SAMPLE_HOTP_KEY generated with str(base64.b32encode(secrets.token_bytes(20)), "utf-8")
SAMPLE_HOTP_KEY: str = "YS6OI6MABO4FGOC4734D4TIVXWTEDZNT"

# SAMPLE_MOTP_KEY generated with secrets.token_hex(8)
SAMPLE_MOTP_KEY: str = "d5f918a35f93b30a"
SAMPLE_TIME: float = 1664791695.2226732


class TestOTP(TestCase):
	def test_motp_when_invalid_key(self) -> None:
		with self.assertRaises(ValueError):
			motp(" invalid ", "0000")

	def test_motp_when_initial_input_not_all_digits(self) -> None:
		with self.assertRaises(ValueError):
			motp(SAMPLE_MOTP_KEY, "-1")

	def test_motp_when_initial_input_wrong_length(self) -> None:
		with self.assertRaises(ValueError):
			motp(SAMPLE_MOTP_KEY, "0")

	@patch("otp_vault.otp.time.time", Mock(return_value=SAMPLE_TIME))
	def test_motp_when_default_arguments(self) -> None:
		self.assertEqual(motp(SAMPLE_MOTP_KEY, "0000"), "5c7c11")

	@patch("otp_vault.otp.time.time", Mock(return_value=SAMPLE_TIME))
	def test_motp_when_length_specified(self) -> None:
		self.assertEqual(motp(SAMPLE_MOTP_KEY, "0000", length=8), "5c7c117b")

	def test_hotp_when_invalid_initial_input(self) -> None:
		with self.assertRaises(ValueError):
			hotp(SAMPLE_HOTP_KEY, "-1")

	def test_hotp_when_invalid_length(self) -> None:
		with self.assertRaises(ValueError):
			hotp(SAMPLE_HOTP_KEY, "42", length=5)

	def test_hotp_when_valid_arguments(self) -> None:
		self.assertEqual(hotp(SAMPLE_HOTP_KEY, "42"), "990887")

	def test_hotp_when_valid_length_range(self) -> None:
		sample_code: str = "1035990887"
		for i in range(6, 11):
			self.assertEqual(hotp(SAMPLE_HOTP_KEY, "42", length=i), sample_code[-i:])

	@patch("otp_vault.otp.time.time", Mock(return_value=SAMPLE_TIME))
	def test_totp_when_default_arguments(self) -> None:
		self.assertEqual(totp(SAMPLE_HOTP_KEY, "0"), "362173")

	@patch("otp_vault.otp.time.time", Mock(return_value=SAMPLE_TIME))
	def test_totp_when_time_step_specified(self) -> None:
		self.assertEqual(totp(SAMPLE_HOTP_KEY, "0", time_step=60), "489376")

	@patch("otp_vault.otp.time.time", Mock(return_value=SAMPLE_TIME))
	def test_totp_when_delta_specified(self) -> None:
		self.assertEqual(totp(SAMPLE_HOTP_KEY, "0", delta=3), "618886")

	@patch("otp_vault.otp.time.time", Mock(return_value=SAMPLE_TIME))
	def test_totp_when_length_specified(self) -> None:
		self.assertEqual(totp(SAMPLE_HOTP_KEY, "0", length=8), "69362173")

	@patch("otp_vault.otp.time.time", Mock(return_value=SAMPLE_TIME))
	def test_totp_when_multiple_arguments_specified(self) -> None:
		self.assertEqual(totp(SAMPLE_HOTP_KEY, "0", time_step=90, delta=5, length=9), "099326450")
