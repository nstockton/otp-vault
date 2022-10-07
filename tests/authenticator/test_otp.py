# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.


# Future Modules:
from __future__ import annotations

# Built-in Modules:
from unittest import TestCase
from unittest.mock import Mock, patch

# Authenticator Modules:
from authenticator.otp import hotp, totp


# SAMPLE_KEY generated with str(base64.b32encode(secrets.token_bytes(20)), "utf-8")
SAMPLE_KEY: str = "YS6OI6MABO4FGOC4734D4TIVXWTEDZNT"
SAMPLE_TIME: float = 1664791695.2226732


class TestOTP(TestCase):
	def test_hotp_when_invalid_counter(self) -> None:
		with self.assertRaises(ValueError):
			hotp(SAMPLE_KEY, -1)

	def test_hotp_when_invalid_length(self) -> None:
		with self.assertRaises(ValueError):
			hotp(SAMPLE_KEY, 42, length=5)

	def test_hotp_when_valid_arguments(self) -> None:
		self.assertEqual(hotp(SAMPLE_KEY, 42), "990887")

	def test_hotp_when_valid_length_range(self) -> None:
		sample_code: str = "1035990887"
		for i in range(6, 11):
			self.assertEqual(hotp(SAMPLE_KEY, 42, length=i), sample_code[-i:])

	@patch("authenticator.otp.time.time", Mock(return_value=SAMPLE_TIME))
	def test_totp_when_default_arguments(self) -> None:
		self.assertEqual(totp(SAMPLE_KEY), "362173")

	@patch("authenticator.otp.time.time", Mock(return_value=SAMPLE_TIME))
	def test_totp_when_interval_specified(self) -> None:
		self.assertEqual(totp(SAMPLE_KEY, interval=60), "489376")

	@patch("authenticator.otp.time.time", Mock(return_value=SAMPLE_TIME))
	def test_totp_when_delta_specified(self) -> None:
		self.assertEqual(totp(SAMPLE_KEY, delta=3), "618886")

	@patch("authenticator.otp.time.time", Mock(return_value=SAMPLE_TIME))
	def test_totp_when_length_specified(self) -> None:
		self.assertEqual(totp(SAMPLE_KEY, length=8), "69362173")

	@patch("authenticator.otp.time.time", Mock(return_value=SAMPLE_TIME))
	def test_totp_when_multiple_arguments_specified(self) -> None:
		self.assertEqual(totp(SAMPLE_KEY, interval=90, delta=5, length=9), "099326450")
