# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.


# Future Modules:
from __future__ import annotations

# Built-in Modules:
import base64
import hmac
import time
from typing import Optional


def hotp(key: str, initial_input: int, length: Optional[int] = None) -> str:
	"""
	Generates an HMAC-based one-time password.

	Args:
		key: The secret key in base32 format.
		initial_input: The HOTP counter or TOTP interval.
		length: The desired length of the returned value.

	Returns:
		The OTP value as a string of digits with the desired length.
	"""
	if initial_input < 0:
		raise ValueError("initial_input must be a positive integer.")
	if length is None:
		length = 6
	elif not 6 <= length <= 10:  # Interval comparison.
		raise ValueError("length must be in range 6-10 (inclusive).")
	key = key.strip().replace(" ", "")
	width: int = len(key) + 7 & -8  # Round up by multiples of 8.
	key = key.ljust(width, "=")  # padding to an 8-character boundary.
	decoded_key: bytes = base64.b32decode(key, casefold=True)
	msg: bytes = initial_input.to_bytes(8, "big")
	digest: bytes = hmac.digest(decoded_key, msg, "sha1")
	offset: int = digest[-1] & 0xF  # Last unsigned nibble of hash.
	digest = digest[offset : offset + 4]  # Truncate to 4 bytes starting at the offset.
	code: int = int.from_bytes(digest, "big") & 0x7FFFFFFF
	code %= 10 ** length
	return str(code).zfill(length)


def totp(key: str, interval: int = 30, delta: int = 0, length: Optional[int] = None) -> str:
	"""
	Generates a time-based one-time password.

	TOTP is the same as HOTP, except the initial input is time based.
	TOTP values are only valid for a period of time, after which the value changes.
	The interval that TOTP values are generated can be found in the QR code from the server.

	Args:
		key: The secret key in base32 format.
		interval: The interval in seconds between OTP value changes.
		delta: A delta which is applied to the current TOTP period (1 for next value, -1 for previous).
		length: The desired length of the returned value.

	Returns:
		The TOTP value as a string of digits.
	"""
	current_period: int = int(time.time()) // interval
	return hotp(key, current_period + delta, length)
