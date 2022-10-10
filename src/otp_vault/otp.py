# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.


# Future Modules:
from __future__ import annotations

# Built-in Modules:
import base64
import hashlib
import hmac
import time


def motp(key: str, initial_input: str, *, length: int = 6) -> str:
	"""
	Generates a mobile one-time password.

	Note:
		https://motp.sourceforge.net/#1.1

	Args:
		key: A secret key of length 16 containing alphanumeric hex.
		initial_input: A 4-digit pin.
		length: The desired length of the generated code.

	Returns:
		The MOTP value as a string of alphanumeric hex with the desired length.
	"""
	key = key.strip()
	initial_input = initial_input.strip()
	try:
		int(key, 16)
	except ValueError:
		raise ValueError("key must contain only hex digits.")
	if initial_input and not initial_input.isdigit():
		raise ValueError("initial_input must contain only digits.")
	if len(initial_input) != 4:
		raise ValueError("initial_input must have length 4.")
	counter: int = int(time.time()) // 10
	data: bytes = bytes(f"{counter}{key}{initial_input}", "us-ascii")
	return hashlib.md5(data).hexdigest()[:length]


def hotp(key: str, initial_input: str, *, length: int = 6) -> str:
	"""
	Generates an HMAC-based one-time password.

	Note:
		https://www.ietf.org/rfc/rfc4226.txt

	Args:
		key: The secret key encoded in base32 format.
		initial_input: The HOTP counter.
		length: The desired length of the returned value.

	Returns:
		The HOTP value as a string of digits with the desired length.
	"""
	if not initial_input.isdigit():
		raise ValueError("initial_input must contain only digits.")
	if not 6 <= length <= 10:  # Interval comparison.
		raise ValueError("length must be in range 6-10 (inclusive).")
	counter: int = int(initial_input)
	width: int = len(key) + 7 & -8  # Round up by multiples of 8.
	key = key.ljust(width, "=")  # padding to an 8-character boundary.
	decoded_key: bytes = base64.b32decode(key, casefold=True)
	msg: bytes = counter.to_bytes(8, "big")
	digest: bytes = hmac.digest(decoded_key, msg, "sha1")
	offset: int = digest[-1] & 0xF  # Last unsigned nibble of hash.
	digest = digest[offset : offset + 4]  # Truncate to 4 bytes starting at the offset.
	code: int = int.from_bytes(digest, "big") & 0x7FFFFFFF
	code %= 10 ** length
	return str(code).zfill(length)


def totp(key: str, initial_input: str, *, time_step: int = 30, delta: int = 0, length: int = 6) -> str:
	"""
	Generates a time-based one-time password.

	Note:
		TOTP is the same as HOTP, except the initial input is time based.
		TOTP values are only valid for a period of time, after which the value changes.
		The interval that TOTP values are generated can be found in the QR code from the server.
		https://www.ietf.org/rfc/rfc6238.txt

	Args:
		key: The secret key encoded in base32 format.
		initial_input: A Unix timestamp representing an alternate start time when calculating steps.
		time_step: The interval in seconds between OTP value changes.
		delta: A delta which is applied to the current time-step (1 for next step, -1 for previous).
		length: The desired length of the returned value.

	Returns:
		The TOTP value as a string of digits.
	"""
	start_epoch: int = int(initial_input)
	current_step: int = int(time.time() - start_epoch) // time_step
	return hotp(key, str(current_step + delta), length=length)
