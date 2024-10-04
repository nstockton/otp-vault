# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.


# Future Modules:
from __future__ import annotations

# Built-in Modules:
import os
from unittest import TestCase

# OTP Vault Modules:
from otp_vault import utils


class TestUtils(TestCase):
	def test_get_data_path(self) -> None:
		subdirectory: tuple[str, ...] = ("level1", "level2")
		output: str = os.path.join(
			os.path.dirname(utils.__file__), os.path.pardir, utils.DATA_DIRECTORY, *subdirectory
		)
		self.assertEqual(utils.get_data_path(*subdirectory), os.path.realpath(output))
