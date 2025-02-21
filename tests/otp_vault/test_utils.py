# Copyright (C) 2025 Nick Stockton
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# Future Modules:
from __future__ import annotations

# Built-in Modules:
from pathlib import Path
from unittest import TestCase, mock

# OTP Vault Modules:
from otp_vault import utils


class TestUtils(TestCase):
	@mock.patch("otp_vault.utils.isFrozen")
	def test_get_data_path(self, mock_is_frozen: mock.Mock) -> None:
		subdirectory: tuple[str, ...] = ("level1", "level2")
		frozen_output = str(
			Path(utils.__file__).parent.joinpath(utils.DATA_DIRECTORY, *subdirectory).resolve()
		)
		not_frozen_output = str(
			Path(utils.__file__).parent.parent.joinpath(utils.DATA_DIRECTORY, *subdirectory).resolve()
		)
		mock_is_frozen.return_value = True
		self.assertEqual(utils.get_data_path(*subdirectory), frozen_output)
		mock_is_frozen.return_value = False
		self.assertEqual(utils.get_data_path(*subdirectory), not_frozen_output)
