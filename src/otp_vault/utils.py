# Copyright (C) 2025 Nick Stockton
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

"""Misc utility functions."""

# Future Modules:
from __future__ import annotations

# Built-in Modules:
from pathlib import Path

# Third-party Modules:
from knickknacks.platforms import get_directory_path, is_frozen


DATA_DIRECTORY: str = "otp_vault_data"


def get_data_path(*args: str) -> str:
	"""
	Retrieves the path of the data directory.

	Args:
		*args: Positional arguments to be passed to os.join after the data path.

	Returns:
		The path.
	"""
	path = Path(get_directory_path())
	if not is_frozen():
		path = path.parent
	return str(path.joinpath(DATA_DIRECTORY, *args).resolve())
