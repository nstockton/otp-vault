# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.


# Future Modules:
from __future__ import annotations

# Built-in Modules:
from contextlib import ExitStack
from unittest import TestCase
from unittest.mock import Mock, mock_open, patch

# Authenticator Modules:
from authenticator.database import Database
from authenticator.main import add_secret, change_password, search_secrets


SAMPLE_PASSWORD: str = "test_password"
SAMPLE_FILENAME: str = "testdatabase-6ca2100554e249998edbe204445a9875"


@patch("authenticator.main.sys.stdout", Mock())  # Prevent output from print.
class TestMain(TestCase):
	def test_change_password_when_valid_password(self) -> None:
		mock_error_handler: Mock = Mock()
		with patch("authenticator.database.open", mock_open()) as mopen:
			database: Database = Database(SAMPLE_PASSWORD, SAMPLE_FILENAME)
			change_password(database, mock_error_handler, "some_valid_password")
			mock_error_handler.assert_not_called()
			mopen.assert_called_once()

	def test_change_password_when_invalid_password(self) -> None:
		mock_error_handler: Mock = Mock()
		with patch("authenticator.database.open", mock_open()) as mopen:
			database: Database = Database(SAMPLE_PASSWORD, SAMPLE_FILENAME)
			change_password(database, mock_error_handler, " invalid_password ")
			mock_error_handler.assert_called_once()
			mopen.assert_not_called()

	def test_add_secret_when_unique_secret_and_valid_inputs(self) -> None:
		mock_error_handler: Mock = Mock()
		with patch("authenticator.database.open", mock_open()) as mopen:
			database: Database = Database(SAMPLE_PASSWORD, SAMPLE_FILENAME)
			add_secret(database, mock_error_handler, SAMPLE_PASSWORD, "test_label", "test_key")
			self.assertIn(("test_label", "test_key"), database.secrets)
			mock_error_handler.assert_not_called()
			mopen.assert_called_once()

	def test_add_secret_when_existing_secret(self) -> None:
		mock_error_handler: Mock = Mock()
		with patch.object(Database, "save") as mock_save:
			database: Database = Database(SAMPLE_PASSWORD, SAMPLE_FILENAME)
			add_secret(database, mock_error_handler, SAMPLE_PASSWORD, "test_label", "test_key")
			mock_error_handler.assert_not_called()
			mock_save.assert_called_once_with(SAMPLE_PASSWORD)
			mock_error_handler.reset_mock()
			mock_save.reset_mock()
			# Adding a secret with the same label again should throw an error.
			add_secret(database, mock_error_handler, SAMPLE_PASSWORD, "test_label", "test_key")
			mock_error_handler.assert_called_once()
			mock_save.assert_not_called()

	def test_add_secret_when_invalid_password(self) -> None:
		mock_error_handler: Mock = Mock()
		with patch("authenticator.database.open", mock_open()) as mopen:
			database: Database = Database(SAMPLE_PASSWORD, SAMPLE_FILENAME)
			add_secret(database, mock_error_handler, " invalid_password ", "test_label", "test_key")
			mock_error_handler.assert_called_once()
			mopen.assert_not_called()

	def test_add_secret_when_invalid_label(self) -> None:
		mock_error_handler: Mock = Mock()
		with patch.object(Database, "save") as mock_save:
			database: Database = Database(SAMPLE_PASSWORD, SAMPLE_FILENAME)
			add_secret(database, mock_error_handler, SAMPLE_PASSWORD, " invalid_label ", "test_key")
			mock_error_handler.assert_called_once()
			mock_save.assert_not_called()

	def test_add_secret_when_invalid_key(self) -> None:
		mock_error_handler: Mock = Mock()
		with patch.object(Database, "save") as mock_save:
			database: Database = Database(SAMPLE_PASSWORD, SAMPLE_FILENAME)
			add_secret(database, mock_error_handler, SAMPLE_PASSWORD, "test_label", " invalid_key ")
			mock_error_handler.assert_called_once()
			mock_save.assert_not_called()

	def test_search_secrets_when_print_results(self) -> None:
		mock_error_handler: Mock = Mock()
		with ExitStack() as cm:
			mock_save = cm.enter_context(patch.object(Database, "save"))
			mock_print = cm.enter_context(patch("authenticator.main.print"))
			mock_totp = cm.enter_context(patch("authenticator.main.totp"))
			database: Database = Database(SAMPLE_PASSWORD, SAMPLE_FILENAME)
			database.add_secret(SAMPLE_PASSWORD, "test_label", "test_key")
			mock_save.reset_mock()
			search_secrets(database, mock_error_handler, SAMPLE_PASSWORD, "test")
			mock_error_handler.assert_not_called()
			mock_save.assert_not_called()
			mock_totp.assert_called_once_with("test_key")
			mock_print.assert_called_once()

	def test_search_secrets_when_no_results(self) -> None:
		mock_error_handler: Mock = Mock()
		with ExitStack() as cm:
			mock_sys_exit = cm.enter_context(patch("authenticator.main.sys.exit"))
			mock_save = cm.enter_context(patch.object(Database, "save"))
			database: Database = Database(SAMPLE_PASSWORD, SAMPLE_FILENAME)
			search_secrets(database, mock_error_handler, SAMPLE_PASSWORD, "unknown label")
			mock_sys_exit.assert_called_once()
			mock_save.assert_not_called()

	def test_search_secrets_when_copy_result(self) -> None:
		mock_error_handler: Mock = Mock()
		with ExitStack() as cm:
			mock_save = cm.enter_context(patch.object(Database, "save"))
			mock_totp = cm.enter_context(patch("authenticator.main.totp"))
			mock_set_clipboard = cm.enter_context(patch("authenticator.main.set_clipboard"))
			mock_totp.return_value = "123456"
			database: Database = Database(SAMPLE_PASSWORD, SAMPLE_FILENAME)
			database.add_secret(SAMPLE_PASSWORD, "test_label", "test_key")
			mock_save.reset_mock()
			search_secrets(database, mock_error_handler, SAMPLE_PASSWORD, "test", copy=1)
			mock_error_handler.assert_not_called()
			mock_save.assert_not_called()
			mock_totp.assert_called_once_with("test_key")
			mock_set_clipboard.assert_called_once_with("123456")

	def test_search_secrets_when_copy_not_in_range(self) -> None:
		mock_error_handler: Mock = Mock()
		with patch.object(Database, "save") as mock_save:
			database: Database = Database(SAMPLE_PASSWORD, SAMPLE_FILENAME)
			database.add_secret(SAMPLE_PASSWORD, "test_label", "test_key")
			mock_save.reset_mock()
			search_secrets(database, mock_error_handler, SAMPLE_PASSWORD, "test", copy=2)
			mock_error_handler.assert_called_once()
			mock_save.assert_not_called()

	def test_search_secrets_when_delete_result(self) -> None:
		mock_error_handler: Mock = Mock()
		with patch.object(Database, "save") as mock_save:
			database: Database = Database(SAMPLE_PASSWORD, SAMPLE_FILENAME)
			database.add_secret(SAMPLE_PASSWORD, "test_label", "test_key")
			mock_save.reset_mock()
			self.assertEqual(len(database.secrets), 1)
			search_secrets(database, mock_error_handler, SAMPLE_PASSWORD, "test", delete=1)
			self.assertEqual(len(database.secrets), 0)
			mock_error_handler.assert_not_called()
			mock_save.assert_called_once_with(SAMPLE_PASSWORD)

	def test_search_secrets_when_delete_not_in_range(self) -> None:
		mock_error_handler: Mock = Mock()
		with patch.object(Database, "save") as mock_save:
			database: Database = Database(SAMPLE_PASSWORD, SAMPLE_FILENAME)
			database.add_secret(SAMPLE_PASSWORD, "test_label", "test_key")
			mock_save.reset_mock()
			search_secrets(database, mock_error_handler, SAMPLE_PASSWORD, "test", delete=2)
			mock_error_handler.assert_called_once()
			mock_save.assert_not_called()
