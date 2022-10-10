# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.


# Future Modules:
from __future__ import annotations

# Built-in Modules:
from contextlib import ExitStack
from unittest import TestCase
from unittest.mock import Mock, mock_open, patch

# OTP Vault Modules:
from otp_vault.database import Database, Secret
from otp_vault.main import add_secret, change_password, get_token, search_secrets


SAMPLE_PASSWORD: str = "test_password"
SAMPLE_FILENAME: str = "testdatabase-6ca2100554e249998edbe204445a9875"


@patch("otp_vault.main.sys.stdout", Mock())  # Prevent output from print.
class TestMain(TestCase):
	def test_get_token_when_invalid_token_type(self) -> None:
		with self.assertRaises(ValueError):
			get_token("invalid_token")

	def test_change_password_when_valid_password(self) -> None:
		mock_error_handler: Mock = Mock()
		with patch("otp_vault.database.open", mock_open()) as mopen:
			database: Database = Database(SAMPLE_PASSWORD, SAMPLE_FILENAME)
			change_password(database, mock_error_handler, "some_valid_password")
			mock_error_handler.assert_not_called()
			mopen.assert_called_once()

	def test_change_password_when_invalid_password(self) -> None:
		mock_error_handler: Mock = Mock()
		with patch("otp_vault.database.open", mock_open()) as mopen:
			database: Database = Database(SAMPLE_PASSWORD, SAMPLE_FILENAME)
			change_password(database, mock_error_handler, " invalid_password ")
			mock_error_handler.assert_called_once()
			mopen.assert_not_called()

	def test_add_secret_when_unique_secret_and_valid_inputs(self) -> None:
		mock_error_handler: Mock = Mock()
		with patch("otp_vault.database.open", mock_open()) as mopen:
			database: Database = Database(SAMPLE_PASSWORD, SAMPLE_FILENAME)
			add_secret(
				database, mock_error_handler, SAMPLE_PASSWORD, "test_label", "test_key", "totp", 6, "0"
			)
			self.assertIn(Secret("test_label", "test_key", "totp", 6, "0"), database.secrets)
			mock_error_handler.assert_not_called()
			mopen.assert_called_once()

	def test_add_secret_when_existing_secret(self) -> None:
		mock_error_handler: Mock = Mock()
		with patch.object(Database, "save") as mock_save:
			database: Database = Database(SAMPLE_PASSWORD, SAMPLE_FILENAME)
			add_secret(
				database, mock_error_handler, SAMPLE_PASSWORD, "test_label", "test_key", "totp", 6, "0"
			)
			mock_error_handler.assert_not_called()
			mock_save.assert_called_once_with(SAMPLE_PASSWORD)
			mock_error_handler.reset_mock()
			mock_save.reset_mock()
			# Adding a secret with the same label again should throw an error.
			add_secret(
				database, mock_error_handler, SAMPLE_PASSWORD, "test_label", "test_key", "totp", 6, "0"
			)
			mock_error_handler.assert_called_once()
			mock_save.assert_not_called()

	def test_add_secret_when_invalid_password(self) -> None:
		mock_error_handler: Mock = Mock()
		with patch("otp_vault.database.open", mock_open()) as mopen:
			database: Database = Database(SAMPLE_PASSWORD, SAMPLE_FILENAME)
			add_secret(
				database, mock_error_handler, " invalid_password ", "test_label", "test_key", "totp", 6, "0"
			)
			mock_error_handler.assert_called_once()
			mopen.assert_not_called()

	def test_add_secret_when_invalid_label(self) -> None:
		mock_error_handler: Mock = Mock()
		with patch.object(Database, "save") as mock_save:
			database: Database = Database(SAMPLE_PASSWORD, SAMPLE_FILENAME)
			add_secret(
				database, mock_error_handler, SAMPLE_PASSWORD, " invalid_label ", "test_key", "totp", 6, "0"
			)
			mock_error_handler.assert_called_once()
			mock_save.assert_not_called()

	def test_add_secret_when_invalid_key(self) -> None:
		mock_error_handler: Mock = Mock()
		with patch.object(Database, "save") as mock_save:
			database: Database = Database(SAMPLE_PASSWORD, SAMPLE_FILENAME)
			add_secret(
				database, mock_error_handler, SAMPLE_PASSWORD, "test_label", " invalid_key ", "totp", 6, "0"
			)
			mock_error_handler.assert_called_once()
			mock_save.assert_not_called()

	def test_search_secrets_when_print_results(self) -> None:
		mock_error_handler: Mock = Mock()
		with ExitStack() as cm:
			mock_save = cm.enter_context(patch.object(Database, "save"))
			mock_print = cm.enter_context(patch("otp_vault.main.print"))
			database: Database = Database(SAMPLE_PASSWORD, SAMPLE_FILENAME)
			database.add_secret(SAMPLE_PASSWORD, "test_label", "test_key", "totp", 6, "0")
			mock_save.reset_mock()
			search_secrets(database, mock_error_handler, SAMPLE_PASSWORD, "test")
			mock_error_handler.assert_not_called()
			mock_save.assert_not_called()
			mock_print.assert_called_once()

	def test_search_secrets_when_no_results(self) -> None:
		mock_error_handler: Mock = Mock()
		with ExitStack() as cm:
			mock_sys_exit = cm.enter_context(patch("otp_vault.main.sys.exit"))
			mock_save = cm.enter_context(patch.object(Database, "save"))
			database: Database = Database(SAMPLE_PASSWORD, SAMPLE_FILENAME)
			search_secrets(database, mock_error_handler, SAMPLE_PASSWORD, "unknown label")
			mock_sys_exit.assert_called_once()
			mock_save.assert_not_called()

	def test_search_secrets_when_copy_result_succeeds(self) -> None:
		mock_error_handler: Mock = Mock()
		with ExitStack() as cm:
			mock_save = cm.enter_context(patch.object(Database, "save"))
			mock_increment_initial_input = cm.enter_context(patch.object(Database, "increment_initial_input"))
			mock_hotp = cm.enter_context(patch("otp_vault.main.otp.hotp"))
			mock_set_clipboard = cm.enter_context(patch("otp_vault.main.set_clipboard"))
			database: Database = Database(SAMPLE_PASSWORD, SAMPLE_FILENAME)
			secret: Secret = Secret("test_label", "test_key", "hotp", 6, "0")
			database.add_secret(SAMPLE_PASSWORD, *secret)
			mock_save.reset_mock()
			mock_hotp.return_value = "123456"
			mock_set_clipboard.return_value = True
			search_secrets(database, mock_error_handler, SAMPLE_PASSWORD, "test", copy=1)
			mock_error_handler.assert_not_called()
			mock_save.assert_not_called()
			mock_hotp.assert_called_once_with("test_key", "0", length=6)
			mock_set_clipboard.assert_called_once_with("123456")
			mock_increment_initial_input.assert_called_once_with(SAMPLE_PASSWORD, secret, amount=1)

	def test_search_secrets_when_copy_result_fails(self) -> None:
		mock_error_handler: Mock = Mock()
		with ExitStack() as cm:
			mock_save = cm.enter_context(patch.object(Database, "save"))
			mock_totp = cm.enter_context(patch("otp_vault.main.otp.totp"))
			mock_set_clipboard = cm.enter_context(patch("otp_vault.main.set_clipboard"))
			database: Database = Database(SAMPLE_PASSWORD, SAMPLE_FILENAME)
			database.add_secret(SAMPLE_PASSWORD, "test_label", "test_key", "totp", 6, "0")
			mock_save.reset_mock()
			mock_totp.return_value = "123456"
			mock_set_clipboard.return_value = False
			search_secrets(database, mock_error_handler, SAMPLE_PASSWORD, "test", copy=1)
			mock_totp.assert_called_once_with("test_key", "0", length=6)
			mock_set_clipboard.assert_called_once_with("123456")
			mock_error_handler.assert_not_called()
			mock_save.assert_not_called()

	def test_search_secrets_when_copy_not_in_range(self) -> None:
		mock_error_handler: Mock = Mock()
		with patch.object(Database, "save") as mock_save:
			database: Database = Database(SAMPLE_PASSWORD, SAMPLE_FILENAME)
			database.add_secret(SAMPLE_PASSWORD, "test_label", "test_key", "totp", 6, "0")
			mock_save.reset_mock()
			search_secrets(database, mock_error_handler, SAMPLE_PASSWORD, "test", copy=2)
			mock_error_handler.assert_called_once()
			mock_save.assert_not_called()

	def test_search_secrets_when_delete_result(self) -> None:
		mock_error_handler: Mock = Mock()
		with patch.object(Database, "save") as mock_save:
			database: Database = Database(SAMPLE_PASSWORD, SAMPLE_FILENAME)
			database.add_secret(SAMPLE_PASSWORD, "test_label", "test_key", "totp", 6, "0")
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
			database.add_secret(SAMPLE_PASSWORD, "test_label", "test_key", "totp", 6, "0")
			mock_save.reset_mock()
			search_secrets(database, mock_error_handler, SAMPLE_PASSWORD, "test", delete=2)
			mock_error_handler.assert_called_once()
			mock_save.assert_not_called()

	def test_search_secrets_when_update_result(self) -> None:
		mock_error_handler: Mock = Mock()
		with patch.object(Database, "save") as mock_save:
			database: Database = Database(SAMPLE_PASSWORD, SAMPLE_FILENAME)
			database.add_secret(SAMPLE_PASSWORD, "test_label", "test_key", "totp", 6, "0")
			mock_save.reset_mock()
			self.assertIn(Secret("test_label", "test_key", "totp", 6, "0"), database.secrets)
			self.assertNotIn(Secret("new_label", "test_key", "totp", 6, "0"), database.secrets)
			search_secrets(database, mock_error_handler, SAMPLE_PASSWORD, "test", update=(1, "new_label"))
			self.assertNotIn(Secret("test_label", "test_key", "totp", 6, "0"), database.secrets)
			self.assertIn(Secret("new_label", "test_key", "totp", 6, "0"), database.secrets)
			mock_error_handler.assert_not_called()
			mock_save.assert_called_once_with(SAMPLE_PASSWORD)

	def test_search_secrets_when_update_not_in_range(self) -> None:
		mock_error_handler: Mock = Mock()
		with patch.object(Database, "save") as mock_save:
			database: Database = Database(SAMPLE_PASSWORD, SAMPLE_FILENAME)
			database.add_secret(SAMPLE_PASSWORD, "test_label", "test_key", "totp", 6, "0")
			mock_save.reset_mock()
			search_secrets(database, mock_error_handler, SAMPLE_PASSWORD, "test", update=(2, "new_label"))
			mock_error_handler.assert_called_once()
			mock_save.assert_not_called()
