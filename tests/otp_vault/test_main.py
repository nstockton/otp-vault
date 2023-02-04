# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.


# Future Modules:
from __future__ import annotations

# Built-in Modules:
import sys
from contextlib import ExitStack
from unittest import TestCase
from unittest.mock import Mock, mock_open, patch

# OTP Vault Modules:
from otp_vault.database import Database, Secret
from otp_vault.main import add_secret, change_password, process_args, search_secrets


SAMPLE_PASSWORD: str = "test_password"
SAMPLE_FILENAME: str = "testdatabase-6ca2100554e249998edbe204445a9875"


@patch("otp_vault.main.sys.stdout", Mock())  # Prevent output from print.
class TestMain(TestCase):
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

	def test_add_secret_when_key_contains_white_space(self) -> None:
		mock_error_handler: Mock = Mock()
		with patch.object(Database, "save") as mock_save:
			database: Database = Database(SAMPLE_PASSWORD, SAMPLE_FILENAME)
			before: Secret = Secret("test_label", " invalid\tkey ", "totp", 6, "0")
			after: Secret = Secret("test_label", "invalidkey", "totp", 6, "0")
			self.assertNotIn(after, database.secrets)
			add_secret(database, mock_error_handler, SAMPLE_PASSWORD, *before)
			self.assertIn(after, database.secrets)
			mock_error_handler.assert_not_called()
			mock_save.assert_called_once_with(SAMPLE_PASSWORD)

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

	def test_search_secrets_when_action_performed_on_item_other_than_first(self) -> None:
		# This tests for a regression occurring when the user tries to
		# perform an action on a search result, other than the first.
		# We need to make sure that only the output of the action is printed when an action is supplied.
		mock_error_handler: Mock = Mock()
		with ExitStack() as cm:
			mock_save = cm.enter_context(patch.object(Database, "save"))
			mock_print = cm.enter_context(patch("otp_vault.main.print"))
			mock_totp = cm.enter_context(patch("otp_vault.main.otp.totp"))
			mock_set_clipboard = cm.enter_context(patch("otp_vault.main.set_clipboard"))
			database: Database = Database(SAMPLE_PASSWORD, SAMPLE_FILENAME)
			secret1: Secret = Secret("test_label1", "test_key1", "totp", 6, "0")
			secret2: Secret = Secret("test_label2", "test_key2", "totp", 6, "0")
			secret3: Secret = Secret("test_label3", "test_key3", "totp", 6, "0")
			database.add_secret(SAMPLE_PASSWORD, *secret1)
			database.add_secret(SAMPLE_PASSWORD, *secret2)
			database.add_secret(SAMPLE_PASSWORD, *secret3)
			mock_save.reset_mock()
			mock_totp.return_value = "123456"
			mock_set_clipboard.return_value = True
			search_secrets(database, mock_error_handler, SAMPLE_PASSWORD, "test", copy=3)
			mock_error_handler.assert_not_called()
			mock_save.assert_not_called()
			mock_totp.assert_called_once()
			mock_set_clipboard.assert_called_once()
			mock_print.assert_called_once()

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

	def test_process_args_when_no_args_given(self) -> None:
		with patch("otp_vault.main.argparse.ArgumentParser.error") as mock_error:
			parsed, _ = process_args()
			self.assertIsNone(parsed.change_password)
			self.assertIsNone(parsed.add)
			self.assertEqual(parsed.type, "totp")
			self.assertEqual(parsed.length, 6)
			self.assertEqual(parsed.initial_input, "0")
			self.assertIsNone(parsed.search)
			self.assertIsNone(parsed.copy)
			self.assertIsNone(parsed.delete)
			self.assertIsNone(parsed.update)
			mock_error.assert_called()

	def test_process_args_when_no_password_given(self) -> None:
		with patch("otp_vault.main.argparse.ArgumentParser.error") as mock_error:
			process_args("--search", "text")
			mock_error.assert_called_once()

	def test_process_args_when_no_required_exclusive_args_given(self) -> None:
		with patch("otp_vault.main.argparse.ArgumentParser.error") as mock_error:
			process_args("test_password")
			mock_error.assert_called_once()

	def test_process_args_when_multiple_required_exclusive_args_given(self) -> None:
		with ExitStack() as cm:
			if sys.version_info < (3, 9):
				# In the argparse.ArgumentParser class, parse_args passes args and namespace
				# to parse_known_args, which then passes them on to _parse_known_args. The
				# parse_args method expects to receive back a tuple containing a namespace
				# instance and a list of unrecognized args.
				# In Python versions < 3.9, if _parse_known_args raises ArgumentError,
				# parse_known_args calls the error method, which then exits the program.
				# Because the error method is being mocked however, parse_known_args is
				# allowed to return None, and parse_args ends up raising TypeError when it
				# tries to perform iterable unpacking on an instance of None. This is fixed
				# in later versions of Python when the exit_on_error flag was added, due to
				# parse_known_args being modified to always return the expected tuple.
				cm.enter_context(self.assertRaises(TypeError))
			mock_error = cm.enter_context(patch("otp_vault.main.argparse.ArgumentParser.error"))
			process_args("test_password", "--change-password", "new_password", "--add", "label", "key")
			mock_error.assert_called()
			mock_error.reset_mock()
			process_args("test_password", "--add", "label", "key", "--search", "text")
			mock_error.assert_called()
			mock_error.reset_mock()
			process_args("test_password", "--change-password", "new_password", "--search", "text")
			mock_error.assert_called()

	def test_process_args_when_valid_args(self) -> None:
		with patch("otp_vault.main.argparse.ArgumentParser.error") as mock_error:
			parsed, _ = process_args("test_password", "--change-password", "new_password")
			self.assertEqual(parsed.change_password, "new_password")
			parsed, _ = process_args("test_password", "--add", "label", "key")
			self.assertEqual(parsed.add, ("label", "key"))
			parsed, _ = process_args("test_password", "--add", "label", "key", "--type", "hotp")
			self.assertEqual(parsed.type, "hotp")
			parsed, _ = process_args("test_password", "--add", "label", "key", "--length", "8")
			self.assertEqual(parsed.length, 8)
			parsed, _ = process_args("test_password", "--add", "label", "key", "--initial-input", "1234")
			self.assertEqual(parsed.initial_input, "1234")
			parsed, _ = process_args("test_password", "--search", "text")
			self.assertEqual(parsed.search, "text")
			parsed, _ = process_args("test_password", "--search", "text", "--copy", "4")
			self.assertEqual(parsed.copy, 4)
			parsed, _ = process_args("test_password", "--search", "text", "--delete", "4")
			self.assertEqual(parsed.delete, 4)
			parsed, _ = process_args("test_password", "--search", "text", "--update", "4", "new_label")
			self.assertEqual(parsed.update, (4, "new_label"))
			mock_error.assert_not_called()

	def test_process_args_when_update_item_number_invalid(self) -> None:
		with patch("otp_vault.main.argparse.ArgumentParser.error") as mock_error:
			parsed, _ = process_args("test_password", "--search", "text", "--update", "invalid", "new_label")
			mock_error.assert_called_once()
