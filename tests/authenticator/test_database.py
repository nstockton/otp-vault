# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.


# Future Modules:
from __future__ import annotations

# Built-in Modules:
import os.path
from contextlib import ExitStack
from unittest import TestCase
from unittest.mock import Mock, PropertyMock, mock_open, patch

# Third-party Modules:
from jsonschema.exceptions import ValidationError

# Authenticator Modules:
from authenticator.database import DATA_DIRECTORY, Database, DatabaseError, Secret
from authenticator.encryption import decrypt


SAMPLE_PASSWORD: str = "test_password"
SAMPLE_FILENAME: str = "testdatabase-878d2b571a6e41d5b0cd61f8c98a13ae"
SAMPLE_DATA: bytes = (
	b"acd34ec20b659e7c9782e4fe6e487382a3e3e3514a8d62ee30010ff94a677042\n"
	+ b"$argon2id$v=19$m=65536,t=3,p=4$T3cOxLgyOhmUDmK0kfDz0Q$0As+kPAbE4pNyrHSp6b3vFSt0GtgGsQJ9Pz9fTrg8Pc\n"
	+ b"gAAAAABjQDUoYx9A1F46X79yzpDqxcg9dBUoynXVBvx2ofBxY8qssfH7oResFfVK5jx7JF3ONxcB35cYBp"
	+ b"uUb3W6I-3Hk5fa6MHZEFNMheIhY52I6_KNBZ21rCfsV6uHdXFuztw51mca5ioLklRgYgbrJMGgPk8CMA=="
)


class TestDatabase(TestCase):
	@patch.object(Database, "save", Mock())
	def test_check_secret_label_whitespace(self) -> None:
		database = Database(SAMPLE_PASSWORD, SAMPLE_FILENAME)
		with self.assertRaises(ValueError):
			database._check_secret_label_whitespace(" ")
		with self.assertRaises(ValueError):
			database._check_secret_label_whitespace(" invalid ")
		with self.assertRaises(ValueError):
			database._check_secret_label_whitespace("invalid\twhitespace")
		database._check_secret_label_whitespace("this is a valid string")

	@patch.object(Database, "save", Mock())
	def test_check_secret_key_whitespace(self) -> None:
		database = Database(SAMPLE_PASSWORD, SAMPLE_FILENAME)
		with self.assertRaises(ValueError):
			database._check_secret_key_whitespace("invalid whitespace")
		database._check_secret_key_whitespace("valid_string")

	def test_validate_json(self) -> None:
		with ExitStack() as cm:
			mock_schema_path = cm.enter_context(patch.object(Database, "schema_path", PropertyMock()))
			mock_schema_path.return_value = os.path.join(DATA_DIRECTORY, "database.schema")
			database = Database(SAMPLE_PASSWORD, SAMPLE_FILENAME)
			self.assertEqual(len(database), 0)
			database["schema_version"] = 1
			# Validation expects list, not tuple.
			database.secrets.append(["test_label", "test_key"])  # type: ignore[arg-type]
			database._validate_json()
			cm.enter_context(self.assertRaises(ValidationError))
			# Invalid secret.
			database.secrets.append([1])  # type: ignore[arg-type]
			database._validate_json()

	@patch("authenticator.database.os")
	def test_load_when_location_does_not_exist(self, mock_os: Mock) -> None:
		mock_os.path.exists.return_value = False
		mock_os.path.isdir.return_value = False
		database = Database(SAMPLE_PASSWORD, SAMPLE_FILENAME)
		# Default values are set when location does not exist.
		self.assertEqual(database.name, SAMPLE_FILENAME)
		mock_os.path.join.side_effect = os.path.join
		self.assertEqual(database.file_path, os.path.join(DATA_DIRECTORY, f"{database.name}.otp"))
		self.assertEqual(database.schema_path, os.path.join(DATA_DIRECTORY, f"{database.name}.schema"))
		self.assertEqual(len(database), 0)
		self.assertEqual(len(database.secrets), 0)
		self.assertEqual(len(database), 1)  # Empty secrets list was added by the call to database.secrets.

	@patch("authenticator.database.os")
	def test_load_when_location_is_a_directory(self, mock_os: Mock) -> None:
		mock_os.path.exists.return_value = True
		mock_os.path.isdir.return_value = True
		with self.assertRaises(DatabaseError):
			Database(SAMPLE_PASSWORD, SAMPLE_FILENAME)

	@patch("authenticator.database.os")
	def test_load_when_corrupt_data(self, mock_os: Mock) -> None:
		mock_os.path.exists.return_value = True
		mock_os.path.isdir.return_value = False
		with ExitStack() as cm:
			cm.enter_context(patch("authenticator.database.open", mock_open(read_data=b"invalid")))
			cm.enter_context(self.assertRaises(DatabaseError))
			Database(SAMPLE_PASSWORD, SAMPLE_FILENAME)

	@patch("authenticator.database.os")
	def test_load_when_valid_data(self, mock_os: Mock) -> None:
		mock_os.path.exists.return_value = True
		mock_os.path.isdir.return_value = False
		with ExitStack() as cm:
			cm.enter_context(patch("authenticator.database.open", mock_open(read_data=SAMPLE_DATA)))
			mock_validate_json = cm.enter_context(patch.object(Database, "_validate_json"))
			database = Database(SAMPLE_PASSWORD, SAMPLE_FILENAME)
			mock_validate_json.assert_called_once()
			self.assertEqual(len(database), 1)
			self.assertIn("secrets", database)
			self.assertEqual(len(database.secrets), 1)
			self.assertIn(("test_label", "test_key"), database.secrets)

	@patch("authenticator.database.os")
	def test_load_when_valid_data_needs_password_rehash(self, mock_os: Mock) -> None:
		mock_os.path.exists.return_value = True
		mock_os.path.isdir.return_value = False
		with ExitStack() as cm:
			cm.enter_context(patch("authenticator.database.open", mock_open(read_data=SAMPLE_DATA)))
			cm.enter_context(patch.object(Database, "_validate_json"))
			mock_decrypt = cm.enter_context(patch("authenticator.database.decrypt"))
			mock_save = cm.enter_context(patch.object(Database, "save"))
			checksum, pw_hash = str(SAMPLE_DATA, "utf-8").splitlines()[:2]
			enc_data: bytes = SAMPLE_DATA.splitlines()[2]
			dec_data, _ = decrypt(SAMPLE_PASSWORD, pw_hash, enc_data)
			mock_decrypt.return_value = (dec_data, True)
			Database(SAMPLE_PASSWORD, SAMPLE_FILENAME)
			mock_save.assert_called_once_with(SAMPLE_PASSWORD)

	def test_save_when_invalid_password(self) -> None:
		with patch("authenticator.database.open", mock_open()) as mopen:
			database = Database(SAMPLE_PASSWORD, SAMPLE_FILENAME)
			database.secrets.append(Secret("test_label", "test_key"))
			with self.assertRaises(ValueError):
				database.save(" ")
			with self.assertRaises(ValueError):
				database.save(" invalid ")
			with self.assertRaises(ValueError):
				database.save("invalid\tpassword")
			mopen.assert_not_called()

	@patch("authenticator.database.os")
	def test_save_when_valid_database(self, mock_os: Mock) -> None:
		mock_os.path.isdir.return_value = False
		saved_data: bytearray = bytearray()
		# Test saving a database.
		with patch("authenticator.database.open", mock_open()) as mopen:
			mopen.return_value.write.side_effect = lambda d: saved_data.extend(d)
			mock_os.path.exists.return_value = False
			database = Database(SAMPLE_PASSWORD, SAMPLE_FILENAME)
			database.secrets.append(Secret("test_label", "test_key"))
			database.save(SAMPLE_PASSWORD)
			mopen.assert_called_once_with(database.file_path, "wb")
		# Test loading the saved data succeeds.
		with ExitStack() as cm:
			cm.enter_context(patch("authenticator.database.open", mock_open(read_data=bytes(saved_data))))
			cm.enter_context(patch.object(Database, "_validate_json"))
			mock_os.path.exists.return_value = True
			database = Database(SAMPLE_PASSWORD, SAMPLE_FILENAME)
			self.assertEqual(len(database), 1)
			self.assertIn("secrets", database)
			self.assertEqual(len(database.secrets), 1)
			self.assertIn(("test_label", "test_key"), database.secrets)

	def test_add_secret_when_valid_data(self) -> None:
		with patch.object(Database, "save") as mock_save:
			database = Database(SAMPLE_PASSWORD, SAMPLE_FILENAME)
			database.add_secret(SAMPLE_PASSWORD, "test_label", "test_key")
			mock_save.assert_called_once_with(SAMPLE_PASSWORD)

	def test_add_secret_when_label_already_exists(self) -> None:
		with ExitStack() as cm:
			mock_save = cm.enter_context(patch.object(Database, "save"))
			database = Database(SAMPLE_PASSWORD, SAMPLE_FILENAME)
			database.add_secret(SAMPLE_PASSWORD, "test_label", "test_key")
			mock_save.assert_called_once_with(SAMPLE_PASSWORD)
			mock_save.reset_mock()
			cm.enter_context(self.assertRaises(ValueError))
			database.add_secret(SAMPLE_PASSWORD, "test_label", "test_key")
			mock_save.assert_not_called()

	def test_search_secrets_when_empty_search_text(self) -> None:
		database = Database(SAMPLE_PASSWORD, SAMPLE_FILENAME)
		database.secrets.append(Secret("alpha", "apple"))
		database.secrets.append(Secret("beta", "banana"))
		database.secrets.append(Secret("Charley", "cantaloupe"))
		# Empty search text should always return immediately.
		self.assertEqual(len(database.search_secrets("", exact_match=True)), 0)

	def test_search_secrets_when_exact_match_and_results_found(self) -> None:
		database = Database(SAMPLE_PASSWORD, SAMPLE_FILENAME)
		database.secrets.append(Secret("alpha", "apple"))
		database.secrets.append(Secret("beta", "banana"))
		database.secrets.append(Secret("Charley", "cantaloupe"))
		self.assertEqual(len(database.search_secrets("Charley", exact_match=True)), 1)

	def test_search_secrets_when_exact_match_and_results_not_found(self) -> None:
		database = Database(SAMPLE_PASSWORD, SAMPLE_FILENAME)
		database.secrets.append(Secret("alpha", "apple"))
		database.secrets.append(Secret("beta", "banana"))
		database.secrets.append(Secret("Charley", "cantaloupe"))
		self.assertEqual(len(database.search_secrets("tango", exact_match=True)), 0)

	def test_search_secrets_when_regex_matches_search_text(self) -> None:
		database = Database(SAMPLE_PASSWORD, SAMPLE_FILENAME)
		database.secrets.append(Secret("alpha", "apple"))
		database.secrets.append(Secret("beta", "banana"))
		database.secrets.append(Secret("Charley", "cantaloupe"))
		self.assertEqual(len(database.search_secrets("a$", exact_match=False)), 2)

	def test_search_secrets_when_regex_does_not_match_search_text(self) -> None:
		database = Database(SAMPLE_PASSWORD, SAMPLE_FILENAME)
		database.secrets.append(Secret("alpha", "apple"))
		database.secrets.append(Secret("beta", "banana"))
		database.secrets.append(Secret("Charley", "cantaloupe"))
		self.assertEqual(len(database.search_secrets("tango", exact_match=False)), 0)

	def test_delete_secret(self) -> None:
		with patch.object(Database, "save") as mock_save:
			database = Database(SAMPLE_PASSWORD, SAMPLE_FILENAME)
			self.assertEqual(len(database.secrets), 0)
			database.secrets.append(Secret("alpha", "apple"))
			database.secrets.append(Secret("beta", "banana"))
			database.secrets.append(Secret("Charley", "cantaloupe"))
			self.assertEqual(len(database.secrets), 3)
			database.delete_secret(SAMPLE_PASSWORD, "beta")
			self.assertEqual(len(database.secrets), 2)
			mock_save.assert_called_once_with(SAMPLE_PASSWORD)

	def test_magic_methods(self) -> None:
		database = Database(SAMPLE_PASSWORD, SAMPLE_FILENAME)
		database["alpha"] = "apple"  # __setitem__
		self.assertEqual(database["alpha"], "apple")  # __getitem__
		self.assertEqual(dict(database), database._database)  # __iter__
		self.assertEqual(len(database), 1)  # __len__
		del database["alpha"]  # __delitem__
