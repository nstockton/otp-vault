# OTP Vault

A CLI-based [OTP][] [authenticator][] app that can generate [HOTP,][HOTP] [TOTP,][TOTP], and [MOTP][] tokens.
The keys for generating the OTP tokens are password-protected using the [Fernet][] recipe
from the Cryptography package for Python, with [Argon2][] as the key derivation function.

## License And Credits

OTP Vault was created by [Nick Stockton,][My GitHub] and is licensed under the terms of the [Mozilla Public License, version 2.0.][MPL2]

## Running From Source

Install the [Python][] interpreter and make sure it's in your path before running this package.

### Windows-specific Instructions

The *otpv.bat* script in the root directory of this repository can be used to install the necessary virtual environment and dependencies for the program.
To install the virtual environment and dependencies, run `otpv.bat` without any arguments. The script will prompt you to install if it does not find an existing virtual environment.
After the install is complete, you can run `otpv.bat` again with supported arguments to run the program.

### Linux-specific Instructions

Execute the following commands from the root directory of this repository to install the module dependencies.
```
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade --require-hashes --requirement requirements-uv.txt
uv sync
pre-commit install -t pre-commit
pre-commit install -t pre-push
```
After that, you can run the program by executing the following commands.
```
source .venv/bin/activate
otpv <arguments>
```


## OTP Vault Usage

```
otpv <PASSWORD> <OPTIONS>
```

### Options

- `--change-password <NEW_PASSWORD>`: changes an existing password.
- `-a <LABEL> <KEY> | --add <LABEL> <KEY>`: adds a secret to the secrets database.
    * `[-t <TYPE> | --type <TYPE>]`: specifies the algorithm to use when adding a secret ("totp" is default). Valid types are "hotp", "motp", and "totp".
    * `[-l <LENGTH> | --length <LENGTH>]`: specifies the desired token length when adding a secret (6 is default). Valid length is in range 6-10.
    * `[-i <VALUE> | --initial-input <VALUE>]`: specifies the pin / counter / start-time used as the moving factor when adding a secret ('0' is default).
- `-s <TEXT> | --search <TEXT>`: searches for a secret by label.
    * `[-c <RESULT_ITEM> | --copy <RESULT_ITEM>]`: copies the token of a search result to the clipboard. If the program does not support clipboard access on the current platform, the token will be printed to the screen instead.
    * `[-d <RESULT_ITEM> | --delete <RESULT_ITEM>]`: deletes a search result from the secrets database.
    * `[-u <RESULT_ITEM> <NEW_LABEL> | --update <RESULT_ITEM> <NEW_LABEL>]`: updates a search result with a new label.
- `-h | --help`: shows program help.
- `-v | --version`: shows program version.


[OTP]: https://en.wikipedia.org/wiki/One-time_password (OTP Wikipedia Page)
[authenticator]: https://en.wikipedia.org/wiki/Authenticator (Authenticator Wikipedia Page)
[HOTP]: https://en.wikipedia.org/wiki/HMAC-based_One-time_Password_algorithm (HOTP Wikipedia Page)
[TOTP]: https://en.wikipedia.org/wiki/Time-based_One-time_Password_algorithm (TOTP Wikipedia Page)
[MOTP]: https://motp.sourceforge.net (Mobile-OTP Main Page)
[Fernet]: https://cryptography.io/en/latest/fernet (Fernet Main Page)
[Argon2]: https://en.wikipedia.org/wiki/Argon2 (Argon2 Wikipedia Page)
[MPL2]: https://www.mozilla.org/en-US/MPL/2.0 (MPL2 License Page)
[My GitHub]: https://github.com/nstockton (My Profile On GitHub)
[Python]: https://python.org (Python Main Page)
