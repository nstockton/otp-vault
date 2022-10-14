@echo off

rem Change the working directory to the location of this batch script.
pushd "%~dp0"

rem Install the program if virtual environment not found.
if not exist .venv (
	echo Virtual environment not found. Creating a new one.
	where /q python.exe
	if ERRORLEVEL 1 (
		where /q py.exe || echo Error: unable to find python.exe or py.exe in path. && exit /b
		echo Found Python Launcher.
		py -m venv .venv
	) else (
		echo Found Python interpreter.
		python -m venv .venv
	)
	echo Activating the virtual environment.
	call .venv\scripts\activate.bat
	echo Installing Poetry.
	python -m pip install --upgrade "poetry==1.1.13"
	echo installing dependencies.
	python -m poetry install --no-ansi
	echo Installing pre-commit hooks.
	python -m pre_commit install -t pre-commit
	python -m pre_commit install -t pre-push
	call .venv\scripts\deactivate.bat
	echo Virtual environment and dependencies installed.
	echo Run this script again to use the program.
	exit /b
)

rem Run the program.
if defined VIRTUAL_ENV (
	rem User is running inside of an activated virtual environment.
	python -m otp_vault %*
) else (
	rem User is not running inside of an activated virtual environment.
	call .venv\scripts\activate.bat
	python -m otp_vault %*
	call .venv\scripts\deactivate.bat
)

rem Reset the working directory.
popd
