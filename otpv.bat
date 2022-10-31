@echo off


:: In order to define functions before main, call main here and exit.
pushd "%~dp0"
call :func_main %*
popd
exit /b %ERRORLEVEL%


:func_install_dependencies
	:: Installs the package dependencies into a new virtual environment.
	::
	:: Returns:
	::	0 if success, non-zero otherwise.
	:: -----
	:: Use python.exe if found to create the venv, otherwise fall back to Python Launcher.
	where /q python.exe
	if ERRORLEVEL 1 (
		:: python.exe was not found. Use Python launcher if available, otherwise error out.
		where /q py.exe || echo Error: unable to find 'python.exe' or 'py.exe' in path. && exit /b 1
		echo Using Python Launcher.
		py -m venv .venv
	) else if ERRORLEVEL 0 (
		:: python.exe was found. Use it.
		echo Found Python interpreter.
		python -m venv .venv
	)
	echo Activating the virtual environment.
	call .venv\scripts\activate.bat
	echo Installing Poetry.
	python -m pip install --progress-bar off --upgrade --require-hashes --requirement requirements-poetry.txt
	echo installing dependencies.
	python -m poetry install --no-ansi
	echo Installing pre-commit hooks.
	python -m pre_commit install -t pre-commit
	python -m pre_commit install -t pre-push
	call .venv\scripts\deactivate.bat
	exit /b 0


:func_run_python_script
	:: Runs Python using a new cmd instance to prevent arguments being put on the window title.
	::
	:: Args:
	::	%*: Command line arguments.
	::
	:: Returns:
	::	0 if success, non-zero otherwise.
	:: -----
	cmd /c "python -m otp_vault %*"
	exit /b %ERRORLEVEL%


:func_main
	:: Executes the main body of the script.
	::
	:: Args:
	::	%*: Command line arguments.
	::
	:: Returns:
	::	0 if success, non-zero otherwise.
	:: -----
	:: Install the program if virtual environment not found.
	if not exist .venv (
		choice /c "yn" /m "Virtual environment not found. Would you like to create a new one
		if ERRORLEVEL 2 (
			echo Unable to proceed without a virtual environment.
		) else if ERRORLEVEL 1 (
			echo Creating a new virtual environment and installing dependencies.
			:: If error, return immediately.
			call :func_install_dependencies || exit /b %ERRORLEVEL%
			echo Virtual environment and dependencies installed.
			echo Run this script again to use the program.
		)
		exit /b 0
	) else if defined VIRTUAL_ENV (
		:: User is running inside of an activated virtual environment.
		call :func_run_python_script %*
	) else (
		:: Virtual environment exists, but it is not currently activated.
		call .venv\scripts\activate.bat
		call :func_run_python_script %*
		call .venv\scripts\deactivate.bat
	)
	exit /b %ERRORLEVEL%
