# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.


# Future Modules:
from __future__ import annotations

# Built-in Modules:
import ctypes
import sys
from typing import Any, Optional, Sequence


if sys.platform == "win32":
	from ctypes import wintypes


def _decl(
	func: Any,
	restype: Optional[Any] = None,
	argtypes: Optional[Sequence[Any]] = None,
	errcheck: Optional[Any] = None,
) -> Any:
	if restype is not None:
		func.restype = restype
	if argtypes is not None:
		func.argtypes = argtypes
	if errcheck is not None:
		func.errcheck = errcheck
	return func


def _errcheck_windows(result: Any, func: Any, args: Sequence[Any]) -> Any:
	if sys.platform == "win32":
		if not result:
			raise ctypes.WinError(ctypes.get_last_error())


if sys.platform == "win32":
	# Windows-specific constants and libraries.
	CF_TEXT = 1
	CF_UNICODETEXT = 13
	GMEM_MOVEABLE = 0x0002
	GMEM_ZEROINIT = 0x0040
	user32 = ctypes.WinDLL("user32", use_last_error=True)
	kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
	OpenClipboard = _decl(user32.OpenClipboard, wintypes.BOOL, (wintypes.HWND,), _errcheck_windows)
	CloseClipboard = _decl(user32.CloseClipboard, wintypes.BOOL)
	EmptyClipboard = _decl(user32.EmptyClipboard, wintypes.BOOL)
	GetClipboardData = _decl(user32.GetClipboardData, wintypes.HANDLE, (wintypes.UINT,))
	SetClipboardData = _decl(user32.SetClipboardData, wintypes.HANDLE, (wintypes.UINT, wintypes.HANDLE))
	GlobalLock = _decl(kernel32.GlobalLock, wintypes.LPVOID, (wintypes.HGLOBAL,))
	GlobalUnlock = _decl(kernel32.GlobalUnlock, wintypes.BOOL, (wintypes.HGLOBAL,))
	GlobalAlloc = _decl(kernel32.GlobalAlloc, wintypes.HGLOBAL, (wintypes.UINT, ctypes.c_size_t))
	GlobalSize = _decl(kernel32.GlobalSize, ctypes.c_size_t, (wintypes.HGLOBAL,))


def _get_clipboard_windows() -> str:
	"""
	Gets the contents of the clipboard on Windows.

	Returns:
		The clipboard contents.
	"""
	if sys.platform == "win32":
		text: str = ""
		OpenClipboard(None)
		try:
			handle = GetClipboardData(CF_UNICODETEXT)
			contents = GlobalLock(handle)
			size = GlobalSize(handle)
			if contents and size:
				raw_data = ctypes.create_string_buffer(size)
				ctypes.memmove(raw_data, contents, size)
				text = str(raw_data.raw, "utf-16le").rstrip("\0")
			GlobalUnlock(handle)
		finally:
			CloseClipboard()
		return text
	else:
		return ""


def _set_clipboard_windows(text: str) -> bool:
	"""
	Copies text into the clipboard on Windows.

	Args:
		text: The text to copy to the clipboard.
	"""
	if sys.platform == "win32":
		data: bytes = bytes(text, "utf-16le")
		OpenClipboard(None)
		try:
			EmptyClipboard()
			handle = GlobalAlloc(GMEM_MOVEABLE | GMEM_ZEROINIT, len(data) + 2)
			contents = GlobalLock(handle)
			ctypes.memmove(contents, data, len(data))
			GlobalUnlock(handle)
			SetClipboardData(CF_UNICODETEXT, handle)
		except Exception:
			return False
		finally:
			CloseClipboard()
		return True
	else:
		return False


def get_clipboard() -> str:
	"""
	Gets the contents of the clipboard.

	Returns:
		The clipboard contents.
	"""
	if sys.platform == "win32":
		return _get_clipboard_windows()
	else:
		return ""


def set_clipboard(text: str) -> bool:
	"""
	Copies text into the clipboard.

	Args:
		text: The text to copy to the clipboard.
	"""
	if sys.platform == "win32":
		return _set_clipboard_windows(text)
	else:
		return False
