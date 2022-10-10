# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.


# Future Modules:
from __future__ import annotations

# Built-in Modules:
import sys
from collections.abc import Sequence
from ctypes import WinDLL, WinError, c_size_t, create_string_buffer, get_last_error, memmove
from ctypes.wintypes import BOOL, HANDLE, HGLOBAL, HWND, LPVOID, UINT
from typing import Any, Optional


CF_TEXT = 1
CF_UNICODETEXT = 13
GMEM_MOVEABLE = 0x0002
GMEM_ZEROINIT = 0x0040


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


def _errcheck(result: Any, func: Any, args: Sequence[Any]) -> Any:
	if not result:
		raise WinError(get_last_error())


user32 = WinDLL("user32", use_last_error=True)
kernel32 = WinDLL("kernel32", use_last_error=True)

OpenClipboard = _decl(user32.OpenClipboard, BOOL, (HWND,), _errcheck)
CloseClipboard = _decl(user32.CloseClipboard, BOOL)
EmptyClipboard = _decl(user32.EmptyClipboard, BOOL)
GetClipboardData = _decl(user32.GetClipboardData, HANDLE, (UINT,))
SetClipboardData = _decl(user32.SetClipboardData, HANDLE, (UINT, HANDLE))
GlobalLock = _decl(kernel32.GlobalLock, LPVOID, (HGLOBAL,))
GlobalUnlock = _decl(kernel32.GlobalUnlock, BOOL, (HGLOBAL,))
GlobalAlloc = _decl(kernel32.GlobalAlloc, HGLOBAL, (UINT, c_size_t))
GlobalSize = _decl(kernel32.GlobalSize, c_size_t, (HGLOBAL,))


def get_clipboard() -> str:
	"""
	Gets the contents of the clipboard.

	Returns:
		The clipboard contents.
	"""
	if sys.platform != "win32":
		# Currently only Windows is supported.
		return ""
	text: str = ""
	OpenClipboard(None)
	try:
		handle = GetClipboardData(CF_UNICODETEXT)
		contents = GlobalLock(handle)
		size = GlobalSize(handle)
		if contents and size:
			raw_data = create_string_buffer(size)
			memmove(raw_data, contents, size)
			text = str(raw_data.raw, "utf-16le").rstrip("\0")
		GlobalUnlock(handle)
	finally:
		CloseClipboard()
	return text


def set_clipboard(text: str) -> bool:
	"""
	Copies text into the clipboard.

	Args:
		text: The text to copy to the clipboard.
	"""
	if sys.platform != "win32":
		# Currently only Windows is supported.
		return False
	data: bytes = bytes(text, "utf-16le")
	OpenClipboard(None)
	try:
		EmptyClipboard()
		handle = GlobalAlloc(GMEM_MOVEABLE | GMEM_ZEROINIT, len(data) + 2)
		contents = GlobalLock(handle)
		memmove(contents, data, len(data))
		GlobalUnlock(handle)
		SetClipboardData(CF_UNICODETEXT, handle)
	except Exception:
		return False
	finally:
		CloseClipboard()
	return True
