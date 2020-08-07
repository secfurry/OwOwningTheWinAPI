// +build windows

// Build only for Windows
//
// Copyright (C) 2020 secfurry
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.
//
// MessageBox Windows API Function Test
//   Displays a simple MessageBox.
package main

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

func main() {
	var (
		// Link and load user32.dll
		dllUser32 = windows.NewLazySystemDLL("user32.dll")

		// Load the "MessageBox" function from user32.dll that we need by name.
		funcMessageBox = dllUser32.NewProc("MessageBoxW")
	)

	// Convert a string to a UTF16 string pointer
	msgText, _ := windows.UTF16PtrFromString("Message Box Text")

	// Convert a string to a UTF16 string pointer
	msgCaption, _ := windows.UTF16PtrFromString("Message Box Caption")

	// Call the function!
	funcMessageBox.Call(
		0,                                   // Parent window HANDLE, set to NULL
		uintptr(unsafe.Pointer(msgText)),    // Pointer to the text UTF16 pointer string
		uintptr(unsafe.Pointer(msgCaption)), // Pointer to the caption UTF16 pointer string
		0,                                   // MessageBox type
	)
}
