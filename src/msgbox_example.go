// +build windows
// ONLY build for Windows platforms
//
// Example Golang Windows API function test
//
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
