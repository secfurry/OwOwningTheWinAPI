# OwOwning with the Windows API

I will add the video link here when it's saved

[PowerPoint Here](https://dij.sh/owo/Slides.pdf)

**OwOwning with the Windows API** is a presentation given during the [DEFCON Furs 2020](https://2020.dcfurs.com) virtual conference.

During the presentation, I (secfurry) explore the methods and function calls used to spoof parent process relationships in Windows and inject shellcode into Windows applications.
I cover many undocumented or lesser known functions and provide code (saved here) to experiment and modify as you see fit.

I can be reached out on Twitter at [@secfurry](https://twitter.com/secfurry).

PS: The code used in this presentation was given to one of my friends [@iDigitalFlame](https://twitter.com/iDigitalFlame) to use in development for his [malware framework XMT](https://github.com/iDigitalFlame/xmt), go check it out if you're interested in more cool stuff like this.

## Links

- [Zw and Nt Prefixes](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/what-does-the-zw-prefix-mean-)
- [PEB Block Overwriting](https://blog.xpnsec.com/how-to-argue-like-cobalt-strike/)
- [StartupInfoEx](https://docs.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-startupinfoexa)
- [Detecting Parent Process Spoofing](https://blog.f-secure.com/detecting-parent-pid-spoofing/)
    [Git Repo](https://github.com/countercept/ppid-spoofing)
- [Preventing Parent Process Spoofing](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute#remarks)
- [Another Writeup on Parent Spoofing](https://blog.didierstevens.com/2009/11/22/quickpost-selectmyparent-or-playing-with-the-windows-process-tree/)

### Windows API Function Reference

- [OpenProcess](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess)
- [InitializeProcThreadAttributeList](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-initializeprocthreadattributelist)
- [UpdateProcThreadAttribute](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute)
- [CreateProcessW](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessw)
- [WaitForSingleObject](https://docs.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitforsingleobject)
- [DuplicateHandle](https://docs.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-duplicatehandle)
- [LookupPrivilegeValue](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-lookupprivilegevaluea)
- [OpenProcessToken](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocesstoken)
- [AdjustTokenPrivileges](https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-adjusttokenprivileges)
- [NtAllocateVirtualMemory](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntallocatevirtualmemory)
- [NtWriteVirtualMemory](http://www.codewarrior.cn/ntdoc/winnt/mm/NtWriteVirtualMemory.htm)
- [NtCreateThreadEx](https://securityxploded.com/ntcreatethreadex.php)

Updated on *08/06/2020*
