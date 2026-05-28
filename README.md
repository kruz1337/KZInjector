# KZInjector
### This branch has a DLL Injector which uses native api calls for windows. It's fully open source project.

![](https://img.shields.io/badge/license-GNU-green?style=plastic) ![](https://img.shields.io/badge/compiler-GCC-yellow?style=plastic) ![](https://img.shields.io/badge/language-c++-e76089?style=plastic) ![](https://img.shields.io/badge/arch-x64%20%7C%20x86-d9654f?style=plastic) ![](https://img.shields.io/badge/config-Debug%20%7C%20Release-c0c0c0?style=plastic) ![](https://img.shields.io/badge/platform-Windows-blue?style=plastic)

![](https://raw.githubusercontent.com/kruz1337/KZInjector/main/thumbnail.png)

- Tested on Windows 10 and Windows 11.
- Supports x64 and x86 architery.
- Debug & Release.
- This version of ManualMap injection method, the file is loaded into the injector's memory, and IAT and RT are fixed within that memory.

### Injection Types
- LoadLibrary
- ManualMap

### Execution Methods
- CreateThread
- ThreadHijack

### Usage with Arguments
```KZInjector.exe [PID/PROCESS NAME] [DLL PATH] [Options]```

Options:
```
-i --injection LoadLibrary / ManualMap
-e --execution CreateThread / ThreadHijack
```
