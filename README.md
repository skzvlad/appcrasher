# AppCrasher 

AppCrasher is simple console Windows application to kill any process by crash. AppCrasher kills the selected process by injecting its own DLL into the selected process and running the "bad" function from the injected DLL (work with non-valid pointer). The project is Microsoft Visual Studio 2022 based (C++ native) without any dependencies.

The main solution for AppCrasher creates two modules: an executable file (AppCrasher_x64.exe or AppCrasher_x86.exe) and a DLL file (AppCrasherInjector_x64.dll or AppCrasherInjector_x86.dll).

## Features
- Kill (by crash) the process by PID
- Kill (by crash) the process by process name
- Kill (by crash) the process by its executable path

Multiple processes can be started with the same name. In this case, only one first process will be killed by name.<br/>Multiple processes can be started with the same executable path. In this case, only one first process will be killed by path.

Please use "AppCrasher_x64.exe" (64-bit version of AppCrasher) to crash 64-bit process.<br/>
Please use "AppCrasher_x86.exe" (32-bit version of AppCrasher) to crash 32-bit process.

The "AppCrasherInjector_x64.dll" should be in the folder with "AppCrasher_x64.exe" file!<br/>
The "AppCrasherInjector_x86.dll" should be in the folder with "AppCrasher_x86.exe" file!

Please run "AppCrasher_x64.exe" or "AppCrasher_x86.exe" under admin!

AppCrasher can be used to test your "Crash Handler" solutions. To change the crash algorithms, please update the "threafFunction" function in the file "appcrasher/AppCrasherInjector/dllmain.cpp". AppCrasher might not work if the application you want to crash has a filter/protection against loading external DLL libraries (intercepting the call the "LoadLibrary" API functions).

## Command line interface
```cmd
    --help
    --pid <Process ID to crash a running process by its PID>
    --pname <Process name to crash a running process by its name>
    --ppath <Full process path to crash a running process by its path>

Examples:
    AppCrasher_x64.exe --help
    AppCrasher_x64.exe --pid 12345
    AppCrasher_x64.exe --pname MyApplication.exe
    AppCrasher_x64.exe --ppath "d:\tools\MyApplication.exe"
```
