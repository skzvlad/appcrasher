/*
 * InjectLib.h
 * Copyright (C) 2011-2023 Vladimir V. Skuzovatkin
 *
 */

#ifndef LOKIBIT_COMMON_SYS_WINDOWS_INJECT_LIB_H
#define LOKIBIT_COMMON_SYS_WINDOWS_INJECT_LIB_H

#include <string>

#include <windows.h>

#include "RemoteProcessInfo.h"

namespace lokibit
{
    namespace sys
    {
        static DWORD injectLib(DWORD dwProcessId, const wchar_t* szLibFile)
        {
            if (!szLibFile)
                return ERROR_INVALID_PARAMETER;
            if (wcslen(szLibFile) == 0)
                return ERROR_INVALID_PARAMETER;

            DWORD res = ERROR_SUCCESS;

            HANDLE hProcess = NULL;
            HANDLE hThread = NULL;
            PWSTR pszLibFileRemote = NULL;

            __try
            {
                const DWORD dwDesiredAccess =
                    PROCESS_QUERY_INFORMATION |
                    PROCESS_CREATE_THREAD |
                    PROCESS_VM_OPERATION |
                    PROCESS_VM_READ |
                    PROCESS_VM_WRITE;

                // Get a handle for the target process.
                hProcess = ::OpenProcess(dwDesiredAccess, FALSE, dwProcessId);
                if (hProcess == NULL)
                {
                    res = ::GetLastError();
                    __leave;
                }

                // Try to set 'SeDebugPrivilege' privilege
                {
                    HANDLE hToken = NULL;
                    TOKEN_PRIVILEGES tp = {0};

                    tp.PrivilegeCount = 1;
                    LookupPrivilegeValueW(NULL, L"SeDebugPrivilege", &tp.Privileges[0].Luid);
                    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
                    if (::OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES, &hToken))
                    {
                        ::AdjustTokenPrivileges(hToken, FALSE, &tp, NULL, NULL, NULL);
                        ::CloseHandle(hToken);
                    }
                }

                // Calculate the number of bytes needed for the DLL's pathname
                const size_t nLibFileLen = (1 + wcslen(szLibFile)) * sizeof(wchar_t);

                // Allocate space in the remote process for the pathname
                pszLibFileRemote = (PWSTR)::VirtualAllocEx(hProcess, NULL, nLibFileLen, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
                if (pszLibFileRemote == NULL)
                {
                    res = ::GetLastError();
                    __leave;
                }

                // Copy the DLL's pathname to the remote process' address space
                SIZE_T nNumberOfBytesWritten = 0;
                if (!::WriteProcessMemory(hProcess, pszLibFileRemote, (PVOID) szLibFile, (SIZE_T) nLibFileLen, &nNumberOfBytesWritten))
                {
                    res = ::GetLastError();
                    __leave;
                }

                HMODULE hKernel32 = NULL;
                res = lokibit::sys::getRemoteModuleHandle(hProcess, "Kernel32.dll", &hKernel32);
                if (res == ERROR_SUCCESS)
                {
                    FARPROC procAddress = NULL;
                    res = lokibit::sys::getRemoteProcAddress(hProcess, hKernel32, "LoadLibraryW", &procAddress);
                    if (res == ERROR_SUCCESS)
                    {
                        PTHREAD_START_ROUTINE pfnThreadRtn = (PTHREAD_START_ROUTINE)procAddress;

                        // Create a remote thread that calls LoadLibraryW(DLLPathname)
                        hThread = ::CreateRemoteThread(hProcess, NULL, 0, pfnThreadRtn, pszLibFileRemote, 0, NULL);
                        if (hThread == NULL)
                        {
                            res = ::GetLastError();
                            __leave;
                        }

                        // Wait for the remote thread to terminate
                        ::WaitForSingleObject(hThread, INFINITE);

                        // Check the injection
                        bool bExists = false;
                        res = sys::existsRemoteModule(hProcess, szLibFile, &bExists);
                        if (res == ERROR_SUCCESS)
                        {
                            if (!bExists)
                            {
                                res = ERROR_MOD_NOT_FOUND;
                            }
                        }
                    }
                }
            }
            __finally
            {
                if (pszLibFileRemote != NULL)
                    ::VirtualFreeEx(hProcess, pszLibFileRemote, 0, MEM_RELEASE);

                if (hThread != NULL)
                    ::CloseHandle(hThread);

                if (hProcess != NULL)
                    ::CloseHandle(hProcess);
            }

            return res;
        }
    }
}

#endif // LOKIBIT_COMMON_SYS_WINDOWS_INJECT_LIB_H
