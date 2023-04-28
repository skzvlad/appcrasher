/*
 * RemoteProcessInfo.h
 * Copyright (C) 2011-2023 Vladimir V. Skuzovatkin
 *
 */

#ifndef LOKIBIT_COMMON_SYS_WINDOWS_REMOTE_PROCESS_INFO_H
#define LOKIBIT_COMMON_SYS_WINDOWS_REMOTE_PROCESS_INFO_H

#include <string>

#include <windows.h>
#include <psapi.h>

namespace lokibit
{
    namespace sys
    {
        static DWORD existsRemoteModule(
            HANDLE hProcess,
            const char* szModuleName,
            bool* pbExists)
        {
            if (!hProcess)
                return ERROR_INVALID_PARAMETER;
            if (!szModuleName)
                return ERROR_INVALID_PARAMETER;
            if (strlen(szModuleName) == 0)
                return ERROR_INVALID_PARAMETER;
            if (!pbExists)
                return ERROR_INVALID_PARAMETER;

            DWORD dwRes = ERROR_SUCCESS;

            HMODULE* pModuleArray = NULL;

            do
            {
                DWORD dwModuleArraySize = 300;
                pModuleArray = new HMODULE[dwModuleArraySize];
                DWORD dwNumModules = dwModuleArraySize;
                if (!::EnumProcessModulesEx(hProcess, pModuleArray,
                    dwModuleArraySize * sizeof(HMODULE), &dwNumModules, LIST_MODULES_ALL))
                {
                    dwRes = ::GetLastError();
                    break;
                }

                dwNumModules /= sizeof(HMODULE);

                if (dwNumModules > dwModuleArraySize)
                {
                    delete [] pModuleArray;
                    pModuleArray = NULL;
                    pModuleArray = new HMODULE[dwNumModules];

                    dwModuleArraySize = dwNumModules;

                    if (!::EnumProcessModulesEx(hProcess, pModuleArray,
                        dwModuleArraySize * sizeof(HMODULE), &dwNumModules, LIST_MODULES_ALL))
                    {
                        dwRes = ::GetLastError();
                        break;
                    }

                    dwNumModules /= sizeof(HMODULE);
                }

                char szCurrentModuleName[MAX_PATH] = { 0 };

                std::string strLibName;
                {
                    char szDrive[_MAX_DRIVE] = { 0 };
                    char szDir[_MAX_DIR] = { 0 };
                    char szFile[_MAX_FNAME] = { 0 };
                    char szExt[_MAX_EXT] = { 0 };

                    if (_splitpath_s(szModuleName,
                        szDrive, _MAX_DRIVE,
                        szDir, _MAX_DIR,
                        szFile, _MAX_FNAME,
                        szExt, _MAX_EXT) == 0)
                    {
                        if (szFile) {
                            strLibName.append(szFile);
                            if (szExt) {
                                if (strlen(szExt) > 0) {
                                    if (szExt[0] != '.')
                                        strLibName.append(".");
                                    strLibName.append(szExt);
                                }
                            }
                        }
                    }
                }

                for (DWORD i = 0; i <= dwNumModules; ++i)
                {
                    if (::GetModuleBaseNameA(hProcess, pModuleArray[i],
                        szCurrentModuleName, sizeof(szCurrentModuleName)) == 0)
                    {
                        continue;
                    }
                    if (_stricmp(szCurrentModuleName, strLibName.c_str()) == 0)
                    {
                        dwRes = ERROR_SUCCESS;
                        *pbExists = true;
                        break;
                    }
                }
            }
            while (false);

            if (pModuleArray)
                delete [] pModuleArray;

            return dwRes;
        }

        static DWORD existsRemoteModule(
            HANDLE hProcess,
            const wchar_t* szModuleName,
            bool* pbExists)
        {
            if (!hProcess)
                return ERROR_INVALID_PARAMETER;
            if (!szModuleName)
                return ERROR_INVALID_PARAMETER;
            if (wcslen(szModuleName) == 0)
                return ERROR_INVALID_PARAMETER;
            if (!pbExists)
                return ERROR_INVALID_PARAMETER;

            DWORD dwRes = ERROR_SUCCESS;

            HMODULE* pModuleArray = NULL;

            do
            {
                DWORD dwModuleArraySize = 300;
                pModuleArray = new HMODULE[dwModuleArraySize];
                DWORD dwNumModules = dwModuleArraySize;
                if (!::EnumProcessModulesEx(hProcess, pModuleArray,
                    dwModuleArraySize * sizeof(HMODULE), &dwNumModules, LIST_MODULES_ALL))
                {
                    dwRes = ::GetLastError();
                    break;
                }

                dwNumModules /= sizeof(HMODULE);

                if (dwNumModules > dwModuleArraySize)
                {
                    delete [] pModuleArray;
                    pModuleArray = NULL;
                    pModuleArray = new HMODULE[dwNumModules];

                    dwModuleArraySize = dwNumModules;

                    if (!::EnumProcessModulesEx(hProcess, pModuleArray,
                        dwModuleArraySize * sizeof(HMODULE), &dwNumModules, LIST_MODULES_ALL))
                    {
                        dwRes = ::GetLastError();
                        break;
                    }

                    dwNumModules /= sizeof(HMODULE);
                }

                wchar_t szCurrentModuleName[MAX_PATH] = { 0 };

                std::wstring strLibName;
                {
                    wchar_t szDrive[_MAX_DRIVE] = { 0 };
                    wchar_t szDir[_MAX_DIR] = { 0 };
                    wchar_t szFile[_MAX_FNAME] = { 0 };
                    wchar_t szExt[_MAX_EXT] = { 0 };

                    if (_wsplitpath_s(szModuleName,
                        szDrive, _MAX_DRIVE,
                        szDir, _MAX_DIR,
                        szFile, _MAX_FNAME,
                        szExt, _MAX_EXT) == 0)
                    {
                        if (szFile) {
                            strLibName.append(szFile);
                            if (szExt) {
                                if (wcslen(szExt) > 0) {
                                    if (szExt[0] != L'.')
                                        strLibName.append(L".");
                                    strLibName.append(szExt);
                                }
                            }
                        }
                    }
                }

                for (DWORD i = 0; i <= dwNumModules; ++i)
                {
                    if (::GetModuleBaseNameW(hProcess, pModuleArray[i],
                        szCurrentModuleName, sizeof(szCurrentModuleName)) == 0)
                    {
                        continue;
                    }
                    if (_wcsicmp(szCurrentModuleName, strLibName.c_str()) == 0)
                    {
                        dwRes = ERROR_SUCCESS;
                        *pbExists = true;
                        break;
                    }
                }
            }
            while (false);

            if (pModuleArray)
                delete [] pModuleArray;

            return dwRes;
        }

        static DWORD getRemoteModuleHandle(
                HANDLE hProcess,
                const char* szModuleName,
                HMODULE* pModule)
        {
            if (!hProcess)
                return ERROR_INVALID_PARAMETER;
            if (!szModuleName)
                return ERROR_INVALID_PARAMETER;
            if (strlen(szModuleName) == 0)
                return ERROR_INVALID_PARAMETER;
            if (!pModule)
                return ERROR_INVALID_PARAMETER;

            DWORD dwRes = ERROR_SUCCESS;

            HMODULE* pModuleArray = NULL;

            do
            {
                DWORD dwModuleArraySize = 300;
                pModuleArray = new HMODULE[dwModuleArraySize];
                DWORD dwNumModules = dwModuleArraySize;
                if (!::EnumProcessModulesEx(hProcess, pModuleArray,
                    dwModuleArraySize * sizeof(HMODULE), &dwNumModules, LIST_MODULES_ALL))
                {
                    dwRes = ::GetLastError();
                    break;
                }

                dwNumModules /= sizeof(HMODULE);

                if (dwNumModules > dwModuleArraySize)
                {
                    delete[] pModuleArray;
                    pModuleArray = NULL;
                    pModuleArray = new HMODULE[dwNumModules];

                    dwModuleArraySize = dwNumModules;

                    if (!::EnumProcessModulesEx(hProcess, pModuleArray,
                        dwModuleArraySize * sizeof(HMODULE), &dwNumModules, LIST_MODULES_ALL))
                    {
                        dwRes = ::GetLastError();
                        break;
                    }

                    dwNumModules /= sizeof(HMODULE);
                }

                char szCurrentModuleName[MAX_PATH] = { 0 };

                for (DWORD i = 0; i <= dwNumModules; ++i)
                {
                    if (::GetModuleBaseNameA(hProcess, pModuleArray[i],
                        szCurrentModuleName, sizeof(szCurrentModuleName)) == 0)
                    {
                        continue;
                    }
                    if (_stricmp(szCurrentModuleName, szModuleName) == 0)
                    {
                        dwRes = ERROR_SUCCESS;
                        *pModule = pModuleArray[i];
                        break;
                    }
                }
            }
            while (false);

            if (pModuleArray)
                delete[] pModuleArray;

            return dwRes;
        }

        static DWORD getRemoteModuleHandle(
            HANDLE hProcess,
            const wchar_t* szModuleName,
            HMODULE* pModule)
        {
            if (!hProcess)
                return ERROR_INVALID_PARAMETER;
            if (!szModuleName)
                return ERROR_INVALID_PARAMETER;
            if (wcslen(szModuleName) == 0)
                return ERROR_INVALID_PARAMETER;
            if (!pModule)
                return ERROR_INVALID_PARAMETER;

            DWORD dwRes = ERROR_SUCCESS;

            HMODULE* pModuleArray = NULL;

            do
            {
                DWORD dwModuleArraySize = 300;
                pModuleArray = new HMODULE[dwModuleArraySize];
                DWORD dwNumModules = 0;
                if (!::EnumProcessModulesEx(hProcess, pModuleArray,
                    dwModuleArraySize * sizeof(HMODULE), &dwNumModules, LIST_MODULES_ALL))
                {
                    dwRes = ::GetLastError();
                    break;
                }

                dwNumModules /= sizeof(HMODULE);

                if (dwNumModules > dwModuleArraySize)
                {
                    delete [] pModuleArray;
                    pModuleArray = NULL;
                    pModuleArray = new HMODULE[dwNumModules];

                    dwModuleArraySize = dwNumModules;

                    if (!::EnumProcessModulesEx(hProcess, pModuleArray,
                        dwModuleArraySize * sizeof(HMODULE), &dwNumModules, LIST_MODULES_ALL))
                    {
                        dwRes = ::GetLastError();
                        break;
                    }

                    dwNumModules /= sizeof(HMODULE);
                }

                wchar_t szCurrentModuleName[MAX_PATH] = { 0 };

                for (DWORD i = 0; i <= dwNumModules; ++i)
                {
                    if (::GetModuleBaseNameW(hProcess, pModuleArray[i],
                        szCurrentModuleName, sizeof(szCurrentModuleName)) == 0)
                    {
                        continue;
                    }
                    if (_wcsicmp(szCurrentModuleName, szModuleName) == 0)
                    {
                        dwRes = ERROR_SUCCESS;
                        *pModule = pModuleArray[i];
                        break;
                    }
                }
            }
            while (false);

            if (pModuleArray)
                delete [] pModuleArray;

            return dwRes;
        }

        static DWORD getRemoteProcAddress(
            HANDLE hProcess,
            HMODULE hModule,
            const char* szProcName,
            FARPROC* pProcAddress);

        static DWORD getRemoteProcAddress(
                HANDLE hProcess,
                HMODULE hModule,
                unsigned int nOrdinal,
                FARPROC* pProcAddress)
        {
            if (!hProcess)
                return ERROR_INVALID_PARAMETER;
            if (!hModule)
                return ERROR_INVALID_PARAMETER;
                return ERROR_INVALID_PARAMETER;
            if (!pProcAddress)
                return ERROR_INVALID_PARAMETER;

            DWORD dwRes = ERROR_SUCCESS;

            FARPROC procAddress = NULL;

            DWORD* pdwExportFunctionTable = 0;
            DWORD* pdwExportNameTable = 0;
            WORD* pwExportOrdinalTable = 0;

            do
            {
                MODULEINFO remoteModuleInfo = { 0 };
                if (!::GetModuleInformation(hProcess, hModule, &remoteModuleInfo,
                    sizeof(remoteModuleInfo)))
                {
                    dwRes = ::GetLastError();
                    break;
                }

                UINT_PTR nRemoteModuleBaseVA = (UINT_PTR) remoteModuleInfo.lpBaseOfDll;

                // Read the DOS header and check it's magic number
                IMAGE_DOS_HEADER dosHeader = { 0 };
                if (!::ReadProcessMemory(hProcess, (LPCVOID)nRemoteModuleBaseVA, &dosHeader,
                    sizeof(dosHeader), NULL))
                {
                    dwRes = ::GetLastError();
                    break;
                }
                if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE)
                {
                    dwRes = ERROR_INVALID_PARAMETER;
                    break;
                }

                // Read and check the NT signature
                DWORD dwSignature = 0;
                if (!::ReadProcessMemory(hProcess, (LPCVOID) (nRemoteModuleBaseVA + dosHeader.e_lfanew),
                    &dwSignature, sizeof(dwSignature), NULL))
                {
                    dwRes = ::GetLastError();
                    break;
                }
                if (dwSignature != IMAGE_NT_SIGNATURE)
                {
                    dwRes = ERROR_INVALID_PARAMETER;
                    break;
                }

                // Read the main header
                IMAGE_FILE_HEADER fileHeader = { 0 };
                if (!::ReadProcessMemory(hProcess,
                    (LPCVOID)(nRemoteModuleBaseVA + dosHeader.e_lfanew + sizeof(dwSignature)),
                    &fileHeader, sizeof(fileHeader), NULL))
                {
                    dwRes = ERROR_INVALID_PARAMETER;
                    break;
                }

                // Which type of optional header is the right size?
                bool bIs64Bit = true;
                IMAGE_OPTIONAL_HEADER64 optHeader64 = { 0 };
                IMAGE_OPTIONAL_HEADER32 optHeader32 = { 0 };
                if (fileHeader.SizeOfOptionalHeader == sizeof(optHeader64))
                    bIs64Bit = true;
                else if (fileHeader.SizeOfOptionalHeader == sizeof(optHeader32))
                    bIs64Bit = false;
                else
                {
                    dwRes = ERROR_INVALID_PARAMETER;
                    break;
                }

                if (bIs64Bit)
                {
                    // Read the optional header and check it's magic number
                    if (!::ReadProcessMemory(hProcess,
                        (LPCVOID) (nRemoteModuleBaseVA + dosHeader.e_lfanew + sizeof(dwSignature) + sizeof(fileHeader)),
                        &optHeader64, fileHeader.SizeOfOptionalHeader, NULL))
                    {
                        dwRes = ::GetLastError();
                        break;
                    }
                    if (optHeader64.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
                    {
                        dwRes = ERROR_INVALID_PARAMETER;
                        break;
                    }
                }
                else
                {
                    // Read the optional header and check it's magic number
                    if (!::ReadProcessMemory(hProcess,
                        (LPCVOID) (nRemoteModuleBaseVA + dosHeader.e_lfanew + sizeof(dwSignature) + sizeof(fileHeader)),
                        &optHeader32, fileHeader.SizeOfOptionalHeader, NULL))
                    {
                        dwRes = ::GetLastError();
                        break;
                    }
                    if (optHeader32.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC)
                    {
                        dwRes = ERROR_INVALID_PARAMETER;
                        break;
                    }
                }

                // Make sure the remote module has an export directory and if it does save it's relative address and size
                IMAGE_DATA_DIRECTORY exportDirectory = { 0 };
                if (bIs64Bit && optHeader64.NumberOfRvaAndSizes >= IMAGE_DIRECTORY_ENTRY_EXPORT + 1)
                {
                    exportDirectory.VirtualAddress = (optHeader64.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]).VirtualAddress;
                    exportDirectory.Size = (optHeader64.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]).Size;
                }
                else if (optHeader32.NumberOfRvaAndSizes >= IMAGE_DIRECTORY_ENTRY_EXPORT + 1)
                {
                    exportDirectory.VirtualAddress = (optHeader32.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]).VirtualAddress;
                    exportDirectory.Size = (optHeader32.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]).Size;
                }
                else
                {
                    dwRes = ERROR_INVALID_PARAMETER;
                    break;
                }

                // Read the main export table
                IMAGE_EXPORT_DIRECTORY exportTable = { 0 };
                if (!::ReadProcessMemory(hProcess, (LPCVOID) (nRemoteModuleBaseVA + exportDirectory.VirtualAddress),
                    &exportTable, sizeof(exportTable), NULL))
                {
                    dwRes = ::GetLastError();
                    break;
                }

                // Save the absolute address of the tables so we don't need to keep adding the base address
                UINT_PTR nExportFunctionTableVA = nRemoteModuleBaseVA + exportTable.AddressOfFunctions;
                UINT_PTR nExportNameTableVA = nRemoteModuleBaseVA + exportTable.AddressOfNames;
                UINT_PTR nExportOrdinalTableVA = nRemoteModuleBaseVA + exportTable.AddressOfNameOrdinals;

                // Allocate memory for our copy of the tables
                pdwExportFunctionTable = new DWORD[exportTable.NumberOfFunctions];
                pdwExportNameTable = new DWORD[exportTable.NumberOfNames];
                pwExportOrdinalTable = new WORD[exportTable.NumberOfNames];
                if (pdwExportFunctionTable == NULL || pdwExportNameTable == NULL || pwExportOrdinalTable == NULL)
                {
                    dwRes = ERROR_NOT_ENOUGH_MEMORY;
                    break;
                }

                // Get a copy of the function table
                if (!::ReadProcessMemory(hProcess, (LPCVOID)nExportFunctionTableVA,
                    pdwExportFunctionTable, exportTable.NumberOfFunctions * sizeof(DWORD), NULL))
                {
                    dwRes = ::GetLastError();
                    break;
                }

                // Get a copy of the name table
                if (!::ReadProcessMemory(hProcess, (LPCVOID)nExportNameTableVA,
                    pdwExportNameTable, exportTable.NumberOfNames * sizeof(DWORD), NULL))
                {
                    dwRes = ::GetLastError();
                    break;
                }

                // Get a copy of the ordinal table
                if (!::ReadProcessMemory(hProcess, (LPCVOID)nExportOrdinalTableVA,
                    pwExportOrdinalTable, exportTable.NumberOfNames * sizeof(WORD), NULL))
                {
                    dwRes = ::GetLastError();
                    break;
                }

                // NOTE:
                // Microsoft's PE/COFF specification does NOT say we need to subtract the ordinal base
                // from our ordinal but it seems to always give the wrong function if we don't

                // Make sure the ordinal is valid
                if (nOrdinal < exportTable.Base || (nOrdinal - exportTable.Base) >= exportTable.NumberOfFunctions)
                {
                    dwRes = ERROR_INVALID_PARAMETER;
                    break;
                }

                UINT nFunctionTableIndex = nOrdinal - exportTable.Base;

                // Check if the function is forwarded and if so get the real address
                if (pdwExportFunctionTable[nFunctionTableIndex] >= exportDirectory.VirtualAddress &&
                    pdwExportFunctionTable[nFunctionTableIndex] <= exportDirectory.VirtualAddress + exportDirectory.Size)
                {
                    bool bDone = false;
                    char nChar = 0;
                    std::string strTempForwardString;

                    // Get the forwarder string one character at a time because we don't know how long it is
                    for (UINT_PTR i = 0; !bDone; ++i)
                    {
                        // Get next character
                        if (!::ReadProcessMemory(hProcess,
                            (LPCVOID) (nRemoteModuleBaseVA + pdwExportFunctionTable[nFunctionTableIndex] + i),
                            &nChar, sizeof(nChar), NULL))
                        {
                            dwRes = ::GetLastError();
                            break;
                        }

                        // Add it to the string
                        strTempForwardString.push_back(nChar);

                        // If it's NUL we are done
                        if (nChar == (CHAR)'\0')
                            bDone = true;
                    }
                    if (dwRes != ERROR_SUCCESS)
                    {
                        break;
                    }

                    // Find the dot that seperates the module name and the function name/ordinal
                    size_t nDot = strTempForwardString.find('.');
                    if (nDot == std::string::npos)
                    {
                        dwRes = ERROR_INVALID_PARAMETER;
                        break;
                    }

                    // Temporary variables that hold parts of the forwarder string
                    std::string strRealModuleName;
                    std::string strRealFunctionId;
                    strRealModuleName = strTempForwardString.substr(0, nDot - 1);
                    strRealFunctionId = strTempForwardString.substr(nDot + 1, std::string::npos);

                    HMODULE hRealModule = NULL;
                    dwRes = sys::getRemoteModuleHandle(hProcess, strRealModuleName.c_str(), &hRealModule);
                    if (dwRes != ERROR_SUCCESS)
                    {
                        break;
                    }

                    // Figure out if the function was exported by name or by ordinal
                    if (strRealFunctionId.at(0) == '#')
                    {
                        // Exported by ordinal

                        // Remove '#' from string
                        strRealFunctionId.erase(0, 1);

                        UINT nRealOrdinal = (UINT) atoi(strRealFunctionId.c_str());

                        // Recursively call this function to get return value
                        procAddress = NULL;
                        dwRes = sys::getRemoteProcAddress(hProcess, hRealModule, nRealOrdinal, &procAddress);
                        if (dwRes != ERROR_SUCCESS)
                            break;
                    }
                    else
                    {
                        // Exported by name
                        // Recursively call this function to get return value
                        procAddress = NULL;
                        dwRes = sys::getRemoteProcAddress(hProcess, hRealModule, strRealFunctionId.c_str(), &procAddress);
                        if (dwRes != ERROR_SUCCESS)
                            break;
                    }
                }
                else
                {
                    // Not Forwarded
                    // Make a temporary variable to hold return value
                    procAddress = (FARPROC) (nRemoteModuleBaseVA + pdwExportFunctionTable[nFunctionTableIndex]);
                }
            }
            while (false);

            if (pdwExportFunctionTable)
                delete[] pdwExportFunctionTable;
            if (pdwExportNameTable)
                delete [] pdwExportNameTable;
            if (pwExportOrdinalTable)
                delete [] pwExportOrdinalTable;

            if (dwRes == ERROR_SUCCESS)
            {
                if (procAddress)
                {
                    if (pProcAddress)
                        *pProcAddress = procAddress;
                }
                else
                {
                    dwRes = ERROR_PROC_NOT_FOUND;
                }
            }

            return dwRes;
        }

        static DWORD getRemoteProcAddress(
            HANDLE hProcess,
            HMODULE hModule,
            const char* szProcName,
            FARPROC* pProcAddress)
        {
            if (!hProcess)
                return ERROR_INVALID_PARAMETER;
            if (!hModule)
                return ERROR_INVALID_PARAMETER;
            if (!szProcName)
                return ERROR_INVALID_PARAMETER;
            if (strlen(szProcName) == 0)
                return ERROR_INVALID_PARAMETER;
            if (!pProcAddress)
                return ERROR_INVALID_PARAMETER;

            DWORD dwRes = ERROR_SUCCESS;

            FARPROC procAddress = NULL;

            DWORD* pdwExportFunctionTable = 0;
            DWORD* pdwExportNameTable = 0;
            WORD* pwExportOrdinalTable = 0;

            do
            {
                MODULEINFO remoteModuleInfo = { 0 };
                if (!::GetModuleInformation(hProcess, hModule, &remoteModuleInfo,
                    sizeof(remoteModuleInfo)))
                {
                    dwRes = ::GetLastError();
                    break;
                }

                UINT_PTR nRemoteModuleBaseVA = (UINT_PTR) remoteModuleInfo.lpBaseOfDll;

                // Read the DOS header and check it's magic number
                IMAGE_DOS_HEADER dosHeader = { 0 };
                if (!::ReadProcessMemory(hProcess, (LPCVOID) nRemoteModuleBaseVA, &dosHeader,
                    sizeof(dosHeader), NULL))
                {
                    dwRes = ::GetLastError();
                    break;
                }
                if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE)
                {
                    dwRes = ERROR_INVALID_PARAMETER;
                    break;
                }

                // Read and check the NT signature
                DWORD dwSignature = 0;
                if (!::ReadProcessMemory(hProcess, (LPCVOID) (nRemoteModuleBaseVA + dosHeader.e_lfanew),
                    &dwSignature, sizeof(dwSignature), NULL))
                {
                    dwRes = ::GetLastError();
                    break;
                }
                if (dwSignature != IMAGE_NT_SIGNATURE)
                {
                    dwRes = ERROR_INVALID_PARAMETER;
                    break;
                }

                // Read the main header
                IMAGE_FILE_HEADER fileHeader = { 0 };
                if (!::ReadProcessMemory(hProcess,
                    (LPCVOID) (nRemoteModuleBaseVA + dosHeader.e_lfanew + sizeof(dwSignature)),
                    &fileHeader, sizeof(fileHeader), NULL))
                {
                    dwRes = ERROR_INVALID_PARAMETER;
                    break;
                }

                // Which type of optional header is the right size?
                bool bIs64Bit = true;
                IMAGE_OPTIONAL_HEADER64 optHeader64 = { 0 };
                IMAGE_OPTIONAL_HEADER32 optHeader32 = { 0 };
                if (fileHeader.SizeOfOptionalHeader == sizeof(optHeader64))
                    bIs64Bit = true;
                else if (fileHeader.SizeOfOptionalHeader == sizeof(optHeader32))
                    bIs64Bit = false;
                else
                {
                    dwRes = ERROR_INVALID_PARAMETER;
                    break;
                }

                if (bIs64Bit)
                {
                    // Read the optional header and check it's magic number
                    if (!::ReadProcessMemory(hProcess,
                        (LPCVOID) (nRemoteModuleBaseVA + dosHeader.e_lfanew + sizeof(dwSignature) + sizeof(fileHeader)),
                        &optHeader64, fileHeader.SizeOfOptionalHeader, NULL))
                    {
                        dwRes = ::GetLastError();
                        break;
                    }
                    if (optHeader64.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
                    {
                        dwRes = ERROR_INVALID_PARAMETER;
                        break;
                    }
                }
                else
                {
                    // Read the optional header and check it's magic number
                    if (!::ReadProcessMemory(hProcess,
                        (LPCVOID) (nRemoteModuleBaseVA + dosHeader.e_lfanew + sizeof(dwSignature) + sizeof(fileHeader)),
                        &optHeader32, fileHeader.SizeOfOptionalHeader, NULL))
                    {
                        dwRes = ::GetLastError();
                        break;
                    }
                    if (optHeader32.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC)
                    {
                        dwRes = ERROR_INVALID_PARAMETER;
                        break;
                    }
                }

                // Make sure the remote module has an export directory and if it does save it's relative address and size
                IMAGE_DATA_DIRECTORY exportDirectory = { 0 };
                if (bIs64Bit && optHeader64.NumberOfRvaAndSizes >= IMAGE_DIRECTORY_ENTRY_EXPORT + 1)
                {
                    exportDirectory.VirtualAddress = (optHeader64.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]).VirtualAddress;
                    exportDirectory.Size = (optHeader64.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]).Size;
                }
                else if (optHeader32.NumberOfRvaAndSizes >= IMAGE_DIRECTORY_ENTRY_EXPORT + 1)
                {
                    exportDirectory.VirtualAddress = (optHeader32.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]).VirtualAddress;
                    exportDirectory.Size = (optHeader32.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]).Size;
                }
                else
                {
                    dwRes = ERROR_INVALID_PARAMETER;
                    break;
                }

                // Read the main export table
                IMAGE_EXPORT_DIRECTORY exportTable = { 0 };
                if (!::ReadProcessMemory(hProcess, (LPCVOID) (nRemoteModuleBaseVA + exportDirectory.VirtualAddress),
                    &exportTable, sizeof(exportTable), NULL))
                {
                    dwRes = ::GetLastError();
                    break;
                }

                // Save the absolute address of the tables so we don't need to keep adding the base address
                UINT_PTR nExportFunctionTableVA = nRemoteModuleBaseVA + exportTable.AddressOfFunctions;
                UINT_PTR nExportNameTableVA = nRemoteModuleBaseVA + exportTable.AddressOfNames;
                UINT_PTR nExportOrdinalTableVA = nRemoteModuleBaseVA + exportTable.AddressOfNameOrdinals;

                // Allocate memory for our copy of the tables
                pdwExportFunctionTable = new DWORD[exportTable.NumberOfFunctions];
                pdwExportNameTable = new DWORD[exportTable.NumberOfNames];
                pwExportOrdinalTable = new WORD[exportTable.NumberOfNames];
                if (pdwExportFunctionTable == NULL || pdwExportNameTable == NULL || pwExportOrdinalTable == NULL)
                {
                    dwRes = ERROR_NOT_ENOUGH_MEMORY;
                    break;
                }

                // Get a copy of the function table
                if (!::ReadProcessMemory(hProcess, (LPCVOID) nExportFunctionTableVA,
                    pdwExportFunctionTable, exportTable.NumberOfFunctions * sizeof(DWORD), NULL))
                {
                    dwRes = ::GetLastError();
                    break;
                }

                // Get a copy of the name table
                if (!::ReadProcessMemory(hProcess, (LPCVOID) nExportNameTableVA,
                    pdwExportNameTable, exportTable.NumberOfNames * sizeof(DWORD), NULL))
                {
                    dwRes = ::GetLastError();
                    break;
                }

                // Get a copy of the ordinal table
                if (!::ReadProcessMemory(hProcess, (LPCVOID) nExportOrdinalTableVA,
                    pwExportOrdinalTable, exportTable.NumberOfNames * sizeof(WORD), NULL))
                {
                    dwRes = ::GetLastError();
                    break;
                }

                // Iterate through all the names and see if they match the one we are looking for
                for (DWORD i = 0; i < exportTable.NumberOfNames; ++i)
                {
                    std::string strTempFunctionName;
                    bool bDone = false;

                    // Get the function name one character at a time because we don't know how long it is
                    for (UINT_PTR j = 0; !bDone; ++j)
                    {
                        // Get next character
                        char nChar = 0;
                        if (!::ReadProcessMemory(hProcess, (LPCVOID) (nRemoteModuleBaseVA + pdwExportNameTable[i] + j),
                            &nChar, sizeof(nChar), NULL))
                        {
                            dwRes = ::GetLastError();
                            break;
                        }

                        // Add it to the string
                        strTempFunctionName.push_back(nChar);

                        // If it's NUL we are done
                        if (nChar == (CHAR)'\0')
                            bDone = true;
                    }
                    if (dwRes != ERROR_SUCCESS)
                    {
                        break;
                    }

                    // Does the name match?
                    if (_stricmp(strTempFunctionName.c_str(), szProcName) == 0)
                    {
                        // NOTE:
                        // Microsoft's PE/COFF specification says we need to subtract the ordinal base
                        // from the value in the ordinal table but that seems to always give the wrong function

                        // Check if the function is forwarded and if so get the real address
                        if (pdwExportFunctionTable[pwExportOrdinalTable[i]] >= exportDirectory.VirtualAddress &&
                            pdwExportFunctionTable[pwExportOrdinalTable[i]] <= exportDirectory.VirtualAddress + exportDirectory.Size)
                        {
                            bDone = false;
                            std::string strTempForwardString;

                            // Get the forwarder string one character at a time because we don't know how long it is
                            for (UINT_PTR j = 0; !bDone; ++j)
                            {
                                // Get next character
                                char nChar = 0;
                                if (!::ReadProcessMemory(hProcess,
                                    (LPCVOID)(nRemoteModuleBaseVA + pdwExportFunctionTable[i] + j),
                                    &nChar, sizeof(nChar), NULL))
                                {
                                    dwRes = ::GetLastError();
                                    break;
                                }

                                // Add it to the string
                                strTempForwardString.push_back(nChar);

                                // If it's NUL we are done
                                if (nChar == (CHAR)'\0')
                                    bDone = true;
                            }
                            if (dwRes != ERROR_SUCCESS)
                            {
                                break;
                            }

                            // Find the dot that seperates the module name and the function name/ordinal
                            size_t nDot = strTempForwardString.find('.');
                            if (nDot == std::string::npos)
                            {
                                dwRes = ERROR_INVALID_PARAMETER;
                                break;
                            }

                            // Temporary variables that hold parts of the forwarder string
                            std::string strRealModuleName;
                            std::string strRealFunctionId;
                            strRealModuleName = strTempForwardString.substr(0, nDot);
                            strRealFunctionId = strTempForwardString.substr(nDot + 1, std::string::npos);

                            HMODULE hRealModule = NULL;
                            dwRes = sys::getRemoteModuleHandle(hProcess, strRealModuleName.c_str(), &hRealModule);
                            if (dwRes != ERROR_SUCCESS)
                            {
                                break;
                            }

                            // Figure out if the function was exported by name or by ordinal
                            if (strRealFunctionId.at(0) == '#')
                            {
                                // Exported by ordinal

                                // Remove '#' from string
                                strRealFunctionId.erase(0, 1);

                                UINT nRealOrdinal = (UINT) atoi(strRealFunctionId.c_str());

                                // Recursively call this function to get return value
                                procAddress = NULL;
                                dwRes = sys::getRemoteProcAddress(hProcess, hRealModule, nRealOrdinal, &procAddress);
                                if (dwRes != ERROR_SUCCESS)
                                {
                                    break;
                                }
                            }
                            else
                            {
                                // Exported by name
                                // Recursively call this function to get return value
                                procAddress = NULL;
                                dwRes = sys::getRemoteProcAddress(hProcess, hRealModule, strRealFunctionId.c_str(), &procAddress);
                                if (dwRes != ERROR_SUCCESS)
                                {
                                    break;
                                }
                            }
                        }
                        else
                        {
                            // Not Forwarded

                            // NOTE:
                            // Microsoft's PE/COFF specification says we need to subtract the ordinal base
                            //from the value in the ordinal table but that seems to always give the wrong function
                            //TempReturn = (FARPROC)(RemoteModuleBaseVA + ExportFunctionTable[ExportOrdinalTable[i] - ExportTable.Base]);

                            // So we do it this way instead
                            procAddress = (FARPROC) (nRemoteModuleBaseVA + pdwExportFunctionTable[pwExportOrdinalTable[i]]);
                        }

                        break;
                    }

                    if (dwRes != ERROR_SUCCESS)
                    {
                        break;
                    }

                    // Wrong function let's try the next...
                }
            }
            while (false);

            if (pdwExportFunctionTable)
                delete [] pdwExportFunctionTable;
            if (pdwExportNameTable)
                delete [] pdwExportNameTable;
            if (pwExportOrdinalTable)
                delete [] pwExportOrdinalTable;

            if (dwRes == ERROR_SUCCESS)
            {
                if (procAddress)
                {
                    if (pProcAddress)
                        *pProcAddress = procAddress;
                }
                else
                {
                    dwRes = ERROR_PROC_NOT_FOUND;
                }
            }

            return dwRes;
        }
    }
}

#endif // LOKIBIT_COMMON_SYS_WINDOWS_REMOTE_PROCESS_INFO_H
