/*
 * DllInjector.cpp
 * Copyright (C) 2011-2023 Vladimir V. Skuzovatkin
 *
 */

#include <iostream>
#include <iomanip>
#include <string>
#include <filesystem>

#include "DllInjector.h"
#include "StrUtils.h"
#include "RemoteProcessInfo.h"
#include "InjectLib.h"
#include "SysProcessUtils.h"

static const std::wstring kDllName_x64 = L"AppCrasherInjector_x64.dll";
static const std::wstring kDllName_x86 = L"AppCrasherInjector_x86.dll";

static std::wstring getExeFileW()
{
    const size_t nSize = 2048;
    wchar_t szBuff[nSize + 1] = { 0 };
    if (!::GetModuleFileNameW(::GetModuleHandleW(NULL), szBuff, nSize))
        return L"";
    return szBuff;
}

static std::wstring getExeDirW()
{
    const std::filesystem::path path = getExeFileW();
    return path.parent_path().wstring();
}

inline bool isApplication64Bit()
{
    #ifdef _WIN64
    bool bIs64Bit = true;
    #else
    bool bIs64Bit = false;
    #endif
    return bIs64Bit;
}

DllInjector::DllInjector()
{
}

DllInjector::~DllInjector()
{
}

int DllInjector::injectToProcessById(long long pid)
{
    if (pid < 1)
    {
        std::wcout << L"ERROR: [DllInjector] PID not defined!" << std::endl;
        return ERROR_INVALID_PARAMETER;
    }

    int res = this->DllInjector::findProcessById(pid);
    if (res != ERROR_SUCCESS)
        return res;

    const std::wstring dllPath = this->dllPath();
    if (!std::filesystem::exists(dllPath))
    {
        std::wcout << L"ERROR: [DllInjector] File: '" << dllPath << L"' is not found!" << std::endl;
        return ERROR_FILE_NOT_FOUND;
    }

    res = lokibit::sys::injectLib((DWORD)pid, dllPath.c_str());
    if (res != ERROR_SUCCESS)
    {
        std::wcout << L"ERROR: [DllInjector] Failed to inject DLL! Error code: " << res << L"." << std::endl;
    }

    return res;
}

int DllInjector::injectToProcessByName(const std::wstring & processName)
{
    if (processName.empty())
    {
        std::wcout << L"ERROR: [DllInjector] Process name is not defined!" << std::endl;
        return ERROR_INVALID_PARAMETER;
    }

    long long pid = 0;
    int res = this->DllInjector::findProcessByName(pid, processName);
    if (res != ERROR_SUCCESS)
    {
        std::wcout << L"ERROR: [DllInjector] Process '" << processName << L"' is not found in the system!" << std::endl;
        return res;
    }

    return this->injectToProcessById(pid);
}

int DllInjector::injectToProcessByExePath(const std::wstring& exePath)
{
    if (exePath.empty())
    {
        std::wcout << L"ERROR: [DllInjector] Process path is not defined!" << std::endl;
        return ERROR_INVALID_PARAMETER;
    }

    long long pid = 0;
    int res = this->DllInjector::findProcessByExePath(pid, exePath);
    if (res != ERROR_SUCCESS)
    {
        std::wcout << L"ERROR: [DllInjector] Process with the path '" << exePath << L"' is not found in the system!" << std::endl;
        return res;
    }

    return this->injectToProcessById(pid);
}

int DllInjector::findProcessById(long long pid)
{
    lokibit::sys::ProcessScanner scaner;
    int res = scaner.open();
    if (res != ERROR_SUCCESS)
    {
        std::wcout << L"ERROR: [DllInjector] Failed to open 'ProcessScanner'! Error code: " << (DWORD)res << std::endl;
        return res;
    }

    res = ERROR_NOT_FOUND;

    while (scaner.next())
    {
        if (pid == scaner.getPid())
        {
            res = ERROR_SUCCESS;
            break;
        }
    }

    return res;
}

int DllInjector::findProcessByName(long long & pid, const std::wstring & processName)
{
    pid = 0;

    std::wstring fixedProcessName = processName;
    lokibit::str::trim(fixedProcessName);
    if (fixedProcessName.empty())
    {
        std::wcout << L"ERROR: [DllInjector] Process name is not defined!" << std::endl;
        return ERROR_INVALID_PARAMETER;
    }

    lokibit::sys::ProcessScanner scaner;
    int res = scaner.open();
    if (res != ERROR_SUCCESS)
    {
        std::wcout << L"ERROR: [DllInjector] Failed to open 'ProcessScanner'! Error code: " << (DWORD)res << std::endl;
        return res;
    }

    res = ERROR_NOT_FOUND;

    std::wstring currName;
    while (scaner.next())
    {
        currName = scaner.getName();
        lokibit::str::trim(currName);

        if ((_wcsicmp(fixedProcessName.c_str(), currName.c_str()) == 0))
        {
            pid = scaner.getPid();
            res = ERROR_SUCCESS;
            break;
        }
    }

    return res;
}

int DllInjector::findProcessByExePath(long long & pid, const std::wstring & exePath)
{
    pid = 0;

    if (exePath.empty())
    {
        std::wcout << L"ERROR: [DllInjector] EXE path is not defined!" << std::endl;
        return ERROR_INVALID_PARAMETER;
    }

    lokibit::sys::ProcessScanner scaner;
    int res = scaner.open();
    if (res != ERROR_SUCCESS)
    {
        std::wcout << L"ERROR: [DllInjector] Failed to open 'ProcessScanner'! Error code: " << (DWORD)res << std::endl;
        return res;
    }

    res = ERROR_NOT_FOUND;

    std::wstring fixedExePath = exePath;
    lokibit::str::trim(fixedExePath);
    lokibit::str::replaceAll(fixedExePath, L"/", L"\\");

    std::wstring currPath;
    while (scaner.next())
    {
        currPath = scaner.getPath();
        lokibit::str::trim(currPath);
        lokibit::str::replaceAll(currPath, L"/", L"\\");

        if ((_wcsicmp(fixedExePath.c_str(), currPath.c_str()) == 0))
        {
            pid = scaner.getPid();
            res = ERROR_SUCCESS;
            break;
        }
    }

    return res;
}

std::wstring DllInjector::dllPath()
{
    std::filesystem::path path = getExeDirW();
    path /= (isApplication64Bit() ? kDllName_x64 : kDllName_x86);
    return path.wstring();
}
