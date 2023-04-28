/*
 * AppCrasher.cpp
 * Copyright (C) 2011-2023 Vladimir V. Skuzovatkin
 *
 */

#include <iostream>
#include <iomanip>
#include <string>

#include "CmdLineParser.h"
#include "DllInjector.h"
#include "PrivilegesUtils.h"

std::wstring helpString()
{
    std::wstring help =
        L"Usage:\r\n"
        L"    --help\r\n"
        L"    --pid <Process ID to hack>\r\n"
        L"    --pname <Process name to hack>\r\n"
        L"    --ppath <Full process path to hack>\r\n"
        L"\r\n"
        L"Examples:\r\n"
        L"    AppCrasher.exe --help\r\n"
        L"    AppCrasher.exe --pid 12345\r\n"
        L"    AppCrasher.exe --pname MyApplication.exe\r\n"
        L"    AppCrasher.exe --ppath \"d:\\tools\\MyApplication.exe\"\r\n";

    return help;
}

int wmain(int argc, wchar_t* argv[])
{
    if (argc < 2)
    {
        std::wcout << helpString() << std::endl;
        return 1;
    }

    bool helpDisplayed = false;
    CmdData cmd;
    parseCmdLine(cmd, argc, argv);
    if (cmd.showHelp)
    {
        std::wcout << helpString() << std::endl;
        helpDisplayed = true;
    }

    if (cmd.pid < 1 && cmd.processName.empty() && cmd.processPath.empty())
    {
        if (!helpDisplayed)
        {
            std::wcout << L"ERROR: The process in not defined!" << std::endl;
            std::wcout << helpString() << std::endl;
            return 1;
        }
    }

    if (cmd.pid > 0)
    {
        std::wcout << L"Trying to inject DLL into process with ID " << cmd.pid << std::endl;
        DllInjector injector;
        int res = injector.injectToProcessById(cmd.pid);
        if (res == 0)
        {
            std::wcout << L"DLL has been injected successfully!" << std::endl;
        }
        else
        {
            std::wcout << L"ERROR: Failed to inject DLL! Error code: " << res << std::endl;
        }
        return res;
    }

    lokibit::security::CurrentProcessPrivilegeHandler privilegeHandler;
    for (size_t i = 0; i < lokibit::security::kAllPrivilegesCount; ++i)
    {
        const lokibit::security::PrivilegeOpt privilege = lokibit::security::kAllPrivileges[i];
        DWORD dwRes = privilegeHandler.addPrivilege(privilege.strName.c_str());
        if (dwRes != ERROR_SUCCESS)
        {
            std::wcout << L"WARNING: Failed to add privilege! Error code: " << dwRes << L". Name: " << privilege.strName << L"." << std::endl;
        }
    }

    if (!cmd.processPath.empty())
    {
        std::wcout << L"Trying to inject DLL into process with path '" << cmd.processPath << L"'." << std::endl;
        DllInjector injector;
        int res = injector.injectToProcessByExePath(cmd.processPath);
        if (res == 0)
        {
            std::wcout << L"DLL has been injected successfully!" << std::endl;
        }
        else
        {
            std::wcout << L"ERROR: Failed to inject DLL! Error code: " << res << std::endl;
        }
        return res;
    }

    if (!cmd.processName.empty())
    {
        std::wcout << L"Trying to inject DLL into process with name '" << cmd.processName << L"'." << std::endl;
        DllInjector injector;
        int res = injector.injectToProcessByName(cmd.processName);
        if (res == 0)
        {
            std::wcout << L"DLL has been injected successfully!" << std::endl;
        }
        else
        {
            std::wcout << L"ERROR: Failed to inject DLL! Error code: " << res << std::endl;
        }
        return res;
    }

    return 0;
}
