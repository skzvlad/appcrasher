/*
 * SysProcessUtils.h
 * Copyright (C) 2011-2023 Vladimir V. Skuzovatkin
 *
 */

#ifndef LOKIBIT_COMMON_SYSPROCESSUTILS_H
#define LOKIBIT_COMMON_SYSPROCESSUTILS_H

#include <string>

#include <windows.h>
#include <tlhelp32.h>
#include <shellapi.h>

#include "StrUtils.h"

namespace winternl
{
    #include <Winternl.h>
}

namespace lokibit
{
    namespace sys
    {
        class ProcessScanner
        {
        public:
            ProcessScanner()
                : m_hProcessSnap(NULL)
                , m_bFirst(true)
            {
                ::ZeroMemory(&m_currentPe32, sizeof(PROCESSENTRY32));
                ::ZeroMemory(&m_currentMe32, sizeof(MODULEENTRY32));
                m_currentPe32.dwSize = sizeof(PROCESSENTRY32);
                m_currentMe32.dwSize = sizeof(MODULEENTRY32);
            }
            ~ProcessScanner()
            {
                this->close();
            }

            ProcessScanner(const ProcessScanner&) = delete;
            ProcessScanner& operator=(const ProcessScanner&) = delete;

            DWORD open()
            {
                if (this->isOpened())
                    return ERROR_ALREADY_EXISTS;

                m_hProcessSnap = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
                if (m_hProcessSnap == INVALID_HANDLE_VALUE || m_hProcessSnap == NULL)
                {
                    m_hProcessSnap = NULL;
                    return ::GetLastError();
                }

                DWORD dwRes = ERROR_SUCCESS;

                ::ZeroMemory(&m_currentPe32, sizeof(PROCESSENTRY32));
                m_currentPe32.dwSize = sizeof(PROCESSENTRY32);

                ::ZeroMemory(&m_currentMe32, sizeof(MODULEENTRY32));
                m_currentMe32.dwSize = sizeof(MODULEENTRY32);

                if (::Process32First(m_hProcessSnap, &m_currentPe32))
                {
                    HANDLE hModuleSnap = ::CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, m_currentPe32.th32ProcessID);
                    if (hModuleSnap != INVALID_HANDLE_VALUE)
                    {
                        MODULEENTRY32 me32;
                        me32.dwSize = sizeof(MODULEENTRY32);
                        if (::Module32FirstW(hModuleSnap, &me32))
                            m_currentMe32 = me32;
                        ::CloseHandle(hModuleSnap);
                    }
                }
                else
                    dwRes = ::GetLastError();

                if (dwRes != ERROR_SUCCESS)
                    this->close();

                m_bFirst = true;

                return dwRes;
            }

            void close()
            {
                if (this->isOpened())
                {
                    ::CloseHandle(m_hProcessSnap);
                    ::ZeroMemory(&m_currentPe32, sizeof(PROCESSENTRY32));
                    ::ZeroMemory(&m_currentMe32, sizeof(MODULEENTRY32));
                    m_currentPe32.dwSize = sizeof(PROCESSENTRY32);
                    m_currentMe32.dwSize = sizeof(MODULEENTRY32);
                    m_hProcessSnap = NULL;
                    m_bFirst = true;
                }
            }

            bool isOpened() const
            {
                return (m_hProcessSnap != NULL && m_hProcessSnap != INVALID_HANDLE_VALUE);
            }

            bool next()
            {
                if (!this->isOpened())
                    return false;
                if (m_bFirst)
                {
                    m_bFirst = false;
                    return true;
                }
                DWORD dwRes = ERROR_SUCCESS;
                if (::Process32Next(m_hProcessSnap, &m_currentPe32))
                {
                    ::ZeroMemory(&m_currentMe32, sizeof(MODULEENTRY32));
                    m_currentMe32.dwSize = sizeof(MODULEENTRY32);

                    HANDLE hModuleSnap = ::CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, m_currentPe32.th32ProcessID);
                    if (hModuleSnap != INVALID_HANDLE_VALUE)
                    {
                        MODULEENTRY32 me32;
                        me32.dwSize = sizeof(MODULEENTRY32);
                        if (::Module32FirstW(hModuleSnap, &me32))
                            m_currentMe32 = me32;
                        ::CloseHandle(hModuleSnap);
                    }
                }
                else
                    dwRes = ::GetLastError();
                return (dwRes == ERROR_SUCCESS);
            }

            DWORD getPid() const
            {
                if (!this->isOpened())
                    return 0;
                return m_currentPe32.th32ProcessID;
            }

            bool isWow64() const
            {
                if (!this->isOpened())
                    return false;
                HANDLE hProcess = ::OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, m_currentPe32.th32ProcessID);
                if (!ProcessScanner::isValidHandle(hProcess))
                    return false;
                typedef BOOL (WINAPI* LPFN_ISWOW64PROCESS)(HANDLE, PBOOL);
                BOOL bIsWow64 = FALSE;
                LPFN_ISWOW64PROCESS fnIsWow64Process = (LPFN_ISWOW64PROCESS)::GetProcAddress(::GetModuleHandleW(L"kernel32"), "IsWow64Process");
                if (fnIsWow64Process)
                {
                    if (!fnIsWow64Process(hProcess, &bIsWow64))
                        bIsWow64 = FALSE;
                }
                ::CloseHandle(hProcess);
                return (bIsWow64 == TRUE);
            }

            void getProcessEntry(PROCESSENTRY32* pData) const
            {
                if (!this->isOpened())
                    return;
                if (pData)
                    *pData = m_currentPe32;
            }

            void getModuleEntry(MODULEENTRY32* pData) const
            {
                if (!this->isOpened())
                    return;
                if (pData)
                    *pData = m_currentMe32;
            }

            std::wstring getName() const
            {
                if (!this->isOpened())
                    return L"";
                if (!m_currentPe32.szExeFile)
                    return L"";
                return (wchar_t*)m_currentPe32.szExeFile;
            }

            std::wstring getPath() const
            {
                if (!this->isOpened())
                    return L"";
                if (m_currentMe32.szExePath)
                {
                    const wchar_t* szPath = (wchar_t*)m_currentMe32.szExePath;
                    if (wcslen(szPath) > 0)
                        return szPath;
                }
                std::wstring strImageName;
                HANDLE hProcess = ::OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, m_currentPe32.th32ProcessID);
                if (ProcessScanner::isValidHandle(hProcess))
                {
                    typedef BOOL (WINAPI* LPFN_QUERYFULLPROCESSIMAGENAMEW)(
                        HANDLE hProcess,
                        DWORD dwFlags,
                        LPWSTR lpExeName,
                        PDWORD lpdwSize);
                    LPFN_QUERYFULLPROCESSIMAGENAMEW fnQueryFullProcessImageNameW =
                        (LPFN_QUERYFULLPROCESSIMAGENAMEW)::GetProcAddress(::GetModuleHandleW(L"kernel32"), "QueryFullProcessImageNameW");
                    if (fnQueryFullProcessImageNameW)
                    {
                        DWORD dwBuffSize = 1024;
                        wchar_t pBuff[1024] = {0};
                        if (fnQueryFullProcessImageNameW(hProcess, 0, pBuff, &dwBuffSize))
                        {
                            if (pBuff && dwBuffSize > 0)
                                strImageName = pBuff;
                        }
                    }
                    ::CloseHandle(hProcess);
                }
                return strImageName;
            }

            std::wstring getCmdLine() const
            {
                if (!this->isOpened())
                    return L"";
                std::wstring strImageName;
                HANDLE hProcess = NULL;
                do
                {
                    hProcess = ::OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, m_currentPe32.th32ProcessID);
                    if (!ProcessScanner::isValidHandle(hProcess))
                        break;
                    typedef winternl::NTSTATUS (NTAPI* LPFN_NTQUERYINFORMATIONPROCESS)(
                        HANDLE ProcessHandle,
                        DWORD ProcessInformationClass,
                        PVOID ProcessInformation,
                        DWORD ProcessInformationLength,
                        PDWORD ReturnLength);
                    LPFN_NTQUERYINFORMATIONPROCESS fnNtQueryInformationProcess =
                        (LPFN_NTQUERYINFORMATIONPROCESS)::GetProcAddress(::GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess");
                    if (!fnNtQueryInformationProcess)
                        break;
                    winternl::PROCESS_BASIC_INFORMATION pbi;
                    winternl::NTSTATUS status = fnNtQueryInformationProcess(hProcess, 0, &pbi, sizeof(pbi), NULL);
                    if (status != 0)
                        break;
                    PVOID pebAddress = pbi.PebBaseAddress;
                    PVOID rtlUserProcParamsAddress;
                    PVOID pAddrToRead = (PCHAR)pebAddress + 0x10;
                    if (!::ReadProcessMemory(hProcess, pAddrToRead, &rtlUserProcParamsAddress, sizeof(PVOID), NULL))
                        break;
                    pAddrToRead = (PCHAR)rtlUserProcParamsAddress + 0x40;
                    winternl::UNICODE_STRING commandLine;
                    if (!::ReadProcessMemory(hProcess, pAddrToRead, &commandLine, sizeof(commandLine), NULL))
                        break;
                    WCHAR* commandLineContents = (WCHAR*)::malloc(commandLine.Length);
                    if (!commandLineContents)
                        break;
                    pAddrToRead = commandLine.Buffer;
                    if (!::ReadProcessMemory(hProcess, pAddrToRead, commandLineContents, commandLine.Length, NULL))
                    {
                        ::free(commandLineContents);
                        break;
                    }
                    const size_t nWstrLen = commandLine.Length / sizeof(wchar_t);
                    strImageName.reserve(nWstrLen);
                    for (size_t i = 0; i < nWstrLen; ++i)
                        strImageName.push_back(commandLineContents[i]);
                    lokibit::str::delAllBorderPairedQuotes(strImageName);
                    ::free(commandLineContents);
                }
                while (false);
                if (ProcessScanner::isValidHandle(hProcess))
                    ::CloseHandle(hProcess);
                if (strImageName.empty())
                    return this->getPath();
                return strImageName;
            }

            static bool isValidHandle(HANDLE h)
            {
                return (h != NULL && h != INVALID_HANDLE_VALUE);
            }

        private:
            HANDLE         m_hProcessSnap;
            PROCESSENTRY32 m_currentPe32;
            MODULEENTRY32  m_currentMe32;
            bool           m_bFirst;
        };
    }
}

#endif // LOKIBIT_COMMON_SYSPROCESSUTILS_H
