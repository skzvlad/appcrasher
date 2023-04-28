/*
 * PrivilegesUtils.h
 * Copyright (C) 2011-2023 Vladimir V. Skuzovatkin
 *
 */

#ifndef LOKIBIT_COMMON_SECURITY_PRIVILEGES_UTILS_H
#define LOKIBIT_COMMON_SECURITY_PRIVILEGES_UTILS_H

#include <windows.h>
#include <string>
#include <set>

namespace lokibit
{
    namespace security
    {
        struct PrivilegeOpt
        {
            std::wstring strName;
            std::wstring strDescription;

            PrivilegeOpt()
                : strName(L"")
                , strDescription(L"")
            {
            }
            PrivilegeOpt(const std::wstring& name, const std::wstring& desc)
                : strName(name)
                , strDescription(desc)
            {
            }
        };

        static const PrivilegeOpt kAllPrivileges[] = 
        {
              PrivilegeOpt(SE_ASSIGNPRIMARYTOKEN_NAME,     L"Required to assign the primary token of a process")
            , PrivilegeOpt(SE_AUDIT_NAME,                  L"Required to generate audit-log entries")
            , PrivilegeOpt(SE_BACKUP_NAME,                 L"Required to perform backup operations")
            , PrivilegeOpt(SE_CHANGE_NOTIFY_NAME,          L"Required to receive notifications of changes to files or directories")
            , PrivilegeOpt(SE_CREATE_GLOBAL_NAME,          L"Required to create named file mapping objects in the global namespace during Terminal Services sessions")
            , PrivilegeOpt(SE_CREATE_PAGEFILE_NAME,        L"Required to create a paging file")
            , PrivilegeOpt(SE_CREATE_PERMANENT_NAME,       L"Required to create a permanent object")
            , PrivilegeOpt(SE_CREATE_SYMBOLIC_LINK_NAME,   L"Required to create a symbolic link")
            , PrivilegeOpt(SE_CREATE_TOKEN_NAME,           L"Required to create a primary token")
            , PrivilegeOpt(SE_DEBUG_NAME,                  L"Required to debug and adjust the memory of a process owned by another account")
            , PrivilegeOpt(SE_ENABLE_DELEGATION_NAME,      L"Required to mark user and computer accounts as trusted for delegation")
            , PrivilegeOpt(SE_IMPERSONATE_NAME,            L"Required to impersonate")
            , PrivilegeOpt(SE_INC_BASE_PRIORITY_NAME,      L"Required to increase the base priority of a process")
            , PrivilegeOpt(SE_INCREASE_QUOTA_NAME,         L"Required to increase the quota assigned to a process")
            , PrivilegeOpt(SE_INC_WORKING_SET_NAME,        L"Required to allocate more memory for applications that run in the context of users")
            , PrivilegeOpt(SE_LOAD_DRIVER_NAME,            L"Required to load or unload a device driver")
            , PrivilegeOpt(SE_LOCK_MEMORY_NAME,            L"Required to lock physical pages in memory")
            , PrivilegeOpt(SE_MACHINE_ACCOUNT_NAME,        L"Required to create a computer account")
            , PrivilegeOpt(SE_MANAGE_VOLUME_NAME,          L"Required to enable volume management privileges")
            , PrivilegeOpt(SE_PROF_SINGLE_PROCESS_NAME,    L"Required to gather profiling information for a single process")
            , PrivilegeOpt(SE_RELABEL_NAME,                L"Required to modify the mandatory integrity level of an object")
            , PrivilegeOpt(SE_REMOTE_SHUTDOWN_NAME,        L"Required to shut down a system using a network request")
            , PrivilegeOpt(SE_RESTORE_NAME,                L"Required to perform restore operations")
            , PrivilegeOpt(SE_SECURITY_NAME,               L"Required to perform a number of security-related functions, such as controlling and viewing audit messages")
            , PrivilegeOpt(SE_SHUTDOWN_NAME,               L"Required to shut down a local system")
            , PrivilegeOpt(SE_SYNC_AGENT_NAME,             L"Required for a domain controller to use the LDAP directory synchronization services")
            , PrivilegeOpt(SE_SYSTEM_ENVIRONMENT_NAME,     L"Required to modify the nonvolatile RAM of systems that use this type of memory to store configuration information")
            , PrivilegeOpt(SE_SYSTEM_PROFILE_NAME,         L"Required to gather profiling information for the entire system")
            , PrivilegeOpt(SE_SYSTEMTIME_NAME,             L"Required to modify the system time")
            , PrivilegeOpt(SE_TAKE_OWNERSHIP_NAME,         L"Required to take ownership of an object without being granted discretionary access")
            , PrivilegeOpt(SE_TCB_NAME,                    L"This privilege identifies its holder as part of the trusted computer base")
            , PrivilegeOpt(SE_TIME_ZONE_NAME,              L"Required to adjust the time zone associated with the computer's internal clock")
            , PrivilegeOpt(SE_TRUSTED_CREDMAN_ACCESS_NAME, L"Required to access Credential Manager as a trusted caller")
            , PrivilegeOpt(SE_UNDOCK_NAME,                 L"Required to undock a laptop")
            , PrivilegeOpt(SE_UNSOLICITED_INPUT_NAME,      L"Required to read unsolicited input from a terminal device")
        };

        static const size_t kAllPrivilegesCount = (sizeof(kAllPrivileges) / sizeof(PrivilegeOpt));

        class ProcessPrivilegeHandler
        {
        private:
            typedef std::set<std::wstring> TPrivilegeNames;
        public:
            ProcessPrivilegeHandler()
                : m_hProcess(NULL)
            {
            }
            ~ProcessPrivilegeHandler()
            {
            }

            DWORD open(HANDLE hProcess)
            {
                if (hProcess == NULL)
                    return ERROR_INVALID_PARAMETER;
                if (m_hProcess != NULL)
                    return ERROR_ALREADY_EXISTS;
                m_hProcess = hProcess;
                return ERROR_SUCCESS;
            }
            void close()
            {
                if (m_hProcess == NULL)
                    return;
                this->freeAllPrivileges();
                m_hProcess = NULL;
            }

            DWORD existsPrivilege(const wchar_t* pszPrivilegeName, bool& bExists)
            {
                if (!m_hProcess)
                    return ERROR_INVALID_ENVIRONMENT;
                if (!pszPrivilegeName)
                    return ERROR_INVALID_PARAMETER;
                bExists = false;
                DWORD dwRes = ERROR_SUCCESS;
                HANDLE hToken = INVALID_HANDLE_VALUE;
                do
                {
                    if (!::OpenProcessToken(m_hProcess, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
                        dwRes = ::GetLastError();
                        break;
                    }
                    TOKEN_PRIVILEGES privilegeToken;
                    ::ZeroMemory(&privilegeToken, sizeof(TOKEN_PRIVILEGES));
                    if (!::LookupPrivilegeValueW(NULL, pszPrivilegeName, &privilegeToken.Privileges[0].Luid )) {
                        dwRes = ::GetLastError();
                        break;
                    }
                    PRIVILEGE_SET privilegesSet;
                    ::ZeroMemory(&privilegesSet, sizeof(PRIVILEGE_SET));
                    privilegesSet.PrivilegeCount = 1;
                    privilegesSet.Control = PRIVILEGE_SET_ALL_NECESSARY;
                    privilegesSet.Privilege[0].Luid = privilegeToken.Privileges[0].Luid;
                    BOOL bResult = FALSE;
                    if (!::PrivilegeCheck(hToken, &privilegesSet, &bResult)) {
                        dwRes = ::GetLastError();
                        break;
                    }
                    bExists = (bResult == TRUE);
                }
                while (false);
                if (hToken != INVALID_HANDLE_VALUE)
                    ::CloseHandle(hToken);
                return dwRes;
            }
            DWORD addPrivilege(const wchar_t* pszPrivilegeName)
            {
                if (!m_hProcess)
                    return ERROR_INVALID_ENVIRONMENT;
                if (!pszPrivilegeName)
                    return ERROR_INVALID_PARAMETER;
                TPrivilegeNames::iterator it = m_aPrivilegeNames.find(pszPrivilegeName);
                if (it != m_aPrivilegeNames.end())
                    return ERROR_SUCCESS;
                DWORD dwRes = ERROR_SUCCESS;
                HANDLE hToken = INVALID_HANDLE_VALUE;
                do
                {
                    if (!::OpenProcessToken(m_hProcess, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
                        dwRes = ::GetLastError();
                        break;
                    }
                    TOKEN_PRIVILEGES privilegeToken;
                    ::ZeroMemory(&privilegeToken, sizeof(TOKEN_PRIVILEGES));
                    if (!::LookupPrivilegeValueW(NULL, pszPrivilegeName, &privilegeToken.Privileges[0].Luid )) {
                        dwRes = ::GetLastError();
                        break;
                    }
                    privilegeToken.PrivilegeCount = 1;
                    privilegeToken.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
                    if (!::AdjustTokenPrivileges(hToken, FALSE, &privilegeToken, 0, (PTOKEN_PRIVILEGES)NULL, 0)) {
                        dwRes = ::GetLastError();
                        break;
                    }
                    m_aPrivilegeNames.insert(pszPrivilegeName);
                }
                while (false);
                if (hToken != INVALID_HANDLE_VALUE)
                    ::CloseHandle(hToken);
                return dwRes;
            }
            DWORD freeAllPrivileges()
            {
                if (m_aPrivilegeNames.size() == 0)
                    return ERROR_SUCCESS;
                if (!m_hProcess)
                    return ERROR_INVALID_ENVIRONMENT;
                DWORD dwRes = ERROR_SUCCESS;
                HANDLE hToken = INVALID_HANDLE_VALUE;
                do
                {
                    if (!::OpenProcessToken(m_hProcess, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
                    {
                        dwRes = ::GetLastError();
                        break;
                    }
                    TOKEN_PRIVILEGES privilegeToken;
                    for (TPrivilegeNames::const_iterator it = m_aPrivilegeNames.begin(); it != m_aPrivilegeNames.end(); ++it)
                    {
                        ::ZeroMemory(&privilegeToken, sizeof(TOKEN_PRIVILEGES));
                        if (::LookupPrivilegeValueW(NULL, it->c_str(), &privilegeToken.Privileges[0].Luid))
                        {
                            privilegeToken.Privileges[0].Attributes = 0;
                            if (!::AdjustTokenPrivileges(hToken, FALSE, &privilegeToken, 0, (PTOKEN_PRIVILEGES) NULL, 0))
                            {
                                if (dwRes == ERROR_SUCCESS)
                                    dwRes = ::GetLastError();
                            }
                        }
                        else
                        {
                            if (dwRes == ERROR_SUCCESS)
                                dwRes = ::GetLastError();
                        }
                    }
                    m_aPrivilegeNames.clear();
                }
                while (false);
                if (hToken != INVALID_HANDLE_VALUE)
                    ::CloseHandle(hToken);
                return dwRes;
            }
        private:
            HANDLE           m_hProcess;
            TPrivilegeNames  m_aPrivilegeNames;
        };

        class CurrentProcessPrivilegeHandler
        {
        public:
            CurrentProcessPrivilegeHandler()
            {
                m_privilegeHandler.open(::GetCurrentProcess());
            }
            ~CurrentProcessPrivilegeHandler()
            {
                m_privilegeHandler.freeAllPrivileges();
            }

            DWORD existsPrivilege(const wchar_t* pszPrivilegeName, bool& bExists)
            {
                return m_privilegeHandler.existsPrivilege(pszPrivilegeName, bExists);
            }
            DWORD addPrivilege(const wchar_t* pszPrivilegeName)
            {
                return m_privilegeHandler.addPrivilege(pszPrivilegeName);
            }
            DWORD freeAllPrivileges()
            {
                return m_privilegeHandler.freeAllPrivileges();
            }
        private:
            ProcessPrivilegeHandler m_privilegeHandler;
        };
    }
}

#endif // LOKIBIT_COMMON_SECURITY_PRIVILEGES_UTILS_H
