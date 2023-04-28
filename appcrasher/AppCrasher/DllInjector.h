// DllInjector.h

#pragma once

#include <string>

class DllInjector
{
public:
    DllInjector();
    ~DllInjector();

    int injectToProcessById(long long pid);
    int injectToProcessByName(const std::wstring& processName);
    int injectToProcessByExePath(const std::wstring& exePath);

private:
    int findProcessById(long long pid);
    int findProcessByName(long long& pid, const std::wstring& processName);
    int findProcessByExePath(long long& pid, const std::wstring& exePath);
    std::wstring dllPath();
};
