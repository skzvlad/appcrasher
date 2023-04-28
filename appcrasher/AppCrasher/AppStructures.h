// AppStructures.h

#pragma once

#include <string>
#include <vector>

struct CmdData
{
    bool         showHelp = false;
    long long    pid = 0;
    std::wstring processName;
    std::wstring processPath;

    CmdData() = default;

    void clear()
    {
        showHelp = false;
        pid = 0;
        processName.clear();
        processPath.clear();
    }
};
