/*
 * CmdLineParser.cpp
 * Copyright (C) 2011-2023 Vladimir V. Skuzovatkin
 *
 */

#include <string>
#include <array>

#include "AppDefs.h"
#include "CmdLineParser.h"
#include "StrUtils.h"

static const std::array<std::wstring, 3> kCmdKeys =
{
    kCmdKey_help,
    kCmdKey_processId,
    kCmdKey_processName
};

bool isCmdKey(const wchar_t* szText, const wchar_t* szCmdKey)
{
    if (!szText)
        return false;
    if (!szCmdKey)
        return false;
    return (_wcsicmp(szText, szCmdKey) == 0);
}

bool isCmdKey(const wchar_t* szCmdKey)
{
    if (!szCmdKey)
        return false;
    for (size_t i = 0; i < kCmdKeys.size(); ++i)
    {
        if ((_wcsicmp(szCmdKey, kCmdKeys[i].c_str()) == 0))
            return true;
    }
    return false;
}

bool parseCmdLine(CmdData& data, int argc, wchar_t* argv[])
{
    data.clear();

    if (argc < 2)
        return false;
    if (!argv)
        return false;

    int nPos = 1;
    while (nPos < argc)
    {
        if (isCmdKey(argv[nPos], kCmdKey_help.c_str()))
        {
            data.showHelp = true;
        }
        else if (isCmdKey(argv[nPos], kCmdKey_processId.c_str()))
        {
            if (nPos + 1 < argc)
            {
                if (!isCmdKey(argv[nPos + 1]))
                {
                    std::wstring text = argv[nPos + 1];
                    lokibit::str::trim(text);
                    if (!text.empty())
                    {
                        try
                        {
                            long long pid = std::stoll(text);
                            data.pid = pid;
                        }
                        catch (...)
                        {
                        }
                    }
                    nPos++;
                }
            }
        }
        else if (isCmdKey(argv[nPos], kCmdKey_processName.c_str()))
        {
            if (nPos + 1 < argc)
            {
                if (!isCmdKey(argv[nPos + 1]))
                {
                    std::wstring text = argv[nPos + 1];
                    lokibit::str::trim(text);
                    data.processName = text;
                    nPos++;
                }
            }
        }
        else if (isCmdKey(argv[nPos], kCmdKey_processPath.c_str()))
        {
            if (nPos + 1 < argc)
            {
                if (!isCmdKey(argv[nPos + 1]))
                {
                    std::wstring text = argv[nPos + 1];
                    lokibit::str::trim(text);
                    data.processPath = text;
                    nPos++;
                }
            }
        }
        nPos++;
    }

    return true;
}
