// CmdLineParser.h

#pragma once

#include "AppStructures.h"

bool isCmdKey(const wchar_t* szCmdKey);
bool parseCmdLine(CmdData& data, int argc, wchar_t* argv[]);
