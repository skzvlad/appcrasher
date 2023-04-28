/*
 * StrUtils.h
 * Copyright (C) 2011-2023 Vladimir V. Skuzovatkin
 *
 */

#ifndef LOKIBIT_COMMON_STRUTILS_H
#define LOKIBIT_COMMON_STRUTILS_H

#include <windows.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

#include <string>
#include <cctype>
#include <cwctype>
#include <locale>
#include <vector>
#include <algorithm>

namespace lokibit
{
    namespace str
    {
        static void trim(std::string& src)
        {
            if (src.empty())
                return;

            const std::string::size_type lenSrc = src.size();

            std::string::size_type posL = 0;
            std::string::size_type posR = lenSrc - 1;
            std::string::size_type pos = 0;

            char chr;

            while (posL < lenSrc)
            {
                chr = src[posL];
                if (isspace((wint_t)chr) != 0)
                    posL++;
                else
                    break;
            }

            if (posL < posR)
            {
                while (posR != 0)
                {
                    chr = src[posR];
                    if (isspace((wint_t)chr) != 0)
                        posR--;
                    else
                        break;
                }
            }

            if (posR < (lenSrc - 1))
                src.erase(posR + 1);
            if (posL > 0)
                src.erase(0, posL);
        }

        static void trim(std::wstring& src)
        {
            if (src.empty())
                return;

            const std::wstring::size_type lenSrc = src.size();

            std::wstring::size_type posL = 0;
            std::wstring::size_type posR = lenSrc - 1;
            std::wstring::size_type pos = 0;

            wchar_t chr;

            while (posL < lenSrc)
            {
                chr = src[posL];
                if (iswspace((wint_t)chr) != 0)
                    posL++;
                else
                    break;
            }

            if (posL < posR)
            {
                while (posR != 0)
                {
                    chr = src[posR];
                    if (iswspace((wint_t)chr) != 0)
                        posR--;
                    else
                        break;
                }
            }

            if (posR < (lenSrc - 1))
                src.erase(posR + 1);
            if (posL > 0)
                src.erase(0, posL);
        }

        static std::wstring& replace(std::wstring& strContext, const std::wstring& strFrom, const std::wstring& strTo)
        {
            size_t nLook = 0;
            size_t nFound = strContext.find(strFrom, nLook);
            if (nFound != std::wstring::npos)
            {
                strContext.replace(nFound, strFrom.size(), strTo);
                nLook = nFound + strTo.size();
            }
            return strContext;
        }

        static std::wstring& replaceAll(std::wstring& strContext, const std::wstring& strFrom, const std::wstring& strTo)
        {
            size_t nLook = 0;
            size_t nFound;
            while ((nFound = strContext.find(strFrom, nLook)) != std::wstring::npos)
            {
                strContext.replace(nFound, strFrom.size(), strTo);
                nLook = nFound + strTo.size();
            }
            return strContext;
        }

        static void delBorderQuotes(std::wstring& strSrc)
        {
            const std::wstring::size_type lenSrc = strSrc.size();

            std::wstring::size_type posL = 0;
            std::wstring::size_type posR = lenSrc - 1;
            std::wstring::size_type pos = 0;

            wchar_t chr;

            while (posL < lenSrc)
            {
                chr = strSrc[posL];
                if (std::iswblank(chr) != 0)
                {
                    posL++;
                }
                else if (chr == L'\"')
                {
                    posL++;
                    break;
                }
                else
                    break;
            }

            if (posL < posR)
            {
                while (posR != 0)
                {
                    chr = strSrc[posR];
                    if (std::iswblank(chr) != 0)
                    {
                        posR--;
                    }
                    else if (chr == L'\"')
                    {
                        posR--;
                        break;
                    }
                    else
                        break;
                }
            }

            if (posL != 0 || posR != (lenSrc - 1))
                strSrc = strSrc.substr(posL, posR - posL + 1);
        }

        static bool delBorderPairedQuotes(std::wstring& strSrc)
        {
            const std::wstring::size_type lenSrc = strSrc.size();
            if (lenSrc < 1)
                return false;

            std::wstring::size_type posL = 0;
            std::wstring::size_type posR = lenSrc - 1;
            std::wstring::size_type pos = 0;

            wchar_t chr;
            bool bLFound = false;
            bool bRFound = false;

            while (posL < lenSrc)
            {
                chr = strSrc[posL];
                if (std::iswblank(chr) != 0)
                {
                    posL++;
                }
                else if (chr == L'\"')
                {
                    posL++;
                    bLFound = true;
                    break;
                }
                else
                    break;
            }

            if (posL < posR)
            {
                while (posR != 0)
                {
                    chr = strSrc[posR];
                    if (std::iswblank(chr) != 0)
                    {
                        posR--;
                    }
                    else if (chr == L'\"')
                    {
                        posR--;
                        bRFound = true;
                        break;
                    }
                    else
                        break;
                }
            }

            if (bLFound && bRFound)
                strSrc = strSrc.substr(posL, posR - posL + 1);

            return (bLFound && bRFound);
        }

        static bool delAllBorderPairedQuotes(std::wstring& strSrc)
        {
            bool bDeleted = false;
            for (;;)
            {
                if (lokibit::str::delBorderPairedQuotes(strSrc))
                    bDeleted = true;
                else
                    break;
            }
            return bDeleted;
        }
    }
}

#endif // LOKIBIT_COMMON_STRUTILS_H
