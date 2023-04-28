// dllmain.cpp

#include "pch.h"
#include <psapi.h>

#include <future>
#include <chrono>
#include <thread>

static int*       g_badPointer = 0;
std::future<void> g_thread;

void threafFunction()
{
    // A simple algorithm (delay) to make sure the library is loaded into the selected process.
    // We do fatal actions after loading this library into the process.
    std::this_thread::sleep_for(std::chrono::milliseconds(1500));

    *g_badPointer = 123;
    g_badPointer++;
}

void crashProcess()
{
    if (g_thread.valid())
    {
        if (g_thread.wait_for(std::chrono::milliseconds(0)) != std::future_status::ready)
        {
            // Thread already started
            return;
        }
    }

    try
    {
        g_thread = std::async(std::launch::async, threafFunction);
    }
    catch (...)
    {
    }
}

BOOL APIENTRY DllMain(HMODULE hModule,
                      DWORD  ul_reason_for_call,
                      LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        crashProcess();
        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
