// The following ifdef block is the standard way of creating macros which make exporting
// from a DLL simpler. All files within this DLL are compiled with the APPCRASHERINJECTOR_EXPORTS
// symbol defined on the command line. This symbol should not be defined on any project
// that uses this DLL. This way any other project whose source files include this file see
// APPCRASHERINJECTOR_API functions as being imported from a DLL, whereas this DLL sees symbols
// defined with this macro as being exported.

#ifdef APPCRASHERINJECTOR_EXPORTS
#define APPCRASHERINJECTOR_API __declspec(dllexport)
#else
#define APPCRASHERINJECTOR_API __declspec(dllimport)
#endif

// We implement at least one exported function to make the shared/dynamic library complete
APPCRASHERINJECTOR_API int appCrasherTest();
