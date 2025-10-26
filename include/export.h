#pragma once

// DLL export/import macros for Windows
#ifdef _WIN32
    #ifdef UNDOWNUNLOCK_EXPORTS
        #define UNDOWNUNLOCK_API __declspec(dllexport)
    #else
        #define UNDOWNUNLOCK_API __declspec(dllimport)
    #endif
#else
    #define UNDOWNUNLOCK_API
#endif