// version.dll Proxy with Borderlands GOTY Hang Fix
// Version: 5.0.1 - WSOEx Timeout Patch

// Define this macro to enable detailed file logging.
// #define PROXY_DEBUG_LOGGING

#include <windows.h>
#include <stdio.h>  // For wsprintfA (used in FileLog)
#include <stdint.h> // For uintptr_t
#include "MinHook.h" // MinHook API

// --- Globals for Real version.dll Function Pointers ---
static HMODULE g_hRealVersionDll = nullptr;

// Typedefs for all 17 original VerQueryValue functions
typedef WINBOOL (WINAPI *tGetFileVersionInfoA)(LPCSTR, DWORD, DWORD, LPVOID);
typedef BOOL (WINAPI *tGetFileVersionInfoByHandle)(DWORD, LPCWSTR, DWORD, DWORD, LPVOID);
typedef BOOL (WINAPI *tGetFileVersionInfoExA)(DWORD, LPCSTR, DWORD, DWORD, LPVOID);
typedef BOOL (WINAPI *tGetFileVersionInfoExW)(DWORD, LPCWSTR, DWORD, DWORD, LPVOID);
typedef DWORD (WINAPI *tGetFileVersionInfoSizeA)(LPCSTR, LPDWORD);
typedef DWORD (WINAPI *tGetFileVersionInfoSizeExA)(DWORD, LPCSTR, LPDWORD);
typedef DWORD (WINAPI *tGetFileVersionInfoSizeExW)(DWORD, LPCWSTR, LPDWORD);
typedef DWORD (WINAPI *tGetFileVersionInfoSizeW)(LPCWSTR, LPDWORD);
typedef WINBOOL (WINAPI *tGetFileVersionInfoW)(LPCWSTR, DWORD, DWORD, LPVOID);
typedef DWORD (WINAPI *tVerFindFileA)(DWORD, LPSTR, LPSTR, LPSTR, LPSTR, PUINT, LPSTR, PUINT);
typedef DWORD (WINAPI *tVerFindFileW)(DWORD, LPWSTR, LPWSTR, LPWSTR, LPWSTR, PUINT, LPWSTR, PUINT);
typedef DWORD (WINAPI *tVerInstallFileA)(DWORD, LPSTR, LPSTR, LPSTR, LPSTR, LPSTR, LPSTR, PUINT);
typedef DWORD (WINAPI *tVerInstallFileW)(DWORD, LPWSTR, LPWSTR, LPWSTR, LPWSTR, LPWSTR, LPWSTR, PUINT);
typedef DWORD (WINAPI *tVerLanguageNameA)(DWORD, LPSTR, DWORD);
typedef DWORD (WINAPI *tVerLanguageNameW)(DWORD, LPWSTR, DWORD);
typedef BOOL (WINAPI *tVerQueryValueA)(LPCVOID, LPCSTR, LPVOID *, PUINT);
typedef BOOL (WINAPI *tVerQueryValueW)(LPCVOID, LPCWSTR, LPVOID *, PUINT);

// Pointers to original functions
static tGetFileVersionInfoA oGetFileVersionInfoA = nullptr;
static tGetFileVersionInfoByHandle oGetFileVersionInfoByHandle = nullptr;
static tGetFileVersionInfoExA oGetFileVersionInfoExA = nullptr;
static tGetFileVersionInfoExW oGetFileVersionInfoExW = nullptr;
static tGetFileVersionInfoSizeA oGetFileVersionInfoSizeA = nullptr;
static tGetFileVersionInfoSizeExA oGetFileVersionInfoSizeExA = nullptr;
static tGetFileVersionInfoSizeExW oGetFileVersionInfoSizeExW = nullptr;
static tGetFileVersionInfoSizeW oGetFileVersionInfoSizeW = nullptr;
static tGetFileVersionInfoW oGetFileVersionInfoW = nullptr;
static tVerFindFileA oVerFindFileA = nullptr;
static tVerFindFileW oVerFindFileW = nullptr;
static tVerInstallFileA oVerInstallFileA = nullptr;
static tVerInstallFileW oVerInstallFileW = nullptr;
static tVerLanguageNameA oVerLanguageNameA = nullptr;
static tVerLanguageNameW oVerLanguageNameW = nullptr;
static tVerQueryValueA oVerQueryValueA = nullptr;
static tVerQueryValueW oVerQueryValueW = nullptr;

// --- MinHook Related Globals & Definitions ---
typedef DWORD (WINAPI *tWaitForSingleObjectEx)(HANDLE hHandle, DWORD dwMilliseconds, BOOL bAlertable);

static tWaitForSingleObjectEx pfnOriginalWaitForSingleObjectEx = nullptr; // Original WSOEx
static uintptr_t g_gameModuleBase = 0; // Base address of BorderlandsGOTY.exe
// RVA of the instruction *after* the problematic 'call KERNELBASE!WaitForSingleObjectEx'
// The call itself is at RVA_MainThread_WSOEx_ReturnSite - call_instruction_size (e.g., -6 for FF15 IAT call)
static constexpr uintptr_t RVA_MainThread_WSOEx_ReturnSite = 0x1F6B90;
static constexpr DWORD PATCHED_TIMEOUT_MS = 1; // Timeout to apply for the fix

// --- Utility Functions ---
#ifdef PROXY_DEBUG_LOGGING
static void FileLog(const char* message) {
    // Simple logging to a file. Consider making the path configurable or disabling in release builds.
    const WCHAR logPath[] = L"C:\\temp\\borderlands_proxy_log.txt"; // Consolidated log file name
    HANDLE hFile = CreateFileW(logPath, FILE_APPEND_DATA, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        SYSTEMTIME st;
        GetLocalTime(&st);
        char timeBuf[128];
        char fullMessage[1024];
        DWORD bytesWritten;

        wsprintfA(timeBuf, "[%04d-%02d-%02d %02d:%02d:%02d.%03d - TID: %lu] ",
                           st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds, GetCurrentThreadId());
        lstrcpyA(fullMessage, timeBuf);
        lstrcatA(fullMessage, message);
        lstrcatA(fullMessage, "\r\n");
        WriteFile(hFile, fullMessage, lstrlenA(fullMessage), &bytesWritten, nullptr);
        CloseHandle(hFile);
    }
}
#else
// Define an empty FileLog macro when logging is disabled to avoid #ifdefs everywhere else
#define FileLog(message) ((void)0)
#endif

// --- Detour Function ---
DWORD WINAPI DetourWaitForSingleObjectEx_ApplyFix(HANDLE hHandle, DWORD dwMilliseconds, BOOL bAlertable) {
    DWORD new_dwMilliseconds = dwMilliseconds;

    if (g_gameModuleBase != 0) {
        void *returnAddress = NULL;
#if defined(_MSC_VER)
            returnAddress = _ReturnAddress();
#elif defined(__GNUC__) || defined(__clang__)
        returnAddress = __builtin_return_address(0);
#endif

        if (returnAddress) {
            uintptr_t returnRVA = (uintptr_t) returnAddress - g_gameModuleBase;

            // Check if this is the specific WSOEx call causing the hang
            if (returnRVA == RVA_MainThread_WSOEx_ReturnSite && dwMilliseconds == INFINITE) {
                new_dwMilliseconds = PATCHED_TIMEOUT_MS; // Apply the fix
#ifdef PROXY_DEBUG_LOGGING
                char logBuffer[256];
                wsprintfA(logBuffer, "DetourWSOEx: Patched INFINITE timeout to %lums for call returning to RVA 0x%p",
                          new_dwMilliseconds, (void*)returnRVA);
                FileLog(logBuffer);
#endif
            }
        }
    }
    // Call the original function with potentially modified timeout
    return pfnOriginalWaitForSingleObjectEx(hHandle, new_dwMilliseconds, bAlertable);
}

// --- Initialization and Uninitialization ---
BOOL LoadOriginalVersionDll() {
    WCHAR systemPath[MAX_PATH];
    if (GetSystemDirectoryW(systemPath, MAX_PATH) == 0) {
        FileLog("Error: GetSystemDirectoryW failed."); // This will compile out if PROXY_DEBUG_LOGGING is not defined
        return FALSE;
    }
    lstrcatW(systemPath, L"\\version.dll");
    g_hRealVersionDll = LoadLibraryW(systemPath);
    if (!g_hRealVersionDll) {
        FileLog("Error: Failed to load real version.dll."); // This will compile out
        return FALSE;
    }

    // Get addresses of all original functions
    oGetFileVersionInfoA = (tGetFileVersionInfoA) GetProcAddress(g_hRealVersionDll, "GetFileVersionInfoA");
    oGetFileVersionInfoByHandle = (tGetFileVersionInfoByHandle) GetProcAddress(
        g_hRealVersionDll, "GetFileVersionInfoByHandle"); // Keep if it was intended, though non-standard.
    oGetFileVersionInfoExA = (tGetFileVersionInfoExA) GetProcAddress(g_hRealVersionDll, "GetFileVersionInfoExA");
    oGetFileVersionInfoExW = (tGetFileVersionInfoExW) GetProcAddress(g_hRealVersionDll, "GetFileVersionInfoExW");
    oGetFileVersionInfoSizeA = (tGetFileVersionInfoSizeA) GetProcAddress(g_hRealVersionDll, "GetFileVersionInfoSizeA");
    oGetFileVersionInfoSizeExA = (tGetFileVersionInfoSizeExA) GetProcAddress(
        g_hRealVersionDll, "GetFileVersionInfoSizeExA");
    oGetFileVersionInfoSizeExW = (tGetFileVersionInfoSizeExW) GetProcAddress(
        g_hRealVersionDll, "GetFileVersionInfoSizeExW");
    oGetFileVersionInfoSizeW = (tGetFileVersionInfoSizeW) GetProcAddress(g_hRealVersionDll, "GetFileVersionInfoSizeW");
    oGetFileVersionInfoW = (tGetFileVersionInfoW) GetProcAddress(g_hRealVersionDll, "GetFileVersionInfoW");
    oVerFindFileA = (tVerFindFileA) GetProcAddress(g_hRealVersionDll, "VerFindFileA");
    oVerFindFileW = (tVerFindFileW) GetProcAddress(g_hRealVersionDll, "VerFindFileW");
    oVerInstallFileA = (tVerInstallFileA) GetProcAddress(g_hRealVersionDll, "VerInstallFileA");
    oVerInstallFileW = (tVerInstallFileW) GetProcAddress(g_hRealVersionDll, "VerInstallFileW");
    oVerLanguageNameA = (tVerLanguageNameA) GetProcAddress(g_hRealVersionDll, "VerLanguageNameA");
    oVerLanguageNameW = (tVerLanguageNameW) GetProcAddress(g_hRealVersionDll, "VerLanguageNameW");
    oVerQueryValueA = (tVerQueryValueA) GetProcAddress(g_hRealVersionDll, "VerQueryValueA");
    oVerQueryValueW = (tVerQueryValueW) GetProcAddress(g_hRealVersionDll, "VerQueryValueW");

    // Check if a representative function pointer is loaded
    if (!oGetFileVersionInfoSizeW) {
        // Example check
        FileLog("Error: Failed to get one or more GetProcAddress for version.dll functions."); // This will compile out
        FreeLibrary(g_hRealVersionDll);
        g_hRealVersionDll = nullptr;
        return FALSE;
    }
    return TRUE;
}

BOOL InitializeHooks() {
    FileLog("InitializeHooks: Starting initialization (v5.0.1)."); // This will compile out

    if (!LoadOriginalVersionDll()) {
        return FALSE; // Error logged in LoadOriginalVersionDll
    }
    FileLog("InitializeHooks: Real version.dll functions mapped."); // This will compile out

    g_gameModuleBase = (uintptr_t) GetModuleHandleW(L"BorderlandsGOTY.exe");
    if (!g_gameModuleBase) {
        // Fallback if specific name fails, though less reliable if multiple .exes
        g_gameModuleBase = (uintptr_t) GetModuleHandleW(nullptr);
    }
    if (!g_gameModuleBase) {
        FileLog("InitializeHooks: CRITICAL Error! Game module base not found."); // This will compile out
        return FALSE;
    }
#ifdef PROXY_DEBUG_LOGGING
    char buffer[128];
    wsprintfA(buffer, "InitializeHooks: Game module base: 0x%p", (void*)g_gameModuleBase);
    FileLog(buffer);
#endif

    if (MH_Initialize() != MH_OK) {
        FileLog("InitializeHooks: MH_Initialize failed."); // This will compile out
        return FALSE;
    }
    FileLog("InitializeHooks: MinHook initialized."); // This will compile out

    LPVOID pTargetWSOEx = GetProcAddress(GetModuleHandleW(L"KernelBase.dll"), "WaitForSingleObjectEx");
    if (!pTargetWSOEx) {
        // Fallback for older systems if KernelBase.dll doesn't have it (unlikely for modern Windows)
        pTargetWSOEx = GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "WaitForSingleObjectEx");
    }
    if (!pTargetWSOEx) {
        FileLog("InitializeHooks: Failed to get address of WaitForSingleObjectEx."); // This will compile out
        MH_Uninitialize();
        return FALSE;
    }

    if (MH_CreateHook(pTargetWSOEx, &DetourWaitForSingleObjectEx_ApplyFix,
                      (LPVOID *) &pfnOriginalWaitForSingleObjectEx) != MH_OK) {
        FileLog("InitializeHooks: MH_CreateHook for WaitForSingleObjectEx failed."); // This will compile out
        MH_Uninitialize();
        return FALSE;
    }
    if (MH_EnableHook(pTargetWSOEx) != MH_OK) {
        FileLog("InitializeHooks: MH_EnableHook for WaitForSingleObjectEx failed."); // This will compile out
        MH_RemoveHook(pTargetWSOEx); // Attempt to clean up partial hook
        MH_Uninitialize();
        return FALSE;
    }
    FileLog("InitializeHooks: WaitForSingleObjectEx hook enabled and patch active."); // This will compile out
    FileLog("InitializeHooks: Initialization successful."); // This will compile out
    return TRUE;
}

void UninitializeHooks() {
    FileLog("UninitializeHooks: Starting uninitialization.");
    LPVOID pTargetWSOEx = NULL; // Function-scoped variable, as in original

    // Log if the hook was never properly set up.
    if (!pfnOriginalWaitForSingleObjectEx) {
        FileLog("UninitializeHooks: WSOEx hook was not set up (pfnOriginal is NULL).");
    }

    // Attempt to unhook only if pfnOriginalWaitForSingleObjectEx indicates a hook was made.
    if (pfnOriginalWaitForSingleObjectEx) {
        // Attempt to get the address of the function we hooked.
        pTargetWSOEx = GetProcAddress(GetModuleHandleW(L"KernelBase.dll"), "WaitForSingleObjectEx");
        if (!pTargetWSOEx) { // Fallback
            pTargetWSOEx = GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "WaitForSingleObjectEx");
        }

        // If we still couldn't get pTargetWSOEx after trying, log the specific failure.
        // This happens only if pfnOriginalWaitForSingleObjectEx was true.
        if (!pTargetWSOEx) {
            FileLog("UninitializeHooks: Could not get WSOEx address for unhooking (already unhooked or system error).");
        }

        // If pTargetWSOEx was successfully obtained, perform the unhook.
        // This also only happens if pfnOriginalWaitForSingleObjectEx was true and pTargetWSOEx is now valid.
        if (pTargetWSOEx) {
            MH_DisableHook(pTargetWSOEx);
            MH_RemoveHook(pTargetWSOEx);
            FileLog("UninitializeHooks: WaitForSingleObjectEx hook removed.");
        }
    }

    if (MH_Uninitialize() == MH_OK) {
        FileLog("UninitializeHooks: MinHook uninitialized successfully.");
    } else {
        FileLog("UninitializeHooks: MH_Uninitialize reported an issue (e.g., not initialized or already uninitialized).");
    }

    if (g_hRealVersionDll) {
        FreeLibrary(g_hRealVersionDll);
        g_hRealVersionDll = nullptr;
        FileLog("UninitializeHooks: Real version.dll freed.");
    }

    FileLog("UninitializeHooks: Cleanup complete.");
}

// --- DllMain ---
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(hModule); // Optimization
            if (!InitializeHooks()) {
                FileLog("DllMain: InitializeHooks FAILED during DLL_PROCESS_ATTACH."); // This will compile out
                // Optionally, could return FALSE here if init failure is critical for proxy to load.
            }
            break;
        case DLL_PROCESS_DETACH:
            UninitializeHooks();
            break;
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
            // Do nothing for thread attach/detach
            break;
        default:
            // Handle any other unexpected reasons
#ifdef PROXY_DEBUG_LOGGING
            char logBuffer[128];
            wsprintfA(logBuffer, "DllMain: Unhandled ul_reason_for_call: %lu", ul_reason_for_call);
            FileLog(logBuffer);
#endif
            break;
    }
    return TRUE;
}

// --- Exported Stub Functions for version.dll ---
#ifdef __cplusplus
extern "C" {
#endif

WINBOOL WINAPI GetFileVersionInfoA(LPCSTR lptstrFilename, DWORD dwHandle, DWORD dwLen, LPVOID lpData) {
    if (oGetFileVersionInfoA) return oGetFileVersionInfoA(lptstrFilename, dwHandle, dwLen, lpData);
    SetLastError(ERROR_PROC_NOT_FOUND);
    return FALSE;
}

BOOL WINAPI GetFileVersionInfoByHandle(DWORD dwFlags, LPCWSTR lpszFileName, DWORD dwHandle, DWORD dwLen,
                                       LPVOID lpData) {
    if (oGetFileVersionInfoByHandle) return oGetFileVersionInfoByHandle(dwFlags, lpszFileName, dwHandle, dwLen, lpData);
    SetLastError(ERROR_PROC_NOT_FOUND);
    return FALSE;
}

BOOL WINAPI GetFileVersionInfoExA(DWORD dwFlags, LPCSTR lpszFileName, DWORD dwHandle, DWORD dwLen, LPVOID lpData) {
    if (oGetFileVersionInfoExA) return oGetFileVersionInfoExA(dwFlags, lpszFileName, dwHandle, dwLen, lpData);
    SetLastError(ERROR_PROC_NOT_FOUND);
    return FALSE;
}

BOOL WINAPI GetFileVersionInfoExW(DWORD dwFlags, LPCWSTR lpszFileName, DWORD dwHandle, DWORD dwLen, LPVOID lpData) {
    if (oGetFileVersionInfoExW) return oGetFileVersionInfoExW(dwFlags, lpszFileName, dwHandle, dwLen, lpData);
    SetLastError(ERROR_PROC_NOT_FOUND);
    return FALSE;
}

DWORD WINAPI GetFileVersionInfoSizeA(LPCSTR lptstrFilename, LPDWORD lpdwHandle) {
    if (oGetFileVersionInfoSizeA) return oGetFileVersionInfoSizeA(lptstrFilename, lpdwHandle);
    if (lpdwHandle) *lpdwHandle = 0;
    SetLastError(ERROR_PROC_NOT_FOUND);
    return 0;
}

DWORD WINAPI GetFileVersionInfoSizeExA(DWORD dwFlags, LPCSTR lpszFileName, LPDWORD lpdwHandle) {
    if (oGetFileVersionInfoSizeExA) return oGetFileVersionInfoSizeExA(dwFlags, lpszFileName, lpdwHandle);
    if (lpdwHandle) *lpdwHandle = 0;
    SetLastError(ERROR_PROC_NOT_FOUND);
    return 0;
}

DWORD WINAPI GetFileVersionInfoSizeExW(DWORD dwFlags, LPCWSTR lpszFileName, LPDWORD lpdwHandle) {
    if (oGetFileVersionInfoSizeExW) return oGetFileVersionInfoSizeExW(dwFlags, lpszFileName, lpdwHandle);
    if (lpdwHandle) *lpdwHandle = 0;
    SetLastError(ERROR_PROC_NOT_FOUND);
    return 0;
}

DWORD WINAPI GetFileVersionInfoSizeW(LPCWSTR lptstrFilename, LPDWORD lpdwHandle) {
    if (oGetFileVersionInfoSizeW) return oGetFileVersionInfoSizeW(lptstrFilename, lpdwHandle);
    if (lpdwHandle) *lpdwHandle = 0;
    SetLastError(ERROR_PROC_NOT_FOUND);
    return 0;
}

WINBOOL WINAPI GetFileVersionInfoW(LPCWSTR lptstrFilename, DWORD dwHandle, DWORD dwLen, LPVOID lpData) {
    if (oGetFileVersionInfoW) return oGetFileVersionInfoW(lptstrFilename, dwHandle, dwLen, lpData);
    SetLastError(ERROR_PROC_NOT_FOUND);
    return FALSE;
}

DWORD WINAPI VerFindFileA(DWORD uFlags, LPSTR szFileName, LPSTR szWinDir, LPSTR szAppDir, LPSTR szCurDir,
                          PUINT lpuCurDirLen, LPSTR szDestDir, PUINT lpuDestDirLen) {
    if (oVerFindFileA) return oVerFindFileA(uFlags, szFileName, szWinDir, szAppDir, szCurDir, lpuCurDirLen, szDestDir,
                                            lpuDestDirLen);
    SetLastError(ERROR_PROC_NOT_FOUND);
    return 0;
}

DWORD WINAPI VerFindFileW(DWORD uFlags, LPWSTR szFileName, LPWSTR szWinDir, LPWSTR szAppDir, LPWSTR szCurDir,
                          PUINT lpuCurDirLen, LPWSTR szDestDir, PUINT lpuDestDirLen) {
    if (oVerFindFileW) return oVerFindFileW(uFlags, szFileName, szWinDir, szAppDir, szCurDir, lpuCurDirLen, szDestDir,
                                            lpuDestDirLen);
    SetLastError(ERROR_PROC_NOT_FOUND);
    return 0;
}

DWORD WINAPI VerInstallFileA(DWORD uFlags, LPSTR szSrcFileName, LPSTR szDestFileName, LPSTR szSrcDir, LPSTR szDestDir,
                             LPSTR szCurDir, LPSTR szTmpFile, PUINT lpuTmpFileLen) {
    if (oVerInstallFileA) return oVerInstallFileA(uFlags, szSrcFileName, szDestFileName, szSrcDir, szDestDir, szCurDir,
                                                  szTmpFile, lpuTmpFileLen);
    SetLastError(ERROR_PROC_NOT_FOUND);
    return 0;
}

DWORD WINAPI VerInstallFileW(DWORD uFlags, LPWSTR szSrcFileName, LPWSTR szDestFileName, LPWSTR szSrcDir,
                             LPWSTR szDestDir, LPWSTR szCurDir, LPWSTR szTmpFile, PUINT lpuTmpFileLen) {
    if (oVerInstallFileW) return oVerInstallFileW(uFlags, szSrcFileName, szDestFileName, szSrcDir, szDestDir, szCurDir,
                                                  szTmpFile, lpuTmpFileLen);
    SetLastError(ERROR_PROC_NOT_FOUND);
    return 0;
}

DWORD WINAPI VerLanguageNameA(DWORD wLang, LPSTR szLang, DWORD nSize) {
    if (oVerLanguageNameA) return oVerLanguageNameA(wLang, szLang, nSize);
    if (nSize > 0 && szLang) szLang[0] = '\0';
    SetLastError(ERROR_PROC_NOT_FOUND);
    return 0;
}

DWORD WINAPI VerLanguageNameW(DWORD wLang, LPWSTR szLang, DWORD nSize) {
    if (oVerLanguageNameW) return oVerLanguageNameW(wLang, szLang, nSize);
    if (nSize > 0 && szLang) szLang[0] = L'\0';
    SetLastError(ERROR_PROC_NOT_FOUND);
    return 0;
}

BOOL WINAPI VerQueryValueA(LPCVOID pBlock, LPCSTR lpSubBlock, LPVOID *lplpBuffer, PUINT puLen) {
    if (oVerQueryValueA) return oVerQueryValueA(pBlock, lpSubBlock, lplpBuffer, puLen);
    if (lplpBuffer) *lplpBuffer = NULL;
    if (puLen) *puLen = 0;
    SetLastError(ERROR_PROC_NOT_FOUND);
    return FALSE;
}

BOOL WINAPI VerQueryValueW(LPCVOID pBlock, LPCWSTR lpSubBlock, LPVOID *lplpBuffer, PUINT puLen) {
    if (oVerQueryValueW) return oVerQueryValueW(pBlock, lpSubBlock, lplpBuffer, puLen);
    if (lplpBuffer) *lplpBuffer = NULL;
    if (puLen) *puLen = 0;
    SetLastError(ERROR_PROC_NOT_FOUND);
    return FALSE;
}

#ifdef __cplusplus
}
#endif
