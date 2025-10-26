#include "../../../include/hooks/hook_utils.h"
#include <psapi.h>

namespace UndownUnlock {
namespace WindowsHook {

bool HookUtils::InstallHook(void* targetFunction, void* hookFunction, BYTE* originalBytes) {
    if (!targetFunction || !hookFunction || !originalBytes) {
        return false;
    }

    DWORD oldProtect;
    // Save the original bytes for later restoration
    memcpy(originalBytes, targetFunction, 5);

    // Change memory protection to allow writing
    if (VirtualProtect(targetFunction, 5, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        // Write a JMP instruction (0xE9) followed by a relative address
        DWORD relativeAddress = static_cast<DWORD>(
            reinterpret_cast<uintptr_t>(hookFunction) -
            reinterpret_cast<uintptr_t>(targetFunction) - 5);
        *((BYTE*)targetFunction) = 0xE9;
        *((DWORD*)((BYTE*)targetFunction + 1)) = relativeAddress;

        // Restore the original memory protection
        VirtualProtect(targetFunction, 5, oldProtect, &oldProtect);
        return true;
    }

    return false;
}

bool HookUtils::RemoveHook(void* targetFunction, BYTE* originalBytes) {
    if (!targetFunction || !originalBytes) {
        return false;
    }

    DWORD oldProtect;
    // Change memory protection to allow writing
    if (VirtualProtect(targetFunction, 5, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        // Restore the original bytes
        memcpy(targetFunction, originalBytes, 5);

        // Restore the original memory protection
        VirtualProtect(targetFunction, 5, oldProtect, &oldProtect);
        return true;
    }

    return false;
}

HWND HookUtils::FindMainWindow() {
    HWND mainWindow = NULL;
    EnumWindows(EnumWindowsCallback, reinterpret_cast<LPARAM>(&mainWindow));
    return mainWindow;
}

// Helper function to determine if the window is a main window
BOOL IsMainWindow(HWND handle) {
    return GetWindow(handle, GW_OWNER) == (HWND)0 && IsWindowVisible(handle);
}

// Callback for EnumWindows that finds the main window of the current process
BOOL CALLBACK EnumWindowsCallback(HWND handle, LPARAM lParam) {
    DWORD processID = 0;
    GetWindowThreadProcessId(handle, &processID);
    
    if (GetCurrentProcessId() == processID && IsMainWindow(handle)) {
        // Stop enumeration if a main window is found, and return its handle
        *reinterpret_cast<HWND*>(lParam) = handle;
        return FALSE;
    }
    
    return TRUE;
}

} // namespace WindowsHook
} // namespace UndownUnlock 