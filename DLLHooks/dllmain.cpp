#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <psapi.h> // For EnumWindows, GetWindowThreadProcessId, GetCurrentProcessId if FindMainWindow is kept here
#include <iostream>
#include <tlhelp32.h> // Not strictly needed after refactoring if process functions are also moved
#include <cstdlib>
#include <tchar.h> // For _TCHAR related things, might not be needed
#include <thread>
#include <vector> // Included for completeness, might not be directly used
#include <string> // Included for completeness
// #include <fstream> // Was present, probably for logging or other utilities not part of core hooking
// #include <GL/gl.h> // Was present, OpenGL related, not part of Windows API hooks
// #include <wincodec.h> // For WIC, not part of Windows API hooks
// #pragma comment(lib, "windowscodecs.lib") // For WIC

// Include the new hook manager system
// Adjust path as necessary based on project structure.
// Assuming DLLHooks is at the same level as 'include' and 'src' directories.
#include "../../include/hooks/new_hook_system.h"
#include "../../include/hooks/dx_hook_core.h" // For DirectXHookManager


// Global variables for hook state and parameters are now managed by WindowsApiHookManager
// or specific hook classes. e.g. WindowsApiHookManager::g_focusHWND

// All "MyFunction" detour implementations are now static methods within their respective hook classes
// (e.g., GetForegroundWindowHook::DetourGetForegroundWindow) in new_hook_system.cpp

// The originalBytes... arrays are now members of each individual Hook object.


// The InstallHook(), InstallFocus(), UninstallFocus(), UninstallHook() functions
// will be replaced by calls to WindowsApiHookManager.

void InitializeAllHooks() {
    std::cout << "DllMain: Initializing all hooks via WindowsApiHookManager..." << std::endl;
    WindowsApiHookManager::GetInstance().InitializeAndInstallHooks();
    // Potentially show a message box or log that hooks are set up by the new manager
    MessageBox(NULL, L"UndownUnlock Hooks Initialized (New System)", L"UndownUnlock", MB_OK);
}

void TeardownAllHooks() {
    std::cout << "DllMain: Tearing down all hooks via WindowsApiHookManager..." << std::endl;
    WindowsApiHookManager::GetInstance().UninstallAllHooks();
}

// Keyboard hook handle - kept for now, to be refactored later.
HHOOK hKeyboardHook = NULL;

// Keyboard hook callback
LRESULT CALLBACK KeyboardProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode == HC_ACTION) {
        PKBDLLHOOKSTRUCT p = (PKBDLLHOOKSTRUCT)lParam;
        if (wParam == WM_KEYDOWN) {
            switch (p->vkCode) {
            case VK_UP:
                std::cout << "Up arrow key pressed, installing focus hooks via manager." << std::endl;
                WindowsApiHookManager::GetInstance().InstallFocusControlHooks();
                break;
            case VK_DOWN:
                std::cout << "Down arrow key pressed, uninstalling focus hooks via manager." << std::endl;
                WindowsApiHookManager::GetInstance().UninstallFocusControlHooks();

                // Restore original behavior if parameters were stored by hooks (now in WindowsApiHookManager g_vars)
                // This part needs careful review as direct SetFocus/BringWindowToTop/SetWindowPos
                // might interfere with or be re-hooked if not handled carefully.
                // The new hook detours currently do not call original functions.
                // This logic might be better placed inside the UninstallFocusControlHooks or as a separate method.
                if (WindowsApiHookManager::g_focusHWND != NULL) {
                    // This call will be to the original SetFocus IF the hook is uninstalled.
                    // If SetFocus is ALSO a managed hook, this could call the detour or original.
                    // For now, assume it calls original after hooks are out.
                    SetFocus(WindowsApiHookManager::g_focusHWND);
                }
                if (WindowsApiHookManager::g_bringWindowToTopHWND != NULL) {
                    BringWindowToTop(WindowsApiHookManager::g_bringWindowToTopHWND);
                }
                if (WindowsApiHookManager::g_setWindowPosParams.hasBeenCalled) {
                     SetWindowPos(
                        WindowsApiHookManager::g_setWindowPosParams.hWnd,
                        WindowsApiHookManager::g_setWindowPosParams.hWndInsertAfter,
                        WindowsApiHookManager::g_setWindowPosParams.X,
                        WindowsApiHookManager::g_setWindowPosParams.Y,
                        WindowsApiHookManager::g_setWindowPosParams.cx,
                        WindowsApiHookManager::g_setWindowPosParams.cy,
                        WindowsApiHookManager::g_setWindowPosParams.uFlags
                    );
                }
                std::cout << "Down arrow key: Restored focus/window state attempt." << std::endl;
                break;
            }
        }
    }
    return CallNextHookEx(hKeyboardHook, nCode, wParam, lParam);
}

// Keyboard hook setup thread function
void SetupKeyboardHookThread() {
    hKeyboardHook = SetWindowsHookEx(WH_KEYBOARD_LL, KeyboardProc, GetModuleHandle(NULL), 0);
    if (!hKeyboardHook) {
        std::cerr << "Failed to install keyboard hook. Error: " << GetLastError() << std::endl;
        return;
    }
    std::cout << "Keyboard hook installed." << std::endl;
    MSG msg;
    // Message loop for the keyboard hook thread
    while (GetMessage(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    std::cout << "Keyboard hook message loop terminating." << std::endl;
}


BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        std::cout << "DLL_PROCESS_ATTACH: Initializing UndownUnlock..." << std::endl;

        // Initialize and Install hooks using the new manager
        InitializeAllHooks(); // This initializes Windows API hooks

        // Initialize DirectX hooks
        std::cout << "DLL_PROCESS_ATTACH: Initializing DirectX hooks..." << std::endl;
        DirectXHookManager::GetInstance().Initialize();

        // Start the keyboard hook in a new thread
        // Consider managing this thread more robustly (e.g., storing thread handle, proper termination)
        std::thread(SetupKeyboardHookThread).detach();

        std::cout << "DLL_PROCESS_ATTACH: UndownUnlock initialization complete." << std::endl;
        break;

    case DLL_PROCESS_DETACH:
        std::cout << "DLL_PROCESS_DETACH: Shutting down UndownUnlock..." << std::endl;

        // Uninstall DirectX hooks first (if they might depend on API hooks or other systems)
        std::cout << "DLL_PROCESS_DETACH: Shutting down DirectX hooks..." << std::endl;
        DirectXHookManager::GetInstance().Shutdown();

        // Uninstall all Windows API hooks using the new manager
        TeardownAllHooks();

        // Uninstall the keyboard hook
        if (hKeyboardHook != nullptr) {
            if (UnhookWindowsHookEx(hKeyboardHook)) {
                std::cout << "Keyboard hook uninstalled successfully." << std::endl;
            } else {
                std::cerr << "Failed to uninstall keyboard hook. Error: " << GetLastError() << std::endl;
            }
            hKeyboardHook = nullptr;
        }
        // Signal the keyboard hook thread to terminate its message loop (if it's not already done)
        // This is tricky as PostThreadMessage might not work if the thread is already gone or stuck.
        // A more robust solution would use an event or a shared flag.
        // For now, relying on process termination to clean up the detached thread.

        std::cout << "DLL_PROCESS_DETACH: UndownUnlock shutdown complete." << std::endl;
        break;
    }
    return TRUE;
}
