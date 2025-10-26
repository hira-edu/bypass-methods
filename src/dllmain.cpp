#include <Windows.h>
#include <iostream>
#include <thread>
#include "../include/dx_hook_core.h"

// Global variables
HMODULE g_hModule = nullptr;
std::thread g_hookThread;
bool g_shutdown = false;

// Forward declarations
DWORD WINAPI HookThreadProc(LPVOID lpParam);

extern "C" {
    // DLL entry point
    BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
        switch (ul_reason_for_call) {
            case DLL_PROCESS_ATTACH:
            {
                // Store the module handle for later use
                g_hModule = hModule;
                
                // Disable thread notifications to reduce overhead
                DisableThreadLibraryCalls(hModule);
                
                // Create a console for debugging if needed
                #ifdef _DEBUG
                AllocConsole();
                FILE* dummy;
                freopen_s(&dummy, "CONOUT$", "w", stdout);
                freopen_s(&dummy, "CONOUT$", "w", stderr);
                #endif
                
                // Initialize logging
                std::cout << "UndownUnlock DirectX Hook DLL loaded" << std::endl;
                
                // Start the hook thread
                g_hookThread = std::thread(HookThreadProc, nullptr);
                
                break;
            }
            
            case DLL_PROCESS_DETACH:
            {
                // Signal the hook thread to exit
                g_shutdown = true;
                
                // Wait for the hook thread to exit
                if (g_hookThread.joinable()) {
                    g_hookThread.join();
                }
                
                // Shutdown the hook core
                UndownUnlock::DXHook::DXHookCore::Shutdown();
                
                // Clean up console if we created one
                #ifdef _DEBUG
                FreeConsole();
                #endif
                
                break;
            }
        }
        
        return TRUE;
    }
    
    // Export a simple test function
    __declspec(dllexport) bool IsHookActive() {
        return UndownUnlock::DXHook::DXHookCore::GetInstance().IsInitialized();
    }
}

// Hook thread main function
DWORD WINAPI HookThreadProc(LPVOID lpParam) {
    // Wait a bit for the application to initialize DirectX
    Sleep(1000);
    
    // Initialize the hook core
    if (!UndownUnlock::DXHook::DXHookCore::Initialize()) {
        std::cerr << "Failed to initialize DirectX hook core" << std::endl;
        return 1;
    }
    
    // Main loop - keep the thread alive and handle any ongoing tasks
    while (!g_shutdown) {
        // Sleep to avoid high CPU usage
        Sleep(100);
        
        // TODO: Add any periodic tasks here if needed
    }
    
    return 0;
} 
