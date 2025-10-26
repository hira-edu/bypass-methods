#include "../../include/dx_hook_core.h"
#include "../../include/signatures/dx_signatures.h"
#include "../../include/hooks/com_interface_wrapper.h"
#include "../../include/raii_wrappers.h"
#include "../../include/error_handler.h"
#include "../../include/performance_monitor.h"
#include "../../include/memory_tracker.h"
#include <iostream>
#include <Windows.h>

namespace UndownUnlock {
namespace DXHook {

using namespace UndownUnlock::Hooks;

// Static instance for callback from static hook methods
SwapChainHook* SwapChainHook::s_instance = nullptr;

SwapChainHook::SwapChainHook()
    : m_originalPresent(nullptr)
    , m_hookedVTable(nullptr)
    , m_hooksInstalled(false) {
    
    auto perfTimer = PerformanceMonitor::GetInstance().StartTimer("SwapChainHook::Constructor");
    auto memTracker = MemoryTracker::GetInstance().TrackAllocation("SwapChainHook", sizeof(SwapChainHook));
    
    // Store the instance for static method access
    s_instance = this;
    
    ErrorHandler::GetInstance().LogInfo("SwapChainHook", "Constructor called");
}

SwapChainHook::~SwapChainHook() {
    auto perfTimer = PerformanceMonitor::GetInstance().StartTimer("SwapChainHook::Destructor");
    
    // Remove hooks if still installed
    RemoveHooks();
    
    // Clear static instance
    if (s_instance == this) {
        s_instance = nullptr;
    }
    
    ErrorHandler::GetInstance().LogInfo("SwapChainHook", "Destructor called");
}

void** VTableHook::GetVTable(void* interfacePtr) {
    auto perfTimer = PerformanceMonitor::GetInstance().StartTimer("VTableHook::GetVTable");
    
    if (!interfacePtr) {
        ErrorHandler::GetInstance().LogError("VTableHook", "GetVTable called with null interface pointer", 
            ErrorSeverity::ERROR, ErrorCategory::INVALID_PARAMETER);
        return nullptr;
    }
    
    // The first member of a COM interface is a pointer to its vtable
    return *reinterpret_cast<void***>(interfacePtr);
}

void* VTableHook::HookVTableEntry(void** vtable, int index, void* hookFunction) {
    auto perfTimer = PerformanceMonitor::GetInstance().StartTimer("VTableHook::HookVTableEntry");
    auto errorContext = ErrorHandler::GetInstance().CreateContext("VTableHook::HookVTableEntry");
    
    if (!vtable || !hookFunction) {
        ErrorHandler::GetInstance().LogError("VTableHook", "HookVTableEntry called with null parameters", 
            ErrorSeverity::ERROR, ErrorCategory::INVALID_PARAMETER);
        return nullptr;
    }
    
    // Store the original function
    void* originalFunction = vtable[index];
    
    // Change the memory protection to allow writing
    DWORD oldProtect;
    if (!VirtualProtect(&vtable[index], sizeof(void*), PAGE_READWRITE, &oldProtect)) {
        ErrorHandler::GetInstance().LogError("VTableHook", "Failed to change memory protection for vtable entry", 
            ErrorSeverity::ERROR, ErrorCategory::SYSTEM);
        std::cerr << "Failed to change memory protection for vtable entry" << std::endl;
        return nullptr;
    }
    
    // Install the hook
    vtable[index] = hookFunction;
    
    // Restore memory protection
    DWORD temp;
    VirtualProtect(&vtable[index], sizeof(void*), oldProtect, &temp);
    
    ErrorHandler::GetInstance().LogInfo("VTableHook", "Successfully hooked vtable entry at index " + std::to_string(index));
    
    // Return the original function
    return originalFunction;
}

bool SwapChainHook::InstallHooks(void* interfacePtr) {
    auto perfTimer = PerformanceMonitor::GetInstance().StartTimer("SwapChainHook::InstallHooks");
    auto errorContext = ErrorHandler::GetInstance().CreateContext("SwapChainHook::InstallHooks");
    
    if (!interfacePtr || m_hooksInstalled) {
        ErrorHandler::GetInstance().LogError("SwapChainHook", "InstallHooks called with invalid parameters or hooks already installed", 
            ErrorSeverity::WARNING, ErrorCategory::INVALID_PARAMETER);
        return false;
    }
    
    // Get the vtable
    void** vtable = GetVTable(interfacePtr);
    if (!vtable) {
        ErrorHandler::GetInstance().LogError("SwapChainHook", "Failed to get SwapChain vtable", 
            ErrorSeverity::ERROR, ErrorCategory::HOOK);
        std::cerr << "Failed to get SwapChain vtable" << std::endl;
        return false;
    }
    
    // Store the vtable for unhooking later
    m_hookedVTable = vtable;
    
    // Determine the correct Present method offset based on the interface version
    auto offsetTimer = PerformanceMonitor::GetInstance().StartTimer("SwapChainHook::GetPresentOffset");
    int presentOffset = Signatures::SwapChain::GetPresentOffset(interfacePtr);
    if (presentOffset < 0) {
        ErrorHandler::GetInstance().LogError("SwapChainHook", "Failed to determine Present method offset", 
            ErrorSeverity::ERROR, ErrorCategory::HOOK);
        std::cerr << "Failed to determine Present method offset" << std::endl;
        return false;
    }
    
    ErrorHandler::GetInstance().LogInfo("SwapChainHook", "Detected SwapChain version with Present at offset " + std::to_string(presentOffset));
    std::cout << "Detected SwapChain version with Present at offset " << presentOffset << std::endl;
    
    // Install the hook for Present
    auto hookTimer = PerformanceMonitor::GetInstance().StartTimer("SwapChainHook::HookPresentMethod");
    m_originalPresent = reinterpret_cast<Present_t>(
        HookVTableEntry(vtable, presentOffset, reinterpret_cast<void*>(&SwapChainHook::HookPresent))
    );
    
    if (!m_originalPresent) {
        ErrorHandler::GetInstance().LogError("SwapChainHook", "Failed to hook Present method", 
            ErrorSeverity::ERROR, ErrorCategory::HOOK);
        std::cerr << "Failed to hook Present method" << std::endl;
        return false;
    }
    
    m_hooksInstalled = true;
    ErrorHandler::GetInstance().LogInfo("SwapChainHook", "Successfully installed SwapChain hooks");
    std::cout << "Successfully installed SwapChain hooks" << std::endl;
    
    return true;
}

void SwapChainHook::RemoveHooks() {
    auto perfTimer = PerformanceMonitor::GetInstance().StartTimer("SwapChainHook::RemoveHooks");
    auto errorContext = ErrorHandler::GetInstance().CreateContext("SwapChainHook::RemoveHooks");
    
    if (!m_hooksInstalled || !m_hookedVTable) {
        ErrorHandler::GetInstance().LogInfo("SwapChainHook", "RemoveHooks called but no hooks installed");
        return;
    }
    
    // Determine the correct Present method offset
    int presentOffset = 8; // Default for IDXGISwapChain
    
    // Restore the original Present function
    if (m_originalPresent) {
        HookVTableEntry(m_hookedVTable, presentOffset, reinterpret_cast<void*>(m_originalPresent));
    }
    
    m_originalPresent = nullptr;
    m_hookedVTable = nullptr;
    m_hooksInstalled = false;
    
    ErrorHandler::GetInstance().LogInfo("SwapChainHook", "Removed SwapChain hooks");
    std::cout << "Removed SwapChain hooks" << std::endl;
}

bool SwapChainHook::FindAndHookSwapChain() {
    auto perfTimer = PerformanceMonitor::GetInstance().StartTimer("SwapChainHook::FindAndHookSwapChain");
    auto errorContext = ErrorHandler::GetInstance().CreateContext("SwapChainHook::FindAndHookSwapChain");
    
    // This will attempt to create a D3D11 device and swap chain
    // to hook it directly rather than waiting for the application to create one
    
    // Create a temporary window for the swap chain
    auto windowTimer = PerformanceMonitor::GetInstance().StartTimer("SwapChainHook::CreateTempWindow");
    HWND tempWindow = CreateWindowExA(
        0, "STATIC", "Temp Window", WS_OVERLAPPEDWINDOW,
        0, 0, 100, 100, NULL, NULL, GetModuleHandleA(NULL), NULL
    );
    
    if (!tempWindow) {
        ErrorHandler::GetInstance().LogError("SwapChainHook", "Failed to create temporary window", 
            ErrorSeverity::ERROR, ErrorCategory::SYSTEM);
        std::cerr << "Failed to create temporary window" << std::endl;
        return false;
    }
    
    bool result = false;
    
    try {
        // Set up the swap chain description
        DXGI_SWAP_CHAIN_DESC swapChainDesc = {};
        swapChainDesc.BufferCount = 1;
        swapChainDesc.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
        swapChainDesc.BufferDesc.Width = 100;
        swapChainDesc.BufferDesc.Height = 100;
        swapChainDesc.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
        swapChainDesc.OutputWindow = tempWindow;
        swapChainDesc.SampleDesc.Count = 1;
        swapChainDesc.Windowed = TRUE;
        
        // Create the device and swap chain using RAII wrappers
        D3D11DeviceWrapper deviceWrapper;
        D3D11DeviceContextWrapper contextWrapper;
        DXGISwapChainWrapper swapChainWrapper;
        
        ID3D11Device* device = nullptr;
        ID3D11DeviceContext* context = nullptr;
        IDXGISwapChain* swapChain = nullptr;
        
        auto createTimer = PerformanceMonitor::GetInstance().StartTimer("SwapChainHook::CreateD3D11Device");
        HRESULT hr = D3D11CreateDeviceAndSwapChain(
            nullptr,                  // Default adapter
            D3D_DRIVER_TYPE_HARDWARE,
            nullptr,                  // No software renderer
            0,                       // Flags
            nullptr,                  // Feature levels
            0,                        // Number of feature levels
            D3D11_SDK_VERSION,
            &swapChainDesc,
            &swapChain,
            &device,
            nullptr,                  // Feature level
            &context
        );
        
        if (SUCCEEDED(hr) && swapChain) {
            // Wrap the interfaces for automatic cleanup
            deviceWrapper.Reset(device, true);
            contextWrapper.Reset(context, true);
            swapChainWrapper.Reset(swapChain, true);
            
            // Hook the swap chain
            result = InstallHooks(swapChainWrapper.Get());
            
            if (result) {
                ErrorHandler::GetInstance().LogInfo("SwapChainHook", "Successfully found and hooked swap chain");
            } else {
                ErrorHandler::GetInstance().LogError("SwapChainHook", "Failed to install hooks on found swap chain", 
                    ErrorSeverity::ERROR, ErrorCategory::HOOK);
            }
            
            // RAII wrappers automatically release interfaces when they go out of scope
        } else {
            ErrorHandler::GetInstance().LogError("SwapChainHook", "Failed to create D3D11 device and swap chain: " + std::to_string(hr), 
                ErrorSeverity::ERROR, ErrorCategory::SYSTEM);
            std::cerr << "Failed to create D3D11 device and swap chain: " << std::hex << hr << std::endl;
        }
    } catch (const std::exception& e) {
        ErrorHandler::GetInstance().LogError("SwapChainHook", "Exception in FindAndHookSwapChain: " + std::string(e.what()), 
            ErrorSeverity::ERROR, ErrorCategory::EXCEPTION);
        std::cerr << "Exception in FindAndHookSwapChain: " << e.what() << std::endl;
    }
    
    // Clean up the temporary window
    DestroyWindow(tempWindow);
    
    return result;
}

void SwapChainHook::SetPresentCallback(std::function<void(IDXGISwapChain*)> callback) {
    auto perfTimer = PerformanceMonitor::GetInstance().StartTimer("SwapChainHook::SetPresentCallback");
    
    m_presentCallback = callback;
    ErrorHandler::GetInstance().LogInfo("SwapChainHook", "Present callback set");
}

// Static hook function for Present
HRESULT STDMETHODCALLTYPE SwapChainHook::HookPresent(IDXGISwapChain* pSwapChain, UINT SyncInterval, UINT Flags) {
    auto perfTimer = PerformanceMonitor::GetInstance().StartTimer("SwapChainHook::HookPresent");
    
    // Make sure we have a valid instance
    if (!s_instance || !s_instance->m_originalPresent) {
        ErrorHandler::GetInstance().LogError("SwapChainHook", "HookPresent called with invalid instance or original function", 
            ErrorSeverity::ERROR, ErrorCategory::HOOK);
        return E_FAIL;
    }
    
    // Call the callback if set
    if (s_instance->m_presentCallback) {
        auto callbackTimer = PerformanceMonitor::GetInstance().StartTimer("SwapChainHook::PresentCallback");
        try {
            s_instance->m_presentCallback(pSwapChain);
        } catch (const std::exception& e) {
            ErrorHandler::GetInstance().LogError("SwapChainHook", "Exception in Present callback: " + std::string(e.what()), 
                ErrorSeverity::ERROR, ErrorCategory::EXCEPTION);
        }
    }
    
    // Call the original Present function
    auto originalTimer = PerformanceMonitor::GetInstance().StartTimer("SwapChainHook::OriginalPresent");
    HRESULT result = s_instance->m_originalPresent(pSwapChain, SyncInterval, Flags);
    
    return result;
}

} // namespace DXHook
} // namespace UndownUnlock 
