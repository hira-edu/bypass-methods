#include "../../include/com_hooks/factory_hooks.h"
#include "../../include/dx_hook_core.h"
#include "../../include/hooks/com_interface_wrapper.h"
#include <cstdint>
#include <limits>
#include <iostream>

namespace UndownUnlock {
namespace DXHook {

// Initialize the singleton instance
FactoryHooks* FactoryHooks::s_instance = nullptr;

FactoryHooks::FactoryHooks()
    : m_originalCreateDXGIFactory(nullptr)
    , m_originalCreateDXGIFactory1(nullptr)
    , m_originalCreateDXGIFactory2(nullptr)
    , m_originalD3D11CreateDevice(nullptr)
    , m_originalD3D11CreateDeviceAndSwapChain(nullptr) {
}

FactoryHooks::~FactoryHooks() {
    Shutdown();
}

FactoryHooks& FactoryHooks::GetInstance() {
    if (!s_instance) {
        s_instance = new FactoryHooks();
    }
    return *s_instance;
}

bool FactoryHooks::Initialize() {
    std::cout << "Initializing DXGI Factory hooks..." << std::endl;
    
    // Install hooks for factory creation functions
    bool factory = InstallHook(
        reinterpret_cast<void**>(&m_originalCreateDXGIFactory),
        reinterpret_cast<void*>(HookCreateDXGIFactory),
        "dxgi.dll", "CreateDXGIFactory"
    );
    
    bool factory1 = InstallHook(
        reinterpret_cast<void**>(&m_originalCreateDXGIFactory1),
        reinterpret_cast<void*>(HookCreateDXGIFactory1),
        "dxgi.dll", "CreateDXGIFactory1"
    );
    
    bool factory2 = InstallHook(
        reinterpret_cast<void**>(&m_originalCreateDXGIFactory2),
        reinterpret_cast<void*>(HookCreateDXGIFactory2),
        "dxgi.dll", "CreateDXGIFactory2"
    );
    
    // Install hooks for device creation functions
    bool device = InstallHook(
        reinterpret_cast<void**>(&m_originalD3D11CreateDevice),
        reinterpret_cast<void*>(HookD3D11CreateDevice),
        "d3d11.dll", "D3D11CreateDevice"
    );
    
    bool deviceAndSwapChain = InstallHook(
        reinterpret_cast<void**>(&m_originalD3D11CreateDeviceAndSwapChain),
        reinterpret_cast<void*>(HookD3D11CreateDeviceAndSwapChain),
        "d3d11.dll", "D3D11CreateDeviceAndSwapChain"
    );
    
    // Log the results
    std::cout << "CreateDXGIFactory hook: " << (factory ? "SUCCESS" : "FAILED") << std::endl;
    std::cout << "CreateDXGIFactory1 hook: " << (factory1 ? "SUCCESS" : "FAILED") << std::endl;
    std::cout << "CreateDXGIFactory2 hook: " << (factory2 ? "SUCCESS" : "FAILED") << std::endl;
    std::cout << "D3D11CreateDevice hook: " << (device ? "SUCCESS" : "FAILED") << std::endl;
    std::cout << "D3D11CreateDeviceAndSwapChain hook: " << (deviceAndSwapChain ? "SUCCESS" : "FAILED") << std::endl;
    
    return factory || factory1 || factory2 || device || deviceAndSwapChain;
}

void FactoryHooks::Shutdown() {
    std::cout << "Shutting down DXGI Factory hooks..." << std::endl;
    
    // Clear tracked interfaces
    std::lock_guard<std::mutex> lock(m_interfaceMutex);
    m_trackedInterfaces.clear();
    m_originalCreateSwapChain.clear();
}

bool FactoryHooks::HookFactoryCreateSwapChain(IDXGIFactory* pFactory) {
    if (!pFactory) {
        return false;
    }
    
    // Get the vtable from the factory
    void** vtable = *reinterpret_cast<void***>(pFactory);
    if (!vtable) {
        return false;
    }
    
    // Store the original CreateSwapChain function (index 10 in IDXGIFactory vtable)
    CreateSwapChain_t originalFunc = reinterpret_cast<CreateSwapChain_t>(vtable[10]);
    m_originalCreateSwapChain[pFactory] = originalFunc;
    
    // Install our hook
    DWORD oldProtect;
    if (!VirtualProtect(&vtable[10], sizeof(void*), PAGE_EXECUTE_READWRITE, &oldProtect)) {
        std::cerr << "Failed to change memory protection for IDXGIFactory::CreateSwapChain" << std::endl;
        return false;
    }
    
    // Replace the function pointer
    vtable[10] = reinterpret_cast<void*>(FactoryCreateSwapChainHook);
    
    // Restore memory protection
    DWORD temp;
    VirtualProtect(&vtable[10], sizeof(void*), oldProtect, &temp);
    
    std::cout << "Hooked IDXGIFactory::CreateSwapChain at " << pFactory << std::endl;
    return true;
}

void* FactoryHooks::GetRealFunctionAddress(const char* moduleName, const char* functionName) {
    HMODULE hModule = GetModuleHandleA(moduleName);
    if (!hModule) {
        std::cerr << "Failed to get module handle for " << moduleName << std::endl;
        return nullptr;
    }
    
    void* funcAddr = GetProcAddress(hModule, functionName);
    if (!funcAddr) {
        std::cerr << "Failed to get address for " << functionName << " in " << moduleName << std::endl;
        return nullptr;
    }
    
    return funcAddr;
}

bool FactoryHooks::InstallHook(void** originalFunction, void* hookFunction, const char* moduleName, const char* functionName) {
    // Get the real function address
    void* realFunc = GetRealFunctionAddress(moduleName, functionName);
    if (!realFunc) {
        return false;
    }
    
    // Store the original function
    *originalFunction = realFunc;
    
    // Install the hook using VirtualProtect
    DWORD oldProtect;
    if (!VirtualProtect(realFunc, 5, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        std::cerr << "Failed to change memory protection for " << functionName << std::endl;
        return false;
    }
    
    // Create a relative jump to our hook function
    // Format: E9 xx xx xx xx (JMP rel32)
    auto source = reinterpret_cast<uintptr_t>(realFunc);
    auto target = reinterpret_cast<uintptr_t>(hookFunction);
    auto displacement = static_cast<int64_t>(target - source - 5);

    if (displacement < std::numeric_limits<int32_t>::min() ||
        displacement > std::numeric_limits<int32_t>::max()) {
        std::cerr << "Hook target too far for JMP rel32 when installing " << functionName << std::endl;
        DWORD temp;
        VirtualProtect(realFunc, 5, oldProtect, &temp);
        return false;
    }

    uint8_t* funcBytes = static_cast<uint8_t*>(realFunc);
    funcBytes[0] = 0xE9; // JMP opcode
    *reinterpret_cast<int32_t*>(&funcBytes[1]) = static_cast<int32_t>(displacement);
    
    // Restore the original protection
    DWORD temp;
    VirtualProtect(realFunc, 5, oldProtect, &temp);
    
    std::cout << "Installed hook for " << functionName << " in " << moduleName << std::endl;
    return true;
}

void FactoryHooks::TrackInterface(void* pInterface, const std::string& interfaceType) {
    if (!pInterface) return;
    
    std::lock_guard<std::mutex> lock(m_interfaceMutex);
    
    // Check if already tracked
    if (m_trackedInterfaces.find(pInterface) != m_trackedInterfaces.end()) {
        return;
    }
    
    // Track the new interface
    TrackedInterface tracked = {};
    tracked.pInterface = pInterface;
    tracked.interfaceType = interfaceType;
    tracked.refCount = 1; // Assume initial refcount is 1
    tracked.threadId = GetCurrentThreadId();
    
    m_trackedInterfaces[pInterface] = tracked;
    
    // If this is a factory, hook its CreateSwapChain method
    if (interfaceType == "IDXGIFactory" || interfaceType == "IDXGIFactory1" || interfaceType == "IDXGIFactory2") {
        HookFactoryCreateSwapChain(static_cast<IDXGIFactory*>(pInterface));
    }
    
    std::cout << "Tracking " << interfaceType << " at " << pInterface << std::endl;
}

void FactoryHooks::UntrackInterface(void* pInterface) {
    if (!pInterface) return;
    
    std::lock_guard<std::mutex> lock(m_interfaceMutex);
    
    auto it = m_trackedInterfaces.find(pInterface);
    if (it != m_trackedInterfaces.end()) {
        std::cout << "Untracking " << it->second.interfaceType << " at " << pInterface << std::endl;
        m_trackedInterfaces.erase(it);
    }
}

bool FactoryHooks::ValidateInterface(IUnknown* pInterface, REFIID riid) {
    if (!pInterface) return false;
    
    // Try to query the interface to verify it supports the requested interface
    IUnknown* pTemp = nullptr;
    HRESULT hr = pInterface->QueryInterface(riid, reinterpret_cast<void**>(&pTemp));
    
    if (SUCCEEDED(hr) && pTemp) {
        pTemp->Release();
        return true;
    }
    
    return false;
}

HRESULT WINAPI FactoryHooks::HookCreateDXGIFactory(REFIID riid, void** ppFactory) {
    FactoryHooks& instance = GetInstance();
    
    // Call the original function
    HRESULT hr = instance.m_originalCreateDXGIFactory(riid, ppFactory);
    
    if (SUCCEEDED(hr) && ppFactory && *ppFactory) {
        // Track the created factory
        instance.TrackInterface(*ppFactory, "IDXGIFactory");
        
        std::cout << "CreateDXGIFactory called, created factory at " << *ppFactory << std::endl;
    }
    
    return hr;
}

HRESULT WINAPI FactoryHooks::HookCreateDXGIFactory1(REFIID riid, void** ppFactory) {
    FactoryHooks& instance = GetInstance();
    
    // Call the original function
    HRESULT hr = instance.m_originalCreateDXGIFactory1(riid, ppFactory);
    
    if (SUCCEEDED(hr) && ppFactory && *ppFactory) {
        // Track the created factory
        instance.TrackInterface(*ppFactory, "IDXGIFactory1");
        
        std::cout << "CreateDXGIFactory1 called, created factory at " << *ppFactory << std::endl;
    }
    
    return hr;
}

HRESULT WINAPI FactoryHooks::HookCreateDXGIFactory2(UINT Flags, REFIID riid, void** ppFactory) {
    FactoryHooks& instance = GetInstance();
    
    // Call the original function
    HRESULT hr = instance.m_originalCreateDXGIFactory2(Flags, riid, ppFactory);
    
    if (SUCCEEDED(hr) && ppFactory && *ppFactory) {
        // Track the created factory
        instance.TrackInterface(*ppFactory, "IDXGIFactory2");
        
        std::cout << "CreateDXGIFactory2 called, created factory at " << *ppFactory << std::endl;
    }
    
    return hr;
}

HRESULT WINAPI FactoryHooks::HookD3D11CreateDevice(
    IDXGIAdapter* pAdapter, D3D_DRIVER_TYPE DriverType, HMODULE Software, UINT Flags,
    const D3D_FEATURE_LEVEL* pFeatureLevels, UINT FeatureLevels, UINT SDKVersion,
    ID3D11Device** ppDevice, D3D_FEATURE_LEVEL* pFeatureLevel, ID3D11DeviceContext** ppImmediateContext) {
    
    FactoryHooks& instance = GetInstance();
    
    // Call the original function
    HRESULT hr = instance.m_originalD3D11CreateDevice(
        pAdapter, DriverType, Software, Flags, pFeatureLevels, FeatureLevels, SDKVersion,
        ppDevice, pFeatureLevel, ppImmediateContext
    );
    
    if (SUCCEEDED(hr)) {
        // Track the created device and context
        if (ppDevice && *ppDevice) {
            instance.TrackInterface(*ppDevice, "ID3D11Device");
            std::cout << "D3D11CreateDevice called, created device at " << *ppDevice << std::endl;
        }
        
        if (ppImmediateContext && *ppImmediateContext) {
            instance.TrackInterface(*ppImmediateContext, "ID3D11DeviceContext");
            std::cout << "D3D11CreateDevice called, created device context at " << *ppImmediateContext << std::endl;
        }
    }
    
    return hr;
}

HRESULT WINAPI FactoryHooks::HookD3D11CreateDeviceAndSwapChain(
    IDXGIAdapter* pAdapter, D3D_DRIVER_TYPE DriverType, HMODULE Software, UINT Flags,
    const D3D_FEATURE_LEVEL* pFeatureLevels, UINT FeatureLevels, UINT SDKVersion,
    const DXGI_SWAP_CHAIN_DESC* pSwapChainDesc, IDXGISwapChain** ppSwapChain,
    ID3D11Device** ppDevice, D3D_FEATURE_LEVEL* pFeatureLevel, ID3D11DeviceContext** ppImmediateContext) {
    
    FactoryHooks& instance = GetInstance();
    
    // Call the original function
    HRESULT hr = instance.m_originalD3D11CreateDeviceAndSwapChain(
        pAdapter, DriverType, Software, Flags, pFeatureLevels, FeatureLevels, SDKVersion,
        pSwapChainDesc, ppSwapChain, ppDevice, pFeatureLevel, ppImmediateContext
    );
    
    if (SUCCEEDED(hr)) {
        // Track the created swap chain, device, and context
        if (ppSwapChain && *ppSwapChain) {
            instance.TrackInterface(*ppSwapChain, "IDXGISwapChain");
            
            // Try to hook the swap chain
            SwapChainHook& swapChainHook = *DXHookCore::GetInstance().m_swapChainHook.get();
            swapChainHook.InstallHooks(*ppSwapChain);
            
            std::cout << "D3D11CreateDeviceAndSwapChain called, created swap chain at " << *ppSwapChain << std::endl;
        }
        
        if (ppDevice && *ppDevice) {
            instance.TrackInterface(*ppDevice, "ID3D11Device");
            std::cout << "D3D11CreateDeviceAndSwapChain called, created device at " << *ppDevice << std::endl;
        }
        
        if (ppImmediateContext && *ppImmediateContext) {
            instance.TrackInterface(*ppImmediateContext, "ID3D11DeviceContext");
            std::cout << "D3D11CreateDeviceAndSwapChain called, created device context at " << *ppImmediateContext << std::endl;
        }
    }
    
    return hr;
}

HRESULT STDMETHODCALLTYPE FactoryHooks::FactoryCreateSwapChainHook(
    IDXGIFactory* pFactory, IUnknown* pDevice, DXGI_SWAP_CHAIN_DESC* pDesc, IDXGISwapChain** ppSwapChain) {
    
    FactoryHooks& instance = GetInstance();
    
    // Find the original function
    auto it = instance.m_originalCreateSwapChain.find(pFactory);
    if (it == instance.m_originalCreateSwapChain.end()) {
        std::cerr << "Error: Original CreateSwapChain not found for factory " << pFactory << std::endl;
        return E_FAIL;
    }
    
    CreateSwapChain_t originalFunc = it->second;
    
    std::cout << "IDXGIFactory::CreateSwapChain called" << std::endl;
    
    // Optionally modify the swap chain description here
    // For example, enabling the BGRA format for better compatibility:
    // pDesc->BufferDesc.Format = DXGI_FORMAT_B8G8R8A8_UNORM;
    
    // Call the original method
    HRESULT hr = originalFunc(pFactory, pDevice, pDesc, ppSwapChain);
    
    if (SUCCEEDED(hr) && ppSwapChain && *ppSwapChain) {
        // Track the newly created swap chain
        instance.TrackInterface(*ppSwapChain, "IDXGISwapChain");
        
        // Hook the swap chain
        SwapChainHook& swapChainHook = *DXHookCore::GetInstance().m_swapChainHook.get();
        swapChainHook.InstallHooks(*ppSwapChain);
        
        std::cout << "Created and hooked SwapChain through IDXGIFactory::CreateSwapChain" << std::endl;
    }
    
    return hr;
}

} // namespace DXHook
} // namespace UndownUnlock 
