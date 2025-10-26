#pragma once

#include <Windows.h>
#include <d3d11.h>
#include <dxgi.h>
#include <dxgi1_2.h>
#include <vector>
#include <string>
#include <memory>
#include <mutex>
#include <atomic>
#include <functional>

#include "signatures/dx_signatures.h"

namespace UndownUnlock {
namespace DXHook {

// Forward declarations
class SwapChainHook;
class MemoryScanner;
class FrameExtractor;
class SharedMemoryTransport;
class FactoryHooks;
class ExamSignaturePatcher;

/**
 * @brief Supported secure exam vendors.
 */
enum class ExamVendor {
    Unknown = 0,
    LockDown,
    ProProctor,
    ETS,
    Prometric
};

/**
 * @brief Resolved signature match for a secure exam client.
 */
struct ExamSignatureMatch {
    std::string name;
    void* address{nullptr};
    std::string module;
    std::string context; // e.g., description/vendor detail
};

/**
 * @brief Core class that manages DirectX hooking operations
 */
class DXHookCore {
public:
    /**
     * @brief Initialize the DirectX hooking system
     * @return True if initialization succeeded, false otherwise
     */
    static bool Initialize();

    /**
     * @brief Shutdown and cleanup all hooks
     */
    static void Shutdown();

    /**
     * @brief Get the singleton instance
     * @return Reference to the singleton instance
     */
    static DXHookCore& GetInstance();

    /**
     * @brief Register a callback for when a new frame is captured
     * @param callback The function to call with captured frame data
     * @return A handle that can be used to unregister the callback
     */
    size_t RegisterFrameCallback(std::function<void(const void*, size_t, uint32_t, uint32_t)> callback);

    /**
     * @brief Unregister a previously registered callback
     * @param handle The handle returned from RegisterFrameCallback
     */
    void UnregisterFrameCallback(size_t handle);

    /**
     * @brief Check whether the hook core finished initialization.
     */
    bool IsInitialized() const;

    ExamVendor GetDetectedExamVendor() const;
    const std::vector<Signatures::SignaturePattern>& GetActiveExamSignatures() const;
    const std::vector<ExamSignatureMatch>& GetResolvedExamSignatures() const;

    // Make FactoryHooks a friend class so it can access private members
    friend class FactoryHooks;
    friend class ExamSignaturePatcher;

private:
    // Note: Tests can access private members through public methods

    // Private constructor for singleton
    DXHookCore();
    ~DXHookCore();

    // Prevent copying
    DXHookCore(const DXHookCore&) = delete;
    DXHookCore& operator=(const DXHookCore&) = delete;

    // Implementation details
    std::unique_ptr<SwapChainHook> m_swapChainHook;
    std::unique_ptr<MemoryScanner> m_memoryScanner;
    std::unique_ptr<FrameExtractor> m_frameExtractor;
    std::unique_ptr<SharedMemoryTransport> m_sharedMemory;

    std::mutex m_callbackMutex;
    std::vector<std::function<void(const void*, size_t, uint32_t, uint32_t)>> m_frameCallbacks;
    std::atomic<bool> m_initialized;
    static DXHookCore* s_instance;

    void InitializeExamSignatures();
    ExamVendor DetectExamVendor() const;
    std::string GetProcessImageName() const;
    std::string DescribeExamVendor(ExamVendor vendor) const;

    ExamVendor m_examVendor;
    bool m_examSignaturesReady;
    bool m_examPatchesApplied;
    std::vector<Signatures::SignaturePattern> m_activeExamSignatures;
    std::vector<ExamSignatureMatch> m_resolvedExamSignatures;
};

/**
 * @brief Interface for vtable hooking system for COM objects
 */
class VTableHook {
public:
    virtual ~VTableHook() = default;

    /**
     * @brief Install hooks for the specified interface
     * @param interfacePtr Pointer to the COM interface to hook
     * @return True if hooks were successfully installed
     */
    virtual bool InstallHooks(void* interfacePtr) = 0;

    /**
     * @brief Remove previously installed hooks
     */
    virtual void RemoveHooks() = 0;

protected:
    /**
     * @brief Get the vtable from a COM interface pointer
     * @param interfacePtr Pointer to a COM interface
     * @return Pointer to the vtable
     */
    void** GetVTable(void* interfacePtr);

    /**
     * @brief Install a hook for a specific vtable entry
     * @param vtable Pointer to the vtable
     * @param index Index into the vtable
     * @param hookFunction Pointer to the hook function
     * @return Pointer to the original function
     */
    void* HookVTableEntry(void** vtable, int index, void* hookFunction);
};

/**
 * @brief SwapChain specific vtable hook implementation
 */
class SwapChainHook : public VTableHook {
public:
    SwapChainHook();
    ~SwapChainHook() override;

    bool InstallHooks(void* interfacePtr) override;
    void RemoveHooks() override;
    
    /**
     * @brief Find and hook a SwapChain in the current process
     * @return True if successful
     */
    bool FindAndHookSwapChain();

    /**
     * @brief Set callback for when Present is called
     * @param callback Function to call when Present is called
     */
    void SetPresentCallback(std::function<void(IDXGISwapChain*)> callback);

private:
    // Original function pointers
    typedef HRESULT (STDMETHODCALLTYPE *Present_t)(IDXGISwapChain*, UINT, UINT);
    Present_t m_originalPresent;
    
    // Our hook functions
    static HRESULT STDMETHODCALLTYPE HookPresent(IDXGISwapChain* pSwapChain, UINT SyncInterval, UINT Flags);
    
    std::function<void(IDXGISwapChain*)> m_presentCallback;
    void** m_hookedVTable;
    bool m_hooksInstalled;
    
    // Store the instance for use in static hook functions
    static SwapChainHook* s_instance;
};

/**
 * @brief Memory scanner for locating DirectX interfaces in process memory
 */
class MemoryScanner {
public:
    MemoryScanner();
    ~MemoryScanner();
    
    /**
     * @brief Locate D3D11.dll and DXGI.dll in process memory
     * @return True if modules were found
     */
    bool FindDXModules();
    
    /**
     * @brief Scan for vtable patterns in memory
     * @param pattern The pattern to search for
     * @param mask The mask for wildcard pattern matching
     * @return Vector of addresses where the pattern was found
     */
    std::vector<void*> ScanForPattern(const std::vector<uint8_t>& pattern, const std::string& mask);
    
    /**
     * @brief Calculate vtable offsets for DirectX interfaces
     * @return Map of interface name to vtable offsets
     */
    std::unordered_map<std::string, std::vector<int>> CalculateVTableOffsets();
    
    /**
     * @brief Parse export table from a loaded module
     * @param moduleName Name of the module to analyze
     * @return Map of export name to function address
     */
    std::unordered_map<std::string, void*> ParseExportTable(const std::string& moduleName);

private:
    HMODULE m_d3d11Module;
    HMODULE m_dxgiModule;
    
    // Memory region information for efficient scanning
    struct MemoryRegion {
        void* baseAddress;
        size_t size;
        DWORD protection;
    };
    
    std::vector<MemoryRegion> m_memoryRegions;
    
    /**
     * @brief Initialize memory region information for scanning
     */
    void InitializeMemoryRegions();
};

} // namespace DXHook
} // namespace UndownUnlock 
