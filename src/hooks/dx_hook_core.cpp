#include "../../include/dx_hook_core.h"
#include "../../include/frame_extractor.h"
#include "../../include/shared_memory_transport.h"
#include "../../include/com_hooks/factory_hooks.h"
#include "../../include/hooks/com_interface_wrapper.h"
#include "../../include/utils/raii_wrappers.h"
#include "../../include/utils/error_handler.h"
#include "../../include/utils/performance_monitor.h"
#include "../../include/utils/memory_tracker.h"
#include "../../include/memory/pattern_scanner.h"
#include "../../include/signatures/dx_signatures.h"
#include "../../include/hooks/exam_signature_patcher.h"
#include <algorithm>
#include <cctype>
#include <iostream>

namespace UndownUnlock {
namespace DXHook {

using namespace UndownUnlock::Hooks;

namespace {

std::string ToLower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return value;
}

std::string ExamVendorToString(ExamVendor vendor) {
    switch (vendor) {
    case ExamVendor::LockDown: return "LockDown Browser";
    case ExamVendor::ProProctor: return "ProProctor";
    case ExamVendor::ETS: return "ETS Secure Browser";
    case ExamVendor::Prometric: return "Prometric";
    default: return "Unknown";
    }
}

const std::vector<std::string>& VendorProcessNames(ExamVendor vendor) {
    static const std::vector<std::string> lockdown = {
        "lockdownbrowser.exe", "lockdownbrowseroem.exe", "lockdown.exe"
    };
    static const std::vector<std::string> proProctor = {
        "proproctor.exe", "proproctordesktop.exe", "psi_proctor_launcher.exe"
    };
    static const std::vector<std::string> ets = {
        "etsbrowser.exe", "etsbrowser64.exe"
    };
    static const std::vector<std::string> prometric = {
        "prometricsecurewrapper.exe", "prometricdevicemonitor.exe"
    };
    static const std::vector<std::string> empty;

    switch (vendor) {
    case ExamVendor::LockDown: return lockdown;
    case ExamVendor::ProProctor: return proProctor;
    case ExamVendor::ETS: return ets;
    case ExamVendor::Prometric: return prometric;
    default: return empty;
    }
}

} // namespace

// Initialize the singleton instance
DXHookCore* DXHookCore::s_instance = nullptr;

DXHookCore::DXHookCore()
    : m_initialized(false),
      m_examVendor(ExamVendor::Unknown),
      m_examSignaturesReady(false),
      m_examPatchesApplied(false) {
    // Initialize utility components
    utils::ErrorHandler::Initialize();
    utils::PerformanceMonitor::Initialize();
    utils::MemoryTracker::Initialize();
}

DXHookCore::~DXHookCore() {
    Shutdown();
    
    // Shutdown utility components
    utils::MemoryTracker::Shutdown();
    utils::PerformanceMonitor::Shutdown();
    utils::ErrorHandler::Shutdown();
}

DXHookCore& DXHookCore::GetInstance() {
    if (!s_instance) {
        s_instance = new DXHookCore();
    }
    return *s_instance;
}

bool DXHookCore::Initialize() {
    // Avoid double initialization
    if (GetInstance().m_initialized) {
        return true;
    }
    
    DXHookCore& instance = GetInstance();
    
    // Start performance monitoring for initialization
    auto init_operation = utils::PerformanceMonitor::GetInstance()->start_operation("dx_hook_core_initialization");
    
    // Set error context for initialization
    utils::ErrorContext context;
    context.set("operation", "dx_hook_core_initialization");
    context.set("component", "DXHookCore");
    utils::ErrorHandler::GetInstance()->set_error_context(context);
    
    try {
        utils::ErrorHandler::GetInstance()->info(
            "Initializing DirectX Hook Core...",
            utils::ErrorCategory::GRAPHICS,
            __FUNCTION__, __FILE__, __LINE__
        );
        
        // Create the components with memory tracking
        auto memory_tracker = utils::MemoryTracker::GetInstance();
        
        auto scanner_allocation = memory_tracker->track_allocation(
            "memory_scanner", sizeof(MemoryScanner), utils::MemoryCategory::SYSTEM
        );
        instance.m_memoryScanner = std::make_unique<MemoryScanner>();
        memory_tracker->release_allocation(scanner_allocation);
        
        auto hook_allocation = memory_tracker->track_allocation(
            "swap_chain_hook", sizeof(SwapChainHook), utils::MemoryCategory::SYSTEM
        );
        instance.m_swapChainHook = std::make_unique<SwapChainHook>();
        memory_tracker->release_allocation(hook_allocation);
        
        auto extractor_allocation = memory_tracker->track_allocation(
            "frame_extractor", sizeof(FrameExtractor), utils::MemoryCategory::GRAPHICS
        );
        instance.m_frameExtractor = std::make_unique<FrameExtractor>();
        memory_tracker->release_allocation(extractor_allocation);
        
        auto transport_allocation = memory_tracker->track_allocation(
            "shared_memory_transport", sizeof(SharedMemoryTransport), utils::MemoryCategory::SYSTEM
        );
        instance.m_sharedMemory = std::make_unique<SharedMemoryTransport>("UndownUnlockFrameData");
        memory_tracker->release_allocation(transport_allocation);
        
        // Initialize the memory scanner
        auto scanner_operation = utils::PerformanceMonitor::GetInstance()->start_operation("memory_scanner_initialization");
        if (!instance.m_memoryScanner->FindDXModules()) {
            utils::PerformanceMonitor::GetInstance()->end_operation(scanner_operation);
            utils::ErrorHandler::GetInstance()->error(
                "Failed to find DirectX modules",
                utils::ErrorCategory::GRAPHICS,
                __FUNCTION__, __FILE__, __LINE__
            );
            return false;
        }
        utils::PerformanceMonitor::GetInstance()->end_operation(scanner_operation);
        
        // Initialize the shared memory transport
        auto transport_operation = utils::PerformanceMonitor::GetInstance()->start_operation("shared_memory_initialization");
        if (!instance.m_sharedMemory->Initialize()) {
            utils::PerformanceMonitor::GetInstance()->end_operation(transport_operation);
            utils::ErrorHandler::GetInstance()->error(
                "Failed to initialize shared memory transport",
                utils::ErrorCategory::SYSTEM,
                __FUNCTION__, __FILE__, __LINE__
            );
            return false;
        }
        utils::PerformanceMonitor::GetInstance()->end_operation(transport_operation);
        
        // Set up callback for when a SwapChain is hooked
        instance.m_swapChainHook->SetPresentCallback([&instance](IDXGISwapChain* pSwapChain) {
            // Start performance monitoring for frame extraction
            auto frame_operation = utils::PerformanceMonitor::GetInstance()->start_operation("frame_extraction");
            
            // Set error context for frame extraction
            utils::ErrorContext frame_context;
            frame_context.set("operation", "frame_extraction");
            frame_context.set("component", "SwapChainCallback");
            utils::ErrorHandler::GetInstance()->set_error_context(frame_context);
            
            // Hook fired - extract a frame
            try {
                // Use RAII wrapper to safely get the device from the swap chain
                auto deviceWrapper = GetInterfaceChecked<ID3D11Device>(pSwapChain, __uuidof(ID3D11Device), "GetDevice");
                
                if (deviceWrapper) {
                    // Get the immediate context using RAII wrapper
                    ID3D11DeviceContext* context = nullptr;
                    deviceWrapper->GetImmediateContext(&context);
                    
                    if (context) {
                        // Wrap the context for automatic cleanup
                        D3D11DeviceContextWrapper contextWrapper(context, true);
                        
                        // Initialize the frame extractor if not already
                        static bool extractorInitialized = false;
                        if (!extractorInitialized) {
                            auto init_operation = utils::PerformanceMonitor::GetInstance()->start_operation("frame_extractor_initialization");
                            instance.m_frameExtractor->Initialize(deviceWrapper.Get(), contextWrapper.Get());
                            instance.m_frameExtractor->SetSharedMemoryTransport(instance.m_sharedMemory.get());
                            utils::PerformanceMonitor::GetInstance()->end_operation(init_operation);
                            extractorInitialized = true;
                        }
                        
                        // Extract the frame
                        instance.m_frameExtractor->ExtractFrame(pSwapChain);
                        
                        // RAII wrappers automatically release interfaces when they go out of scope
                    } else {
                        utils::ErrorHandler::GetInstance()->error(
                            "Failed to get immediate context from device",
                            utils::ErrorCategory::GRAPHICS,
                            __FUNCTION__, __FILE__, __LINE__
                        );
                    }
                }
            }
            catch (const std::exception& e) {
                utils::ErrorHandler::GetInstance()->error(
                    "Exception in Present callback: " + std::string(e.what()),
                    utils::ErrorCategory::GRAPHICS,
                    __FUNCTION__, __FILE__, __LINE__
                );
            }
            
            // End performance monitoring
            utils::PerformanceMonitor::GetInstance()->end_operation(frame_operation);
            
            // Clear error context
            utils::ErrorHandler::GetInstance()->clear_error_context();
        });
        
        // Try to find and hook a SwapChain
        auto hook_operation = utils::PerformanceMonitor::GetInstance()->start_operation("swap_chain_hook_installation");
        bool hookResult = instance.m_swapChainHook->FindAndHookSwapChain();
        utils::PerformanceMonitor::GetInstance()->end_operation(hook_operation);
        
        if (!hookResult) {
            utils::ErrorHandler::GetInstance()->info(
                "Initial SwapChain hook not found, waiting for application to create one...",
                utils::ErrorCategory::GRAPHICS,
                __FUNCTION__, __FILE__, __LINE__
            );
            // This is not a fatal error - we'll hook when the app creates a SwapChain
        }
        
        // Initialize the factory hooks for COM interface runtime detection
        auto factory_operation = utils::PerformanceMonitor::GetInstance()->start_operation("factory_hooks_initialization");
        bool factoryHookResult = FactoryHooks::GetInstance().Initialize();
        utils::PerformanceMonitor::GetInstance()->end_operation(factory_operation);
        
        if (!factoryHookResult) {
            utils::ErrorHandler::GetInstance()->warning(
                "Failed to initialize factory hooks",
                utils::ErrorCategory::GRAPHICS,
                __FUNCTION__, __FILE__, __LINE__
            );
            // Continue anyway, as we might still hook through other methods
        } else {
            utils::ErrorHandler::GetInstance()->info(
                "COM Interface runtime detection initialized",
                utils::ErrorCategory::GRAPHICS,
                __FUNCTION__, __FILE__, __LINE__
            );
        }

        instance.InitializeExamSignatures();
        
        // Set flag indicating initialization succeeded
        instance.m_initialized = true;
        utils::ErrorHandler::GetInstance()->info(
            "DirectX Hook Core initialized successfully",
            utils::ErrorCategory::GRAPHICS,
            __FUNCTION__, __FILE__, __LINE__
        );
        
        // End performance monitoring for initialization
        utils::PerformanceMonitor::GetInstance()->end_operation(init_operation);
        
        // Clear error context
        utils::ErrorHandler::GetInstance()->clear_error_context();
        
        return true;
    }
    catch (const std::exception& e) {
        // End performance monitoring on error
        utils::PerformanceMonitor::GetInstance()->end_operation(init_operation);
        
        utils::ErrorHandler::GetInstance()->error(
            "Exception in DXHookCore::Initialize: " + std::string(e.what()),
            utils::ErrorCategory::GRAPHICS,
            __FUNCTION__, __FILE__, __LINE__
        );
        
        // Clear error context
        utils::ErrorHandler::GetInstance()->clear_error_context();
        
        return false;
    }
}

void DXHookCore::Shutdown() {
    if (!GetInstance().m_initialized) {
        return;
    }
    
    DXHookCore& instance = GetInstance();
    
    // Start performance monitoring for shutdown
    auto shutdown_operation = utils::PerformanceMonitor::GetInstance()->start_operation("dx_hook_core_shutdown");
    
    // Set error context for shutdown
    utils::ErrorContext context;
    context.set("operation", "dx_hook_core_shutdown");
    context.set("component", "DXHookCore");
    utils::ErrorHandler::GetInstance()->set_error_context(context);
    
    utils::ErrorHandler::GetInstance()->info(
        "Shutting down DirectX Hook Core...",
        utils::ErrorCategory::GRAPHICS,
        __FUNCTION__, __FILE__, __LINE__
    );
    
    try {
        // Shut down factory hooks
        FactoryHooks::GetInstance().Shutdown();
        
        // Clear any callbacks
        instance.m_frameCallbacks.clear();
        
        // Release components in reverse order with memory tracking
        auto memory_tracker = utils::MemoryTracker::GetInstance();
        
        if (instance.m_sharedMemory) {
            memory_tracker->track_allocation("shared_memory_cleanup", 0, utils::MemoryCategory::SYSTEM);
            instance.m_sharedMemory.reset();
        }
        
        if (instance.m_frameExtractor) {
            memory_tracker->track_allocation("frame_extractor_cleanup", 0, utils::MemoryCategory::GRAPHICS);
            instance.m_frameExtractor.reset();
        }
        
        if (instance.m_swapChainHook) {
            memory_tracker->track_allocation("swap_chain_hook_cleanup", 0, utils::MemoryCategory::SYSTEM);
            instance.m_swapChainHook.reset();
        }
        
        if (instance.m_memoryScanner) {
            memory_tracker->track_allocation("memory_scanner_cleanup", 0, utils::MemoryCategory::SYSTEM);
            instance.m_memoryScanner.reset();
        }
        
        instance.m_initialized = false;
        
        utils::ErrorHandler::GetInstance()->info(
            "DirectX Hook Core shutdown complete",
            utils::ErrorCategory::GRAPHICS,
            __FUNCTION__, __FILE__, __LINE__
        );
        
        // End performance monitoring
        utils::PerformanceMonitor::GetInstance()->end_operation(shutdown_operation);
        
        // Clear error context
        utils::ErrorHandler::GetInstance()->clear_error_context();
        
    } catch (const std::exception& e) {
        // End performance monitoring on error
        utils::PerformanceMonitor::GetInstance()->end_operation(shutdown_operation);
        
        utils::ErrorHandler::GetInstance()->error(
            "Exception in DXHookCore::Shutdown: " + std::string(e.what()),
            utils::ErrorCategory::GRAPHICS,
            __FUNCTION__, __FILE__, __LINE__
        );
        
        // Clear error context
        utils::ErrorHandler::GetInstance()->clear_error_context();
    }
}

size_t DXHookCore::RegisterFrameCallback(std::function<void(const void*, size_t, uint32_t, uint32_t)> callback) {
    if (!callback) {
        utils::ErrorHandler::GetInstance()->warning(
            "Attempted to register null callback",
            utils::ErrorCategory::GRAPHICS,
            __FUNCTION__, __FILE__, __LINE__
        );
        return 0;
    }
    
    DXHookCore& instance = GetInstance();
    
    std::lock_guard<std::mutex> lock(instance.m_callbackMutex);
    instance.m_frameCallbacks.push_back(callback);
    
    size_t handle = instance.m_frameCallbacks.size() - 1;
    
    utils::ErrorHandler::GetInstance()->debug(
        "Frame callback registered with handle: " + std::to_string(handle),
        utils::ErrorCategory::GRAPHICS,
        __FUNCTION__, __FILE__, __LINE__
    );
    
    // Return the index as a handle
    return handle;
}

void DXHookCore::UnregisterFrameCallback(size_t handle) {
    DXHookCore& instance = GetInstance();
    
    std::lock_guard<std::mutex> lock(instance.m_callbackMutex);
    if (handle < instance.m_frameCallbacks.size()) {
        // Replace with an empty function instead of resizing the vector
        // to avoid invalidating other handles
        instance.m_frameCallbacks[handle] = [](const void*, size_t, uint32_t, uint32_t) {};
        
        utils::ErrorHandler::GetInstance()->debug(
            "Frame callback unregistered with handle: " + std::to_string(handle),
            utils::ErrorCategory::GRAPHICS,
            __FUNCTION__, __FILE__, __LINE__
        );
    } else {
        utils::ErrorHandler::GetInstance()->warning(
            "Attempted to unregister invalid callback handle: " + std::to_string(handle),
            utils::ErrorCategory::GRAPHICS,
            __FUNCTION__, __FILE__, __LINE__
        );
    }
}

bool DXHookCore::IsInitialized() const {
    return m_initialized.load();
}

ExamVendor DXHookCore::GetDetectedExamVendor() const {
    return m_examVendor;
}

const std::vector<Signatures::SignaturePattern>& DXHookCore::GetActiveExamSignatures() const {
    return m_activeExamSignatures;
}

const std::vector<ExamSignatureMatch>& DXHookCore::GetResolvedExamSignatures() const {
    return m_resolvedExamSignatures;
}

void DXHookCore::InitializeExamSignatures() {
    if (m_examSignaturesReady) {
        return;
    }

    m_examVendor = DetectExamVendor();
    const std::string vendorLabel = DescribeExamVendor(m_examVendor);

    utils::ErrorHandler::GetInstance()->info(
        "DXHookCore vendor context: " + vendorLabel,
        utils::ErrorCategory::GRAPHICS,
        __FUNCTION__, __FILE__, __LINE__
    );

    switch (m_examVendor) {
    case ExamVendor::LockDown:
        m_activeExamSignatures = Signatures::GetLockDownSignatures();
        break;
    case ExamVendor::ProProctor:
        m_activeExamSignatures = Signatures::GetProProctorSignatures();
        break;
    case ExamVendor::ETS:
        m_activeExamSignatures = Signatures::GetETSSecureBrowserSignatures();
        break;
    case ExamVendor::Prometric:
        m_activeExamSignatures = Signatures::GetPrometricSignatures();
        break;
    case ExamVendor::Unknown:
    default:
        m_activeExamSignatures = Signatures::GetAllExamClientSignatures();
        break;
    }

    if (m_activeExamSignatures.empty()) {
        utils::ErrorHandler::GetInstance()->warning(
            "No exam signatures were loaded for vendor context: " + vendorLabel,
            utils::ErrorCategory::GRAPHICS,
            __FUNCTION__, __FILE__, __LINE__
        );
        m_examSignaturesReady = true;
        return;
    }

    PatternScanner scanner;
    if (!scanner.Initialize()) {
        utils::ErrorHandler::GetInstance()->warning(
            "PatternScanner failed to initialize; exam signature resolution skipped",
            utils::ErrorCategory::GRAPHICS,
            __FUNCTION__, __FILE__, __LINE__
        );
        m_examSignaturesReady = true;
        return;
    }

    m_resolvedExamSignatures.clear();
    for (const auto& signature : m_activeExamSignatures) {
        auto results = scanner.ScanForPattern(
            signature.pattern,
            signature.mask,
                signature.name,
            signature.moduleOrSection
        );

        for (const auto& match : results) {
            ExamSignatureMatch resolved;
            resolved.name = signature.name;
            resolved.address = match.address;
            resolved.module = signature.moduleOrSection;
            resolved.context = signature.description;
            m_resolvedExamSignatures.push_back(std::move(resolved));
        }
    }

    utils::ErrorHandler::GetInstance()->info(
        "Resolved " + std::to_string(m_resolvedExamSignatures.size()) +
        " exam signature locations for " + vendorLabel,
        utils::ErrorCategory::GRAPHICS,
        __FUNCTION__, __FILE__, __LINE__
    );

    m_examSignaturesReady = true;

    if (!m_resolvedExamSignatures.empty() && !m_examPatchesApplied) {
        Hooks::ExamSignaturePatcher::ApplyPatches(m_resolvedExamSignatures, m_examVendor);
        m_examPatchesApplied = true;
    }
}

ExamVendor DXHookCore::DetectExamVendor() const {
    const std::string executable = GetProcessImageName();
    if (executable.empty()) {
        return ExamVendor::Unknown;
    }

    for (ExamVendor vendor : {
             ExamVendor::LockDown,
             ExamVendor::ProProctor,
             ExamVendor::ETS,
             ExamVendor::Prometric }) {
        const auto& names = VendorProcessNames(vendor);
        if (std::find(names.begin(), names.end(), executable) != names.end()) {
            return vendor;
        }
    }

    return ExamVendor::Unknown;
}

std::string DXHookCore::GetProcessImageName() const {
    char buffer[MAX_PATH] = {0};
    DWORD len = GetModuleFileNameA(nullptr, buffer, MAX_PATH);
    if (len == 0) {
        return {};
    }

    std::string path(buffer, len);
    const size_t pos = path.find_last_of("\\/");
    std::string fileName = (pos == std::string::npos) ? path : path.substr(pos + 1);
    return ToLower(fileName);
}

std::string DXHookCore::DescribeExamVendor(ExamVendor vendor) const {
    return ExamVendorToString(vendor);
}

} // namespace DXHook
} // namespace UndownUnlock
