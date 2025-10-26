#include "../../include/signatures/dx_signatures.h"
#include "../../include/raii_wrappers.h"
#include "../../include/error_handler.h"
#include "../../include/memory_tracker.h"
#include "../../include/performance_monitor.h"
#include <iostream>
#include <dxgi.h>
#include <dxgi1_2.h>
#include <dxgi1_3.h>
#include <dxgi1_4.h>
#include <dxgi1_5.h>
#include <dxgi1_2.h>
#include <dxgi1_3.h>
#include <dxgi1_4.h>
#include <d3d11.h>
#include <iomanip>
#include <sstream>

namespace UndownUnlock {
namespace DXHook {
namespace Signatures {

// Performance monitoring for signature operations
static PerformanceMonitor g_signatureMonitor("DXSignatures");

// Memory tracking for signature resources
static MemoryTracker g_signatureMemory("DXSignatures");

// Convert string pattern to byte array and mask
std::pair<std::vector<uint8_t>, std::string> ParsePattern(const std::string& pattern) {
    auto timer = g_signatureMonitor.StartTimer("ParsePattern");
    
    try {
        std::vector<uint8_t> bytes;
        std::string mask;
        
        // Track memory allocation for pattern parsing
        g_signatureMemory.TrackAllocation("PatternBytes", pattern.length() * sizeof(uint8_t));
        
        std::istringstream stream(pattern);
        std::string token;
        
        while (stream >> token) {
            if (token == "?") {
                bytes.push_back(0);
                mask.push_back('?');
            } else {
                // Convert hex string to byte
                try {
                    uint8_t byte = static_cast<uint8_t>(std::stoi(token, nullptr, 16));
                    bytes.push_back(byte);
                    mask.push_back('x');
                } catch (const std::exception& e) {
                    ErrorHandler::LogError(ErrorSeverity::WARNING, ErrorCategory::SIGNATURE_PARSING,
                                         "Error parsing pattern token",
                                         {{"Token", token},
                                          {"Exception", e.what()},
                                          {"Pattern", pattern}});
                    // Use wildcard for invalid tokens
                    bytes.push_back(0);
                    mask.push_back('?');
                }
            }
        }
        
        timer.Stop();
        g_signatureMonitor.RecordOperation("ParsePattern", timer.GetElapsedTime());
        
        return {bytes, mask};
        
    } catch (const std::exception& e) {
        timer.Stop();
        ErrorHandler::LogError(ErrorSeverity::ERROR, ErrorCategory::EXCEPTION,
                             "Exception during pattern parsing",
                             {{"Exception", e.what()},
                              {"Pattern", pattern},
                              {"Operation", "ParsePattern"}});
        throw;
    }
}

// SwapChain signatures
namespace SwapChain {

// Signature for D3D11CreateDeviceAndSwapChain function
// This is a simplified pattern focusing on key instruction sequences
const SignaturePattern D3D11CreateSwapChain = {
    "D3D11CreateDeviceAndSwapChain",
    // Pattern bytes will be initialized in GetDXSignatures
    {},
    "",
    "d3d11.dll",
    "Pattern for D3D11CreateDeviceAndSwapChain function"
};

// Patterns for factory creation functions
const SignaturePattern CreateDXGIFactory = {
    "CreateDXGIFactory",
    {},
    "",
    "dxgi.dll",
    "Pattern for CreateDXGIFactory function"
};

const SignaturePattern CreateDXGIFactory1 = {
    "CreateDXGIFactory1",
    {},
    "",
    "dxgi.dll",
    "Pattern for CreateDXGIFactory1 function"
};

const SignaturePattern CreateDXGIFactory2 = {
    "CreateDXGIFactory2",
    {},
    "",
    "dxgi.dll",
    "Pattern for CreateDXGIFactory2 function"
};

// Virtual table offsets for various interfaces
const std::unordered_map<std::string, int> VTableOffsets = {
    {"IDXGISwapChain", 8},         // Present offset in IDXGISwapChain
    {"IDXGISwapChain1", 8},        // Same offset inherited from IDXGISwapChain
    {"IDXGISwapChain2", 8},        // Same offset inherited from IDXGISwapChain
    {"IDXGISwapChain3", 8},        // Same offset inherited from IDXGISwapChain
    {"IDXGISwapChain4", 8},        // Same offset inherited from IDXGISwapChain
    {"IDXGIFactory", 10},          // CreateSwapChain offset in IDXGIFactory
    {"IDXGIFactory1", 10},         // Same offset inherited from IDXGIFactory
    {"IDXGIFactory2", 10},         // Same offset inherited from IDXGIFactory
    {"IDXGIFactory3", 10},         // Same offset inherited from IDXGIFactory
    {"IDXGIFactory4", 10}          // Same offset inherited from IDXGIFactory
};

// Function to determine the correct vtable offset for Present based on the interface version
int GetPresentOffset(void* pSwapChain) {
    auto timer = g_signatureMonitor.StartTimer("GetPresentOffset");
    
    try {
        if (!pSwapChain) {
            ErrorHandler::LogError(ErrorSeverity::ERROR, ErrorCategory::SIGNATURE_PARSING,
                                 "Invalid swap chain pointer",
                                 {{"Operation", "GetPresentOffset"}});
            return -1;
        }
        
        // Query for different versions of the interface to determine its type
        IUnknown* pUnknown = static_cast<IUnknown*>(pSwapChain);
        
        // Try the newest interface first and work backwards
        IDXGISwapChain4* pSwapChain4 = nullptr;
        if (SUCCEEDED(pUnknown->QueryInterface(__uuidof(IDXGISwapChain4), reinterpret_cast<void**>(&pSwapChain4)))) {
            pSwapChain4->Release();
            timer.Stop();
            g_signatureMonitor.RecordOperation("GetPresentOffset", timer.GetElapsedTime());
            return VTableOffsets.at("IDXGISwapChain4");
        }
        
        IDXGISwapChain3* pSwapChain3 = nullptr;
        if (SUCCEEDED(pUnknown->QueryInterface(__uuidof(IDXGISwapChain3), reinterpret_cast<void**>(&pSwapChain3)))) {
            pSwapChain3->Release();
            timer.Stop();
            g_signatureMonitor.RecordOperation("GetPresentOffset", timer.GetElapsedTime());
            return VTableOffsets.at("IDXGISwapChain3");
        }
        
        IDXGISwapChain2* pSwapChain2 = nullptr;
        if (SUCCEEDED(pUnknown->QueryInterface(__uuidof(IDXGISwapChain2), reinterpret_cast<void**>(&pSwapChain2)))) {
            pSwapChain2->Release();
            timer.Stop();
            g_signatureMonitor.RecordOperation("GetPresentOffset", timer.GetElapsedTime());
            return VTableOffsets.at("IDXGISwapChain2");
        }
        
        IDXGISwapChain1* pSwapChain1 = nullptr;
        if (SUCCEEDED(pUnknown->QueryInterface(__uuidof(IDXGISwapChain1), reinterpret_cast<void**>(&pSwapChain1)))) {
            pSwapChain1->Release();
            timer.Stop();
            g_signatureMonitor.RecordOperation("GetPresentOffset", timer.GetElapsedTime());
            return VTableOffsets.at("IDXGISwapChain1");
        }
        
        // Base interface - all versions support this
        timer.Stop();
        g_signatureMonitor.RecordOperation("GetPresentOffset", timer.GetElapsedTime());
        return VTableOffsets.at("IDXGISwapChain");
        
    } catch (const std::exception& e) {
        timer.Stop();
        ErrorHandler::LogError(ErrorSeverity::ERROR, ErrorCategory::EXCEPTION,
                             "Exception during present offset determination",
                             {{"Exception", e.what()},
                              {"Operation", "GetPresentOffset"}});
        return -1;
    }
}

} // namespace SwapChain

// Get all DirectX signatures
std::vector<SignaturePattern> GetDXSignatures() {
    auto timer = g_signatureMonitor.StartTimer("GetDXSignatures");
    
    try {
        std::vector<SignaturePattern> signatures;
        
        // Track memory allocation for signatures vector
        g_signatureMemory.TrackAllocation("SignaturesVector", sizeof(std::vector<SignaturePattern>));
        
        // D3D11CreateDeviceAndSwapChain pattern
        // This is a generic pattern looking for characteristic instruction sequences
        auto parsedD3D11Pattern = ParsePattern(
            "48 89 5C 24 ? 48 89 74 24 ? 57 48 83 EC 40 48 8B FA 8B F1 48 89 54 24 ? 48 8D 05"
        );
        
        auto d3d11CreateSwapChain = SwapChain::D3D11CreateSwapChain;
        d3d11CreateSwapChain.pattern = parsedD3D11Pattern.first;
        d3d11CreateSwapChain.mask = parsedD3D11Pattern.second;
        signatures.push_back(d3d11CreateSwapChain);
        
        // CreateDXGIFactory pattern
        auto parsedFactoryPattern = ParsePattern(
            "48 83 EC 48 48 8B 05 ? ? ? ? 48 85 C0 75 ? 33 C0 48 83 C4 48 C3"
        );
        
        auto createDXGIFactory = SwapChain::CreateDXGIFactory;
        createDXGIFactory.pattern = parsedFactoryPattern.first;
        createDXGIFactory.mask = parsedFactoryPattern.second;
        signatures.push_back(createDXGIFactory);
        
        // CreateDXGIFactory1 pattern
        auto parsedFactory1Pattern = ParsePattern(
            "48 83 EC 38 E8 ? ? ? ? 48 89 5C 24 ? 48 89 7C 24 ?"
        );
        
        auto createDXGIFactory1 = SwapChain::CreateDXGIFactory1;
        createDXGIFactory1.pattern = parsedFactory1Pattern.first;
        createDXGIFactory1.mask = parsedFactory1Pattern.second;
        signatures.push_back(createDXGIFactory1);
        
        // CreateDXGIFactory2 pattern
        auto parsedFactory2Pattern = ParsePattern(
            "48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 48 83 EC 30 41 8B E9"
        );
        
        auto createDXGIFactory2 = SwapChain::CreateDXGIFactory2;
        createDXGIFactory2.pattern = parsedFactory2Pattern.first;
        createDXGIFactory2.mask = parsedFactory2Pattern.second;
        signatures.push_back(createDXGIFactory2);
        
        ErrorHandler::LogInfo(ErrorCategory::SIGNATURE_PARSING,
                            "DX signatures loaded successfully",
                            {{"SignatureCount", std::to_string(signatures.size())}});
        
        timer.Stop();
        g_signatureMonitor.RecordOperation("GetDXSignatures", timer.GetElapsedTime());
        
        return signatures;
        
    } catch (const std::exception& e) {
        timer.Stop();
        ErrorHandler::LogError(ErrorSeverity::ERROR, ErrorCategory::EXCEPTION,
                             "Exception during DX signature loading",
                             {{"Exception", e.what()},
                              {"Operation", "GetDXSignatures"}});
        throw;
    }
}

// GetLockDownSignatures is now defined in lockdown_signatures.cpp

// Get DirectX interface information
std::unordered_map<std::string, DXInterface> GetDXInterfaces() {
    auto timer = g_signatureMonitor.StartTimer("GetDXInterfaces");
    
    try {
        std::unordered_map<std::string, DXInterface> interfaces;
        
        // Track memory allocation for interfaces map
        g_signatureMemory.TrackAllocation("DXInterfaces", sizeof(std::unordered_map<std::string, DXInterface>));
        
        // IDXGISwapChain interface
        DXInterface swapChain = {
            "IDXGISwapChain",
            "2411E7E1-12AC-4CCF-BD14-9798E8534DC0",
            {
                "QueryInterface",
                "AddRef",
                "Release",
                "SetPrivateData",
                "SetPrivateDataInterface",
                "GetPrivateData",
                "GetParent",
                "GetDevice",
                "Present",
                "GetBuffer",
                "SetFullscreenState",
                "GetFullscreenState",
                "GetDesc",
                "ResizeBuffers",
                "ResizeTarget",
                "GetContainingOutput",
                "GetFrameStatistics",
                "GetLastPresentCount"
            },
            1
        };
        interfaces["IDXGISwapChain"] = swapChain;
        
        // IDXGISwapChain1 interface
        DXInterface swapChain1 = {
            "IDXGISwapChain1",
            "790A45F7-0D42-4876-983A-0A1410E63F0F",
            {
                "QueryInterface",
                "AddRef",
                "Release",
                "SetPrivateData",
                "SetPrivateDataInterface",
                "GetPrivateData",
                "GetParent",
                "GetDevice",
                "Present",
                "GetBuffer",
                "SetFullscreenState",
                "GetFullscreenState",
                "GetDesc",
                "ResizeBuffers",
                "ResizeTarget",
                "GetContainingOutput",
                "GetFrameStatistics",
                "GetLastPresentCount",
                "GetDesc1",
                "GetFullscreenDesc",
                "GetHwnd",
                "GetCoreWindow",
                "Present1",
                "IsTemporaryMonoSupported",
                "GetRestrictToOutput",
                "SetBackgroundColor",
                "GetBackgroundColor",
                "SetRotation",
                "GetRotation"
            },
            1
        };
        interfaces["IDXGISwapChain1"] = swapChain1;
        
        ErrorHandler::LogInfo(ErrorCategory::SIGNATURE_PARSING,
                            "DX interfaces loaded successfully",
                            {{"InterfaceCount", std::to_string(interfaces.size())}});
        
        timer.Stop();
        g_signatureMonitor.RecordOperation("GetDXInterfaces", timer.GetElapsedTime());
        
        return interfaces;
        
    } catch (const std::exception& e) {
        timer.Stop();
        ErrorHandler::LogError(ErrorSeverity::ERROR, ErrorCategory::EXCEPTION,
                             "Exception during DX interface loading",
                             {{"Exception", e.what()},
                              {"Operation", "GetDXInterfaces"}});
        throw;
    }
}

} // namespace Signatures
} // namespace DXHook
} // namespace UndownUnlock 
