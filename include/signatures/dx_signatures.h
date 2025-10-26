#pragma once

#include <vector>
#include <string>
#include <unordered_map>
#include <cstdint>

namespace UndownUnlock {
namespace DXHook {
namespace Signatures {

/**
 * @brief Represents a pattern signature with wildcard support
 */
struct SignaturePattern {
    std::string name;
    std::vector<uint8_t> pattern;
    std::string mask;
    std::string moduleOrSection;
    std::string description;
};

/**
 * @brief DirectX interfaces and their vtable layouts
 */
struct DXInterface {
    std::string name;
    std::string uuid;
    std::vector<std::string> methodNames;
    int version;
};

/**
 * @brief Get a list of all known DirectX signatures
 * @return Vector of SignaturePattern objects
 */
std::vector<SignaturePattern> GetDXSignatures();

/**
 * @brief Get a list of LockDown Browser-specific signatures
 * @return Vector of SignaturePattern objects
 */
std::vector<SignaturePattern> GetLockDownSignatures();
std::pair<std::vector<uint8_t>, std::string> ParsePattern(const std::string& pattern);

/**
 * @brief Get interface information for DirectX COM interfaces
 * @return Map of interface name to DXInterface structure
 */
std::unordered_map<std::string, DXInterface> GetDXInterfaces();

/**
 * @brief SwapChain creation signatures for different versions
 */
namespace SwapChain {
    // D3D11 SwapChain creation signatures
    extern const SignaturePattern D3D11CreateSwapChain;
    extern const SignaturePattern CreateDXGIFactory;
    extern const SignaturePattern CreateDXGIFactory1;
    extern const SignaturePattern CreateDXGIFactory2;
    
    // Vtable offsets for different interfaces
    extern const std::unordered_map<std::string, int> VTableOffsets;
    
    // Function to determine correct vtable offsets based on interface version
    int GetPresentOffset(void* pSwapChain);
}

} // namespace Signatures
} // namespace DXHook
} // namespace UndownUnlock 
