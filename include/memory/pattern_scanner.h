#pragma once

#include <Windows.h>
#include <vector>
#include <string>
#include <unordered_map>
#include <memory>
#include <cstdint>
#include <functional>

namespace UndownUnlock {
namespace DXHook {

/**
 * @brief Result of a pattern scan
 */
struct PatternScanResult {
    void* address;
    std::string patternName;
    int confidence; // 0-100 for fuzzy matching
};

/**
 * @brief Memory region information for scanning
 */
struct MemoryRegion {
    void* baseAddress;
    size_t size;
    DWORD protection;
    std::string name; // Module or section name
};

/**
 * @brief Enhanced pattern scanner with wildcard support and fuzzy matching
 */
class PatternScanner {
public:
    PatternScanner();
    ~PatternScanner();

    /**
     * @brief Initialize memory regions for scanning
     * @return True if initialization successful
     */
    bool Initialize();

    /**
     * @brief Scan for a pattern in memory
     * @param pattern Byte pattern to search for
     * @param mask Mask string with 'x' for exact match and '?' for wildcard
     * @param name Optional name for the pattern
     * @param moduleName Optional module to limit search to
     * @return Vector of addresses where the pattern was found
     */
    std::vector<PatternScanResult> ScanForPattern(
        const std::vector<uint8_t>& pattern,
        const std::string& mask,
        const std::string& name = "",
        const std::string& moduleName = ""
    );

    /**
     * @brief Scan for a pattern in memory using a string format
     * @param patternString Pattern string in the format "48 8B 05 ? ? ? ? 48 85 C0"
     * @param name Optional name for the pattern
     * @param moduleName Optional module to limit search to
     * @return Vector of addresses where the pattern was found
     */
    std::vector<PatternScanResult> ScanForPatternString(
        const std::string& patternString,
        const std::string& name = "",
        const std::string& moduleName = ""
    );

    /**
     * @brief Scan for multiple patterns in one pass
     * @param patterns Vector of pattern/mask/name tuples
     * @param moduleName Optional module to limit search to
     * @return Map of pattern name to results
     */
    std::unordered_map<std::string, std::vector<PatternScanResult>> ScanForPatterns(
        const std::vector<std::tuple<std::vector<uint8_t>, std::string, std::string>>& patterns,
        const std::string& moduleName = ""
    );

    /**
     * @brief Parse a pattern string into byte array and mask
     * @param patternString Pattern string in the format "48 8B 05 ? ? ? ? 48 85 C0"
     * @return Pair of byte array and mask string
     */
    static std::pair<std::vector<uint8_t>, std::string> ParsePatternString(
        const std::string& patternString
    );

    /**
     * @brief Get all loaded modules in the process
     * @return Vector of module info (base address, size, name)
     */
    std::vector<std::tuple<void*, size_t, std::string>> GetModules();

    /**
     * @brief Add a custom memory region to scan
     * @param region Memory region info
     */
    void AddMemoryRegion(const MemoryRegion& region);

    /**
     * @brief Get all memory regions that will be scanned
     * @return Vector of memory regions
     */
    const std::vector<MemoryRegion>& GetMemoryRegions() const;

    /**
     * @brief Set callback for progress reporting
     * @param callback Function to call with progress (0-100)
     */
    void SetProgressCallback(std::function<void(int)> callback);

private:
    // Friend test classes for testing private methods
    friend class ::PatternScannerTest;

    std::vector<MemoryRegion> m_memoryRegions;
    std::function<void(int)> m_progressCallback;

    /**
     * @brief Initialize memory regions based on current process memory map
     */
    void InitializeMemoryRegions();

    /**
     * @brief Implement Boyer-Moore-Horspool algorithm with wildcards
     * @param data Pointer to memory to search
     * @param dataSize Size of memory region
     * @param pattern Pattern to search for
     * @param mask Mask for pattern (x=match, ?=wildcard)
     * @return Vector of addresses where pattern was found
     */
    std::vector<void*> BoyerMooreHorspoolSearch(
        const uint8_t* data,
        size_t dataSize,
        const std::vector<uint8_t>& pattern,
        const std::string& mask
    );

    /**
     * @brief Perform fuzzy matching for pattern with Levenshtein distance
     * @param data Pointer to memory to search
     * @param dataSize Size of memory region
     * @param pattern Pattern to search for
     * @param maxDistance Maximum Levenshtein distance allowed
     * @return Vector of results with confidence score
     */
    std::vector<std::pair<void*, int>> FuzzyPatternMatch(
        const uint8_t* data,
        size_t dataSize,
        const std::vector<uint8_t>& pattern,
        int maxDistance
    );
};

} // namespace DXHook
} // namespace UndownUnlock 