#pragma once

#include <string>
#include <vector>
#include <cstdint> // For uint8_t if used in pattern directly, though string is fine

namespace UndownUnlock {
namespace Signatures {

struct SignatureInfo {
    std::string name;        // e.g., "LDB_CheckWindowFocus"
    std::string idaPattern;  // e.g., "55 8B EC 83 E4 F8 ?? ?? ?? ??"
    int searchOffset = 0;    // Offset from the found pattern to the actual function start or desired address
    int resultOffset = 0;    // If the found address needs further adjustment to point to the actual function start
    std::string module;      // Module or section the signature applies to (LockDownBrowser.exe, etc.)
    std::string vendor;      // Which secure exam client this signature maps to (LockDown, ProProctor, ETS, Prometric)
    std::string description; // Optional human-readable description
                           // Often the pattern itself is designed to start at the function, so this might be 0.
                           // Or, if the pattern includes a JMP/CALL, this could be an offset from the pattern start
                           // to the instruction containing the relative address.
};

// Function to retrieve the list of defined LockDown Browser related signatures
std::vector<SignatureInfo> GetLockdownSignatures();
std::vector<SignatureInfo> GetProProctorSignatures();
std::vector<SignatureInfo> GetETSSignatures();
std::vector<SignatureInfo> GetPrometricSignatures();
std::vector<SignatureInfo> GetVendorSignatures(const std::string& vendor);
std::vector<SignatureInfo> GetAllDefaultExamSignatures();

} // namespace Signatures
} // namespace UndownUnlock
