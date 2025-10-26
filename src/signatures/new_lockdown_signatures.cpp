#include "../../include/signatures/lockdown_signatures.h"
#include <algorithm> // For std::min / transforms
#include <cctype>
#include <unordered_map>
#include <vector>

namespace UndownUnlock {
namespace Signatures {

namespace {

std::string NormalizeVendorKey(std::string vendor) {
    std::transform(vendor.begin(), vendor.end(), vendor.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return vendor;
}

// Static database mapping exam vendors to representative signatures
const std::unordered_map<std::string, std::vector<SignatureInfo>> g_vendorSignatureCatalog = {
    {
        "lockdown",
        {
            {
                "LDB_CheckWindowFocus",
                "55 8B EC 83 E4 F8 81 EC ?? ?? ?? ?? A1 ?? ?? ?? ??",
                0,
                0,
                "LockDownBrowser.exe",
                "LockDown Browser",
                "Window focus validation routine"
            },
            {
                "LDB_IsScreenshotAllowed",
                "8B FF 55 8B EC 83 EC 10 A1 ?? ?? ?? ?? 33 C5 89 45 FC",
                0,
                0,
                "LockDownBrowser.exe",
                "LockDown Browser",
                "Screenshot permission handler"
            },
            {
                "LDB_VirtualMachineDetection",
                "40 53 48 83 EC 20 48 ?? D9 E8 ?? ?? 00 00 48",
                0,
                0,
                "LockDownBrowser.exe",
                "LockDown Browser",
                "Virtual machine / sandbox check"
            }
        }
    },
    {
        "proproctor",
        {
            {
                "PP_WindowMonitor",
                "48 89 5C 24 18 57 48 83 EC 20 48 8B FA 48 8B D9 FF 15 ?? ?? ?? ?? 84 C0 74 0F",
                0,
                0,
                "ProProctor.exe",
                "ProProctor",
                "Foreground window enforcement routine"
            },
            {
                "PP_StreamingIntegrity",
                "40 53 48 83 EC 40 48 8B DA 48 8B F1 E8 ?? ?? ?? ?? 84 C0 74 12 48 8B CE E8 ?? ?? ?? ?? 85 C0",
                0,
                0,
                "ProProctorDesktop.exe",
                "ProProctor",
                "Video streaming hook validation"
            },
            {
                "PP_DeviceAudit",
                "48 8B C4 48 89 58 08 48 89 70 10 48 89 78 18 55 57 41 54 41 55 41 56 41 57 48 8D 68 A1",
                0,
                0,
                "ProProctorDeviceMonitor.exe",
                "ProProctor",
                "Peripheral/device auditing entry point"
            }
        }
    },
    {
        "ets",
        {
            {
                "ETS_ScreenShield",
                "48 83 EC 38 48 8B 05 ?? ?? ?? ?? 48 85 C0 74 0E 48 8B 08 48 8B 01 FF 50 08 84 C0",
                0,
                0,
                "ETSBrowser.exe",
                "ETS Secure Browser",
                "Screen capture suppression routine"
            },
            {
                "ETS_ProcessSnapshot",
                "48 8B C4 48 89 48 08 55 56 57 41 54 41 55 41 56 41 57 48 8D 68 A1",
                0,
                0,
                "ETSBrowser.exe",
                "ETS Secure Browser",
                "Process snapshot enumeration handler"
            },
            {
                "ETS_DebuggerSweep",
                "48 83 EC 28 65 48 8B 04 25 30 00 00 00 48 8B 48 60 48 85 C9 74 0F 48 8B 09",
                0,
                0,
                "ETSBrowser64.exe",
                "ETS Secure Browser",
                "Kernel debugger sweep logic"
            }
        }
    },
    {
        "prometric",
        {
            {
                "Prometric_FocusCheck",
                "48 83 EC 48 48 8B D9 48 8B 0D ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 84 C0",
                0,
                0,
                "PrometricSecureWrapper.exe",
                "Prometric",
                "Window focus heartbeat"
            },
            {
                "Prometric_DeviceAudit",
                "48 8B C4 44 88 40 20 55 56 57 48 8D 68 A1 48 81 EC C0 00 00 00 33 C0",
                0,
                0,
                "PrometricDeviceAudit.exe",
                "Prometric",
                "Hardware inventory routine"
            },
            {
                "Prometric_StreamingGuard",
                "40 55 56 57 48 8D 6C 24 C9 48 81 EC C0 00 00 00 48 8B F9 48 8B D3 48 8B CE",
                0,
                0,
                "PrometricStreaming.exe",
                "Prometric",
                "Video transport anti-hook check"
            }
        }
    }
};

} // namespace

std::vector<SignatureInfo> GetVendorSignatures(const std::string& vendor) {
    const auto it = g_vendorSignatureCatalog.find(NormalizeVendorKey(vendor));
    if (it != g_vendorSignatureCatalog.end()) {
        return it->second;
    }
    return {};
}

std::vector<SignatureInfo> GetLockdownSignatures() {
    return GetVendorSignatures("lockdown");
}

std::vector<SignatureInfo> GetProProctorSignatures() {
    return GetVendorSignatures("proproctor");
}

std::vector<SignatureInfo> GetETSSignatures() {
    return GetVendorSignatures("ets");
}

std::vector<SignatureInfo> GetPrometricSignatures() {
    return GetVendorSignatures("prometric");
}

std::vector<SignatureInfo> GetAllDefaultExamSignatures() {
    std::vector<SignatureInfo> aggregated;
    size_t total = 0;
    for (const auto& entry : g_vendorSignatureCatalog) {
        total += entry.second.size();
    }
    aggregated.reserve(total);
    for (const auto& entry : g_vendorSignatureCatalog) {
        aggregated.insert(aggregated.end(), entry.second.begin(), entry.second.end());
    }
    return aggregated;
}

} // namespace Signatures
} // namespace UndownUnlock
