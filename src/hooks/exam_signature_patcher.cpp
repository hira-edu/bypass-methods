#include "../../include/hooks/exam_signature_patcher.h"
#include "../../include/utils/error_handler.h"

#include <windows.h>
#include <vector>
#include <string>
#include <algorithm>
#include <cstring>

namespace UndownUnlock {
namespace Hooks {

namespace {

struct PatchRule {
    std::string keyword;
    std::vector<uint8_t> patchBytes;
    std::string description;
};

const std::vector<PatchRule> kPatchRules = {
    {"Focus", {0xB0, 0x01, 0xC3}, "Force focus validation to succeed"},
    {"Screen", {0x33, 0xC0, 0xC3}, "Neutralize screen capture checks"},
    {"HookDetection", {0x33, 0xC0, 0xC3}, "Bypass hook detection routines"},
    {"Integrity", {0x33, 0xC0, 0xC3}, "Skip integrity checks"},
    {"Process", {0x33, 0xC0, 0xC3}, "Disable process enumeration alerts"},
    {"VM", {0x33, 0xC0, 0xC3}, "Suppress VM detection"}
};

bool ApplyPatch(void* address, const std::vector<uint8_t>& patch) {
    DWORD oldProtect = 0;
    if (!VirtualProtect(address, patch.size(), PAGE_EXECUTE_READWRITE, &oldProtect)) {
        return false;
    }

    std::memcpy(address, patch.data(), patch.size());

    DWORD temp = 0;
    VirtualProtect(address, patch.size(), oldProtect, &temp);
    FlushInstructionCache(GetCurrentProcess(), address, patch.size());
    return true;
}

} // namespace

void ExamSignaturePatcher::ApplyPatches(const std::vector<DXHook::ExamSignatureMatch>& matches,
                                        DXHook::ExamVendor vendor) {
    if (matches.empty()) {
        utils::ErrorHandler::GetInstance()->warning(
            "ExamSignaturePatcher: no resolved signatures to patch",
            utils::ErrorCategory::GRAPHICS,
            __FUNCTION__, __FILE__, __LINE__
        );
        return;
    }

    int patchedCount = 0;
    for (const auto& match : matches) {
        auto loweredName = match.name;
        std::transform(loweredName.begin(), loweredName.end(), loweredName.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

        const PatchRule* rule = nullptr;
        for (const auto& candidate : kPatchRules) {
            auto loweredKeyword = candidate.keyword;
            std::transform(loweredKeyword.begin(), loweredKeyword.end(), loweredKeyword.begin(),
                           [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            if (loweredName.find(loweredKeyword) != std::string::npos) {
                rule = &candidate;
                break;
            }
        }

        if (!rule) {
            continue;
        }

        if (ApplyPatch(match.address, rule->patchBytes)) {
            patchedCount++;
            utils::ErrorHandler::GetInstance()->info(
                "Patched " + match.name + " (" + rule->description + ")",
                utils::ErrorCategory::GRAPHICS,
                __FUNCTION__, __FILE__, __LINE__
            );
        } else {
            utils::ErrorHandler::GetInstance()->warning(
                "Failed to patch " + match.name,
                utils::ErrorCategory::GRAPHICS,
                __FUNCTION__, __FILE__, __LINE__
            );
        }
    }

    utils::ErrorHandler::GetInstance()->info(
        "ExamSignaturePatcher applied " + std::to_string(patchedCount) +
        " patches for vendor " + std::to_string(static_cast<int>(vendor)),
        utils::ErrorCategory::GRAPHICS,
        __FUNCTION__, __FILE__, __LINE__
    );
}

} // namespace Hooks
} // namespace UndownUnlock
