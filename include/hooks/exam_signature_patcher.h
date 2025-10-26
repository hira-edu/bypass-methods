#pragma once

#include "../dx_hook_core.h"
#include <vector>

namespace UndownUnlock {
namespace Hooks {

class ExamSignaturePatcher {
public:
    static void ApplyPatches(const std::vector<DXHook::ExamSignatureMatch>& matches,
                             DXHook::ExamVendor vendor);
};

} // namespace Hooks
} // namespace UndownUnlock
