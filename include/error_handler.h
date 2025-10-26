#pragma once

#include "utils/error_handler.h"

#include <string>
#include <unordered_map>
#include <vector>

namespace UndownUnlock {

using Utils::ErrorCategory;
using Utils::ErrorContext;
using Utils::ErrorSeverity;
using Utils::ErrorStatistics;
using Utils::LogEntry;
using Utils::LogLevel;
using Utils::ContextSnapshot;
using Utils::ErrorInfo;

/**
 * Compatibility wrapper that exposes the legacy ErrorHandler interface used by
 * hooks/tests while delegating to utils::ErrorHandler underneath.
 */
class ErrorHandler {
public:
    using LogEntry = Utils::LogEntry;
    using ErrorInfo = Utils::ErrorInfo;
    using ContextSnapshot = Utils::ContextSnapshot;
    using ErrorContext = Utils::ErrorContext;

    class ContextGuard {
    public:
        ContextGuard() = default;
        ContextGuard(const std::string& name, const ErrorContext& context);

        ContextGuard(ContextGuard&& other) noexcept;
        ContextGuard& operator=(ContextGuard&& other) noexcept;

        ContextGuard(const ContextGuard&) = delete;
        ContextGuard& operator=(const ContextGuard&) = delete;

        ~ContextGuard();

    private:
        void release();

        Utils::ErrorHandler* handler_{nullptr};
        bool active_{false};
    };

    static ErrorHandler& GetInstance();
    static void Initialize();
    static void Shutdown();

    ContextGuard CreateContext(const std::string& name,
                               const ErrorContext& context = ErrorContext());

    void ClearLogs();
    std::vector<LogEntry> GetLogs() const;
    std::vector<ErrorInfo> GetErrors() const;
    std::vector<ContextSnapshot> GetContexts() const;

    void LogInfo(const std::string& component, const std::string& message);
    void LogWarning(const std::string& component, const std::string& message);
    void LogError(const std::string& component, const std::string& message,
                  ErrorSeverity severity = ErrorSeverity::ERROR,
                  ErrorCategory category = ErrorCategory::GENERAL,
                  DWORD windows_error = 0);

    static void LogInfo(ErrorCategory category, const std::string& message,
                        const std::unordered_map<std::string, std::string>& metadata = {});
    static void LogWarning(ErrorCategory category, const std::string& message,
                           const std::unordered_map<std::string, std::string>& metadata = {});
    static void LogError(ErrorSeverity severity, ErrorCategory category,
                         const std::string& message,
                         const std::unordered_map<std::string, std::string>& metadata = {});

private:
    static Utils::ErrorHandler& Native();
    static std::string FormatStructuredMessage(
        const std::string& message,
        const std::unordered_map<std::string, std::string>& metadata);
};

// ===== Inline implementations =====

inline ErrorHandler::ContextGuard::ContextGuard(const std::string& name,
                                                const ErrorContext& context) {
    handler_ = &ErrorHandler::Native();
    handler_->set_error_context(context);
    handler_->push_error_context(name);
    active_ = true;
}

inline ErrorHandler::ContextGuard::ContextGuard(ContextGuard&& other) noexcept {
    handler_ = other.handler_;
    active_ = other.active_;
    other.handler_ = nullptr;
    other.active_ = false;
}

inline ErrorHandler::ContextGuard& ErrorHandler::ContextGuard::operator=(
    ContextGuard&& other) noexcept {
    if (this == &other) {
        return *this;
    }
    release();
    handler_ = other.handler_;
    active_ = other.active_;
    other.handler_ = nullptr;
    other.active_ = false;
    return *this;
}

inline ErrorHandler::ContextGuard::~ContextGuard() {
    release();
}

inline void ErrorHandler::ContextGuard::release() {
    if (handler_ && active_) {
        handler_->pop_error_context();
        handler_->clear_error_context();
    }
    active_ = false;
    handler_ = nullptr;
}

inline Utils::ErrorHandler& ErrorHandler::Native() {
    return Utils::ErrorHandler::get_instance();
}

inline ErrorHandler& ErrorHandler::GetInstance() {
    static ErrorHandler wrapper;
    return wrapper;
}

inline void ErrorHandler::Initialize() {
    Utils::ErrorHandler::Initialize();
}

inline void ErrorHandler::Shutdown() {
    Utils::ErrorHandler::Shutdown();
}

inline ErrorHandler::ContextGuard ErrorHandler::CreateContext(
    const std::string& name, const ErrorContext& context) {
    return ContextGuard(name, context);
}

inline void ErrorHandler::ClearLogs() {
    Native().ClearLogs();
}

inline std::vector<ErrorHandler::LogEntry> ErrorHandler::GetLogs() const {
    return Native().GetLogs();
}

inline std::vector<ErrorHandler::ErrorInfo> ErrorHandler::GetErrors() const {
    return Native().GetErrors();
}

inline std::vector<ErrorHandler::ContextSnapshot> ErrorHandler::GetContexts() const {
    return Native().GetContexts();
}

inline void ErrorHandler::LogInfo(const std::string& component, const std::string& message) {
    Native().LogInfo(component, message);
}

inline void ErrorHandler::LogWarning(const std::string& component, const std::string& message) {
    Native().LogWarning(component, message);
}

inline void ErrorHandler::LogError(const std::string& component, const std::string& message,
                                   ErrorSeverity severity, ErrorCategory category,
                                   DWORD windows_error) {
    Native().LogError(component, message, severity, category, windows_error);
}

inline std::string ErrorHandler::FormatStructuredMessage(
    const std::string& message,
    const std::unordered_map<std::string, std::string>& metadata) {
    if (metadata.empty()) {
        return message;
    }

    std::string formatted = message + " | ";
    bool first = true;
    for (const auto& entry : metadata) {
        if (!first) {
            formatted += ", ";
        }
        formatted += entry.first + "=" + entry.second;
        first = false;
    }
    return formatted;
}

inline void ErrorHandler::LogInfo(ErrorCategory category, const std::string& message,
                                  const std::unordered_map<std::string, std::string>& metadata) {
    Utils::ErrorHandler::LogInfo(category, FormatStructuredMessage(message, metadata));
}

inline void ErrorHandler::LogWarning(ErrorCategory category, const std::string& message,
                                     const std::unordered_map<std::string, std::string>& metadata) {
    Utils::ErrorHandler::LogWarning(category, FormatStructuredMessage(message, metadata));
}

inline void ErrorHandler::LogError(ErrorSeverity severity, ErrorCategory category,
                                   const std::string& message,
                                   const std::unordered_map<std::string, std::string>& metadata) {
    Utils::ErrorHandler::LogError(severity, category, FormatStructuredMessage(message, metadata));
}

} // namespace UndownUnlock
