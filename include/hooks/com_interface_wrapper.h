#pragma once

#include <windows.h>
#include <d3d11.h>
#include <dxgi.h>
#include <dxgi1_2.h>
#include <memory>
#include <type_traits>
#include <stdexcept>

#ifdef interface
#undef interface
#endif

namespace UndownUnlock {
namespace Hooks {

/**
 * RAII wrapper for COM interfaces to prevent memory leaks
 * Automatically calls Release() when the wrapper goes out of scope
 */
template<typename T>
class ComInterfaceWrapper {
    static_assert(std::is_base_of_v<IUnknown, T>, "T must inherit from IUnknown");
    
private:
    T* m_interface;
    bool m_owned;

public:
    // Default constructor - no interface
    ComInterfaceWrapper() : m_interface(nullptr), m_owned(false) {}
    
    // Constructor taking ownership of an interface
    explicit ComInterfaceWrapper(T* interface, bool takeOwnership = true) 
        : m_interface(interface), m_owned(takeOwnership) {}
    
    // Copy constructor - AddRefs the interface
    ComInterfaceWrapper(const ComInterfaceWrapper& other) 
        : m_interface(other.m_interface), m_owned(other.m_owned) {
        if (m_interface && m_owned) {
            m_interface->AddRef();
        }
    }
    
    // Move constructor - transfers ownership
    ComInterfaceWrapper(ComInterfaceWrapper&& other) noexcept
        : m_interface(other.m_interface), m_owned(other.m_owned) {
        other.m_interface = nullptr;
        other.m_owned = false;
    }
    
    // Copy assignment - AddRefs the interface
    ComInterfaceWrapper& operator=(const ComInterfaceWrapper& other) {
        if (this != &other) {
            Release();
            m_interface = other.m_interface;
            m_owned = other.m_owned;
            if (m_interface && m_owned) {
                m_interface->AddRef();
            }
        }
        return *this;
    }
    
    // Move assignment - transfers ownership
    ComInterfaceWrapper& operator=(ComInterfaceWrapper&& other) noexcept {
        if (this != &other) {
            Release();
            m_interface = other.m_interface;
            m_owned = other.m_owned;
            other.m_interface = nullptr;
            other.m_owned = false;
        }
        return *this;
    }
    
    // Destructor - automatically releases the interface
    ~ComInterfaceWrapper() {
        Release();
    }
    
    // Release the interface and reset the wrapper
    void Release() {
        if (m_interface && m_owned) {
            m_interface->Release();
            m_owned = false;
        }
        m_interface = nullptr;
    }
    
    // Get the raw interface pointer (use with caution)
    T* Get() const { return m_interface; }
    
    // Get the raw interface pointer and release ownership
    T* Detach() {
        T* temp = m_interface;
        m_interface = nullptr;
        m_owned = false;
        return temp;
    }
    
    // Check if the wrapper has a valid interface
    bool IsValid() const { return m_interface != nullptr; }
    
    // Operator overloads for easy access
    T* operator->() const { 
        if (!m_interface) {
            throw std::runtime_error("Attempting to access null COM interface");
        }
        return m_interface; 
    }
    
    T& operator*() const { 
        if (!m_interface) {
            throw std::runtime_error("Attempting to dereference null COM interface");
        }
        return *m_interface; 
    }
    
    // Boolean conversion operator
    explicit operator bool() const { return m_interface != nullptr; }
    
    // Reset the wrapper with a new interface
    void Reset(T* interface = nullptr, bool takeOwnership = true) {
        Release();
        m_interface = interface;
        m_owned = takeOwnership;
    }
};

// Type aliases for common COM interfaces
using D3D11DeviceWrapper = ComInterfaceWrapper<ID3D11Device>;
using D3D11DeviceContextWrapper = ComInterfaceWrapper<ID3D11DeviceContext>;
using D3D11Texture2DWrapper = ComInterfaceWrapper<ID3D11Texture2D>;
using DXGISwapChainWrapper = ComInterfaceWrapper<IDXGISwapChain>;
using DXGIOutputWrapper = ComInterfaceWrapper<IDXGIOutput>;
using DXGIOutputDuplicationWrapper = ComInterfaceWrapper<IDXGIOutputDuplication>;

/**
 * Helper function to safely get a COM interface from another interface
 */
template<typename T, typename U>
ComInterfaceWrapper<T> GetInterface(U* source, const IID& riid) {
    T* interface = nullptr;
    HRESULT hr = source->QueryInterface(riid, reinterpret_cast<void**>(&interface));
    if (SUCCEEDED(hr) && interface) {
        return ComInterfaceWrapper<T>(interface, true);
    }
    return ComInterfaceWrapper<T>();
}

/**
 * Helper function to safely get a COM interface from another interface with error checking
 */
template<typename T, typename U>
ComInterfaceWrapper<T> GetInterfaceChecked(U* source, const IID& riid, const char* operation = "QueryInterface") {
    T* interface = nullptr;
    HRESULT hr = source->QueryInterface(riid, reinterpret_cast<void**>(&interface));
    if (FAILED(hr)) {
        throw std::runtime_error(std::string(operation) + " failed with HRESULT: " + std::to_string(hr));
    }
    if (!interface) {
        throw std::runtime_error(std::string(operation) + " returned null interface");
    }
    return ComInterfaceWrapper<T>(interface, true);
}

} // namespace Hooks
} // namespace UndownUnlock 
