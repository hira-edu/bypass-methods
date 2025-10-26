#pragma once

#include <Windows.h>
#include <d3d11.h>
#include <dxgi.h>
#include <vector>
#include <memory>
#include <functional>
#include "hooks/com_interface_wrapper.h"
#include "raii_wrappers.h"

namespace UndownUnlock {
namespace DXHook {

using Hooks::D3D11Texture2DWrapper;

// Forward declarations
struct FrameData;
class SharedMemoryTransport;

/**
 * @brief Structure containing frame data and metadata
 */
struct FrameData {
    std::vector<uint8_t> data;        // The raw pixel data
    uint32_t width;                   // Frame width
    uint32_t height;                  // Frame height
    uint32_t stride;                  // Bytes per row
    DXGI_FORMAT format;               // Pixel format
    uint64_t timestamp;               // Capture timestamp
    uint32_t sequence;                // Frame sequence number
};

/**
 * @brief Class responsible for extracting frame data from IDXGISwapChain
 */
class FrameExtractor {
public:
    FrameExtractor();
    ~FrameExtractor();

    /**
     * @brief Initialize the frame extractor
     * @param device D3D11 device to use for frame extraction
     * @param context D3D11 device context
     * @return True if initialization succeeded
     */
    bool Initialize(ID3D11Device* device, ID3D11DeviceContext* context);

    /**
     * @brief Extract frame data from a swap chain's back buffer
     * @param pSwapChain The swap chain to extract from
     * @return True if extraction succeeded
     */
    bool ExtractFrame(IDXGISwapChain* pSwapChain);

    /**
     * @brief Set a callback for when a frame is extracted
     * @param callback Function to call with the extracted frame data
     */
    void SetFrameCallback(std::function<void(const FrameData&)> callback);

    /**
     * @brief Set the shared memory transport for extracted frames
     * @param sharedMemory Pointer to shared memory transport object
     */
    void SetSharedMemoryTransport(SharedMemoryTransport* sharedMemory);

private:
    ID3D11Device* m_device;                       // D3D11 device
    ID3D11DeviceContext* m_deviceContext;         // D3D11 device context
    D3D11Texture2DWrapper m_stagingTextureWrapper; // RAII wrapper for staging texture
    uint32_t m_currentWidth;                      // Current frame width
    uint32_t m_currentHeight;                     // Current frame height
    DXGI_FORMAT m_currentFormat;                  // Current frame format
    std::function<void(const FrameData&)> m_frameCallback;   // Callback for extracted frames
    SharedMemoryTransport* m_sharedMemory;        // Shared memory transport
    uint32_t m_frameSequence;                     // Frame sequence counter

    /**
     * @brief Create or resize the staging texture based on the backbuffer
     * @param width New width
     * @param height New height
     * @param format New format
     * @return True if successful
     */
    bool CreateOrResizeStagingTexture(uint32_t width, uint32_t height, DXGI_FORMAT format);

    /**
     * @brief Convert frame data to a standard format if needed
     * @param sourceData Source frame data
     * @param convertedData Output converted frame data
     * @return True if conversion was performed
     */
    bool ConvertFrameFormat(const FrameData& sourceData, FrameData& convertedData);
};

} // namespace DXHook
} // namespace UndownUnlock 
