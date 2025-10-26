#pragma once

#include "export.h"
#include <Windows.h>
#include <string>
#include <vector>
#include <atomic>
#include <mutex>
#include <condition_variable>

namespace UndownUnlock {
namespace DXHook {

// Forward declarations
struct FrameData;

/**
 * @brief Shared memory frame buffer header
 */
struct SharedMemoryHeader {
    uint32_t magic;                // Magic number to identify the shared memory
    uint32_t version;              // Version of the shared memory format
    uint32_t bufferSize;           // Total size of the buffer
    uint32_t frameDataOffset;      // Offset to the start of frame data
    std::atomic<uint32_t> producerIndex; // Current producer position
    std::atomic<uint32_t> consumerIndex; // Current consumer position
    uint32_t maxFrames;            // Maximum number of frames in the ring buffer
    uint32_t frameSize;            // Size of each frame slot
    std::atomic<uint32_t> sequence;// Frame sequence counter
    SRWLOCK srwLock;              // Slim reader/writer lock for synchronization
};

/**
 * @brief Frame slot header in shared memory
 */
struct FrameSlotHeader {
    uint32_t sequence;             // Frame sequence number
    uint32_t width;                // Frame width
    uint32_t height;               // Frame height
    uint32_t stride;               // Bytes per row
    uint32_t format;               // Pixel format (DXGI_FORMAT)
    uint64_t timestamp;            // Capture timestamp
    uint32_t dataSize;             // Size of frame data
    uint32_t flags;                // Additional flags
};

/**
 * @brief Class for transporting frame data via shared memory
 */
class UNDOWNUNLOCK_API SharedMemoryTransport {
public:
    /**
     * @brief Constructor
     * @param name Name of the shared memory object
     * @param initialSize Initial size of the shared memory buffer
     */
    SharedMemoryTransport(const std::string& name, size_t initialSize = 64 * 1024 * 1024);
    ~SharedMemoryTransport();
    
    /**
     * @brief Initialize the shared memory transport
     * @return True if initialization succeeded
     */
    bool Initialize();
    
    /**
     * @brief Write frame data to shared memory
     * @param frameData The frame data to write
     * @return True if write succeeded
     */
    bool WriteFrame(const FrameData& frameData);
    
    /**
     * @brief Read frame data from shared memory
     * @param frameData Output frame data
     * @return True if read succeeded
     */
    bool ReadFrame(FrameData& frameData);
    
    /**
     * @brief Wait for a new frame to be available
     * @param timeoutMs Timeout in milliseconds, 0 for no wait, INFINITE for infinite wait
     * @return True if a new frame is available
     */
    bool WaitForFrame(DWORD timeoutMs = 1000);
    
    /**
     * @brief Resize the shared memory buffer if needed
     * @param newSize New size for the buffer
     * @return True if resize succeeded
     */
    bool ResizeBuffer(size_t newSize);
    
private:
    std::string m_name;                // Name of the shared memory object
    HANDLE m_sharedMemoryHandle;       // Handle to the shared memory
    void* m_mappedAddress;             // Mapped address of the shared memory
    SharedMemoryHeader* m_header;      // Pointer to the shared memory header
    size_t m_initialSize;              // Initial size of the shared memory buffer
    
    // Event for signaling new frames
    HANDLE m_newFrameEvent;
    
    // Helper functions
    void* GetFrameSlotAddress(uint32_t index);
    bool AcquireWriteLock();
    void ReleaseWriteLock();
    bool AcquireReadLock();
    void ReleaseReadLock();
    
    // Frame management
    uint32_t GetAvailableFrameSlot();
    uint32_t GetNextFrameToRead();
};

} // namespace DXHook
} // namespace UndownUnlock 