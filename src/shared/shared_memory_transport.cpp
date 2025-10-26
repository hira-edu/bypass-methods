#include "../../include/shared_memory_transport.h"
#include "../../include/frame_extractor.h"
#include "../../include/utils/raii_wrappers.h"
#include "../../include/utils/error_handler.h"
#include "../../include/utils/performance_monitor.h"
#include "../../include/utils/memory_tracker.h"
#include <iostream>
#include <sstream>

namespace UndownUnlock {
namespace DXHook {

// Constants
constexpr uint32_t SHARED_MEMORY_MAGIC = 0x554E444F;  // "UNDO" in hex
constexpr uint32_t SHARED_MEMORY_VERSION = 1;
constexpr uint32_t DEFAULT_MAX_FRAMES = 4;
constexpr uint32_t HEADER_SIZE = sizeof(SharedMemoryHeader);
constexpr uint32_t SLOT_HEADER_SIZE = sizeof(FrameSlotHeader);

SharedMemoryTransport::SharedMemoryTransport(const std::string& name, size_t initialSize)
    : m_name(name)
    , m_sharedMemoryHandle(nullptr)
    , m_mappedAddress(nullptr)
    , m_header(nullptr)
    , m_initialSize(initialSize)
    , m_newFrameEvent(nullptr) {
    
    // Set error context for this transport instance
    utils::ErrorContext context;
    context.set("component", "SharedMemoryTransport");
    context.set("name", name);
    context.set("initial_size", std::to_string(initialSize));
    utils::ErrorHandler::GetInstance()->set_error_context(context);
    
    utils::ErrorHandler::GetInstance()->info(
        "SharedMemoryTransport created",
        utils::ErrorCategory::SYSTEM,
        __FUNCTION__, __FILE__, __LINE__
    );
}

SharedMemoryTransport::~SharedMemoryTransport() {
    // Start performance monitoring for cleanup
    auto cleanup_operation = utils::PerformanceMonitor::GetInstance()->start_operation("shared_memory_cleanup");
    
    utils::ErrorHandler::GetInstance()->info(
        "Cleaning up SharedMemoryTransport: " + m_name,
        utils::ErrorCategory::SYSTEM,
        __FUNCTION__, __FILE__, __LINE__
    );
    
    try {
        // Clean up resources with proper error handling
        if (m_mappedAddress) {
            if (!UnmapViewOfFile(m_mappedAddress)) {
                utils::ErrorHandler::GetInstance()->warning(
                    "Failed to unmap view of file",
                    utils::ErrorCategory::SYSTEM,
                    __FUNCTION__, __FILE__, __LINE__, GetLastError()
                );
            }
            m_mappedAddress = nullptr;
        }
        
        if (m_sharedMemoryHandle) {
            if (!CloseHandle(m_sharedMemoryHandle)) {
                utils::ErrorHandler::GetInstance()->warning(
                    "Failed to close shared memory handle",
                    utils::ErrorCategory::SYSTEM,
                    __FUNCTION__, __FILE__, __LINE__, GetLastError()
                );
            }
            m_sharedMemoryHandle = nullptr;
        }
        
        if (m_newFrameEvent) {
            if (!CloseHandle(m_newFrameEvent)) {
                utils::ErrorHandler::GetInstance()->warning(
                    "Failed to close event handle",
                    utils::ErrorCategory::SYSTEM,
                    __FUNCTION__, __FILE__, __LINE__, GetLastError()
                );
            }
            m_newFrameEvent = nullptr;
        }
        
        utils::ErrorHandler::GetInstance()->info(
            "SharedMemoryTransport cleanup complete: " + m_name,
            utils::ErrorCategory::SYSTEM,
            __FUNCTION__, __FILE__, __LINE__
        );
        
    } catch (const std::exception& e) {
        utils::ErrorHandler::GetInstance()->error(
            "Exception during SharedMemoryTransport cleanup: " + std::string(e.what()),
            utils::ErrorCategory::SYSTEM,
            __FUNCTION__, __FILE__, __LINE__
        );
    }
    
    // End performance monitoring
    utils::PerformanceMonitor::GetInstance()->end_operation(cleanup_operation);
    
    // Clear error context
    utils::ErrorHandler::GetInstance()->clear_error_context();
}

bool SharedMemoryTransport::Initialize() {
    // Start performance monitoring for initialization
    auto init_operation = utils::PerformanceMonitor::GetInstance()->start_operation("shared_memory_initialization");
    
    utils::ErrorHandler::GetInstance()->info(
        "Initializing SharedMemoryTransport: " + m_name,
        utils::ErrorCategory::SYSTEM,
        __FUNCTION__, __FILE__, __LINE__
    );
    
    try {
        // Create event for signaling new frames
        std::string eventName = m_name + "_Event";
        m_newFrameEvent = CreateEventA(nullptr, FALSE, FALSE, eventName.c_str());
        if (!m_newFrameEvent) {
            utils::ErrorHandler::GetInstance()->error(
                "Failed to create event for shared memory",
                utils::ErrorCategory::SYSTEM,
                __FUNCTION__, __FILE__, __LINE__, GetLastError()
            );
            utils::PerformanceMonitor::GetInstance()->end_operation(init_operation);
            return false;
        }
    
        // Try to open existing shared memory first
        m_sharedMemoryHandle = OpenFileMappingA(FILE_MAP_ALL_ACCESS, FALSE, m_name.c_str());
        
        // If it doesn't exist, create a new one
        if (!m_sharedMemoryHandle) {
            m_sharedMemoryHandle = CreateFileMappingA(
                INVALID_HANDLE_VALUE,
                nullptr,
                PAGE_READWRITE,
                0,
                (DWORD)m_initialSize,
                m_name.c_str()
            );
            
            if (!m_sharedMemoryHandle) {
                utils::ErrorHandler::GetInstance()->error(
                    "Failed to create shared memory",
                    utils::ErrorCategory::SYSTEM,
                    __FUNCTION__, __FILE__, __LINE__, GetLastError()
                );
                utils::PerformanceMonitor::GetInstance()->end_operation(init_operation);
                return false;
            }
        
            // Map the shared memory
            m_mappedAddress = MapViewOfFile(
                m_sharedMemoryHandle,
                FILE_MAP_ALL_ACCESS,
                0,
                0,
                m_initialSize
            );
            
            if (!m_mappedAddress) {
                utils::ErrorHandler::GetInstance()->error(
                    "Failed to map shared memory",
                    utils::ErrorCategory::SYSTEM,
                    __FUNCTION__, __FILE__, __LINE__, GetLastError()
                );
                CloseHandle(m_sharedMemoryHandle);
                m_sharedMemoryHandle = nullptr;
                utils::PerformanceMonitor::GetInstance()->end_operation(init_operation);
                return false;
            }
        
            // Initialize the header
            m_header = static_cast<SharedMemoryHeader*>(m_mappedAddress);
            m_header->magic = SHARED_MEMORY_MAGIC;
            m_header->version = SHARED_MEMORY_VERSION;
            m_header->bufferSize = (uint32_t)m_initialSize;
            m_header->frameDataOffset = HEADER_SIZE;
            m_header->producerIndex.store(0);
            m_header->consumerIndex.store(0);
            m_header->maxFrames = DEFAULT_MAX_FRAMES;
            
            // Calculate frame size - allocate enough space for a 1080p frame with some extra
            uint32_t estimatedFrameSize = 1920 * 1080 * 4 + SLOT_HEADER_SIZE;
            m_header->frameSize = estimatedFrameSize;
            
            // Initialize sequence counter
            m_header->sequence.store(0);
            
            // Initialize the slim reader/writer lock
            InitializeSRWLock(&m_header->srwLock);
            
            utils::ErrorHandler::GetInstance()->info(
                "Created shared memory: " + m_name + ", size: " + std::to_string(m_initialSize) + 
                ", max frames: " + std::to_string(m_header->maxFrames),
                utils::ErrorCategory::SYSTEM,
                __FUNCTION__, __FILE__, __LINE__
            );
        } else {
            // Map the existing shared memory
            m_mappedAddress = MapViewOfFile(
                m_sharedMemoryHandle,
                FILE_MAP_ALL_ACCESS,
                0,
                0,
                0  // Map the entire file
            );
            
            if (!m_mappedAddress) {
                utils::ErrorHandler::GetInstance()->error(
                    "Failed to map existing shared memory",
                    utils::ErrorCategory::SYSTEM,
                    __FUNCTION__, __FILE__, __LINE__, GetLastError()
                );
                CloseHandle(m_sharedMemoryHandle);
                m_sharedMemoryHandle = nullptr;
                utils::PerformanceMonitor::GetInstance()->end_operation(init_operation);
                return false;
            }
        
            // Get the header
            m_header = static_cast<SharedMemoryHeader*>(m_mappedAddress);
            
            // Verify magic and version
            if (m_header->magic != SHARED_MEMORY_MAGIC) {
                utils::ErrorHandler::GetInstance()->error(
                    "Invalid shared memory magic number",
                    utils::ErrorCategory::SYSTEM,
                    __FUNCTION__, __FILE__, __LINE__
                );
                UnmapViewOfFile(m_mappedAddress);
                CloseHandle(m_sharedMemoryHandle);
                m_mappedAddress = nullptr;
                m_sharedMemoryHandle = nullptr;
                utils::PerformanceMonitor::GetInstance()->end_operation(init_operation);
                return false;
            }
            
            if (m_header->version != SHARED_MEMORY_VERSION) {
                utils::ErrorHandler::GetInstance()->error(
                    "Incompatible shared memory version",
                    utils::ErrorCategory::SYSTEM,
                    __FUNCTION__, __FILE__, __LINE__
                );
                UnmapViewOfFile(m_mappedAddress);
                CloseHandle(m_sharedMemoryHandle);
                m_mappedAddress = nullptr;
                m_sharedMemoryHandle = nullptr;
                utils::PerformanceMonitor::GetInstance()->end_operation(init_operation);
                return false;
            }
            
            utils::ErrorHandler::GetInstance()->info(
                "Connected to existing shared memory: " + m_name + 
                ", size: " + std::to_string(m_header->bufferSize) +
                ", max frames: " + std::to_string(m_header->maxFrames),
                utils::ErrorCategory::SYSTEM,
                __FUNCTION__, __FILE__, __LINE__
            );
        }
        
        utils::ErrorHandler::GetInstance()->info(
            "SharedMemoryTransport initialization complete: " + m_name,
            utils::ErrorCategory::SYSTEM,
            __FUNCTION__, __FILE__, __LINE__
        );
        
        // End performance monitoring
        utils::PerformanceMonitor::GetInstance()->end_operation(init_operation);
        
        return true;
        
    } catch (const std::exception& e) {
        utils::ErrorHandler::GetInstance()->error(
            "Exception during SharedMemoryTransport initialization: " + std::string(e.what()),
            utils::ErrorCategory::SYSTEM,
            __FUNCTION__, __FILE__, __LINE__
        );
        
        // End performance monitoring on error
        utils::PerformanceMonitor::GetInstance()->end_operation(init_operation);
        
        return false;
    }
}

bool SharedMemoryTransport::AcquireWriteLock() {
    AcquireSRWLockExclusive(&m_header->srwLock);
    return true;
}

void SharedMemoryTransport::ReleaseWriteLock() {
    ReleaseSRWLockExclusive(&m_header->srwLock);
}

bool SharedMemoryTransport::AcquireReadLock() {
    AcquireSRWLockShared(&m_header->srwLock);
    return true;
}

void SharedMemoryTransport::ReleaseReadLock() {
    ReleaseSRWLockShared(&m_header->srwLock);
}

uint32_t SharedMemoryTransport::GetAvailableFrameSlot() {
    uint32_t produceIndex = m_header->producerIndex.load();
    uint32_t consumeIndex = m_header->consumerIndex.load();
    
    // Check if the buffer is full
    if ((produceIndex + 1) % m_header->maxFrames == consumeIndex) {
        // If full, overwrite the oldest frame
        // In a real implementation, we might want to decide on a different policy
        m_header->consumerIndex.store((consumeIndex + 1) % m_header->maxFrames);
    }
    
    return produceIndex;
}

uint32_t SharedMemoryTransport::GetNextFrameToRead() {
    uint32_t produceIndex = m_header->producerIndex.load();
    uint32_t consumeIndex = m_header->consumerIndex.load();
    
    // Check if the buffer is empty
    if (produceIndex == consumeIndex) {
        return UINT32_MAX;  // No frames available
    }
    
    return consumeIndex;
}

void* SharedMemoryTransport::GetFrameSlotAddress(uint32_t index) {
    if (!m_mappedAddress || !m_header) {
        return nullptr;
    }
    
    // Calculate the offset of the frame slot
    uint32_t offset = m_header->frameDataOffset + (index * m_header->frameSize);
    
    // Ensure we don't go past the end of the buffer
    if (offset + m_header->frameSize > m_header->bufferSize) {
        return nullptr;
    }
    
    // Return the address of the frame slot
    return static_cast<uint8_t*>(m_mappedAddress) + offset;
}

bool SharedMemoryTransport::WriteFrame(const FrameData& frameData) {
    // Start performance monitoring for frame writing
    auto write_operation = utils::PerformanceMonitor::GetInstance()->start_operation("shared_memory_write_frame");
    
    if (!m_mappedAddress || !m_header) {
        utils::ErrorHandler::GetInstance()->error(
            "Cannot write frame - shared memory not initialized",
            utils::ErrorCategory::SYSTEM,
            __FUNCTION__, __FILE__, __LINE__
        );
        utils::PerformanceMonitor::GetInstance()->end_operation(write_operation);
        return false;
    }
    
    // Calculate total size needed for this frame
    uint32_t requiredSize = SLOT_HEADER_SIZE + (uint32_t)frameData.data.size();
    
    // Check if the frame is too large for our slots
    if (requiredSize > m_header->frameSize) {
        utils::ErrorHandler::GetInstance()->error(
            "Frame too large for shared memory slot: " + std::to_string(requiredSize) + 
            " > " + std::to_string(m_header->frameSize),
            utils::ErrorCategory::SYSTEM,
            __FUNCTION__, __FILE__, __LINE__
        );
        
        // In a real implementation, we would resize the shared memory here
        utils::PerformanceMonitor::GetInstance()->end_operation(write_operation);
        return false;
    }
    
    // Acquire write lock
    AcquireWriteLock();
    
    try {
        // Get the slot to write to
        uint32_t slotIndex = GetAvailableFrameSlot();
        void* slotAddress = GetFrameSlotAddress(slotIndex);
        
        if (!slotAddress) {
            utils::ErrorHandler::GetInstance()->error(
                "Failed to get frame slot address",
                utils::ErrorCategory::SYSTEM,
                __FUNCTION__, __FILE__, __LINE__
            );
            ReleaseWriteLock();
            utils::PerformanceMonitor::GetInstance()->end_operation(write_operation);
            return false;
        }
        
        // Write the frame header
        FrameSlotHeader* slotHeader = static_cast<FrameSlotHeader*>(slotAddress);
        slotHeader->sequence = m_header->sequence.fetch_add(1);
        slotHeader->width = frameData.width;
        slotHeader->height = frameData.height;
        slotHeader->stride = frameData.stride;
        slotHeader->format = static_cast<uint32_t>(frameData.format);
        slotHeader->timestamp = frameData.timestamp;
        slotHeader->dataSize = (uint32_t)frameData.data.size();
        slotHeader->flags = 0;
        
        // Write the frame data
        uint8_t* dataPtr = static_cast<uint8_t*>(slotAddress) + SLOT_HEADER_SIZE;
        memcpy(dataPtr, frameData.data.data(), frameData.data.size());
        
        // Update the producer index
        m_header->producerIndex.store((slotIndex + 1) % m_header->maxFrames);
        
        // Release the lock before signaling
        ReleaseWriteLock();
        
        // Signal that a new frame is available
        if (!SetEvent(m_newFrameEvent)) {
            utils::ErrorHandler::GetInstance()->warning(
                "Failed to signal new frame event",
                utils::ErrorCategory::SYSTEM,
                __FUNCTION__, __FILE__, __LINE__, GetLastError()
            );
        }
        
        utils::ErrorHandler::GetInstance()->debug(
            "Frame written successfully to slot " + std::to_string(slotIndex),
            utils::ErrorCategory::SYSTEM,
            __FUNCTION__, __FILE__, __LINE__
        );
        
        // End performance monitoring
        utils::PerformanceMonitor::GetInstance()->end_operation(write_operation);
        
        return true;
    }
    catch (const std::exception& e) {
        utils::ErrorHandler::GetInstance()->error(
            "Exception in WriteFrame: " + std::string(e.what()),
            utils::ErrorCategory::SYSTEM,
            __FUNCTION__, __FILE__, __LINE__
        );
        ReleaseWriteLock();
        utils::PerformanceMonitor::GetInstance()->end_operation(write_operation);
        return false;
    }
}

bool SharedMemoryTransport::ReadFrame(FrameData& frameData) {
    // Start performance monitoring for frame reading
    auto read_operation = utils::PerformanceMonitor::GetInstance()->start_operation("shared_memory_read_frame");
    
    if (!m_mappedAddress || !m_header) {
        utils::ErrorHandler::GetInstance()->error(
            "Cannot read frame - shared memory not initialized",
            utils::ErrorCategory::SYSTEM,
            __FUNCTION__, __FILE__, __LINE__
        );
        utils::PerformanceMonitor::GetInstance()->end_operation(read_operation);
        return false;
    }
    
    // Acquire read lock
    AcquireReadLock();
    
    try {
        // Get the slot to read from
        uint32_t slotIndex = GetNextFrameToRead();
        
        // No frames available
        if (slotIndex == UINT32_MAX) {
            ReleaseReadLock();
            utils::PerformanceMonitor::GetInstance()->end_operation(read_operation);
            return false;
        }
        
        void* slotAddress = GetFrameSlotAddress(slotIndex);
        
        if (!slotAddress) {
            utils::ErrorHandler::GetInstance()->error(
                "Failed to get frame slot address for reading",
                utils::ErrorCategory::SYSTEM,
                __FUNCTION__, __FILE__, __LINE__
            );
            ReleaseReadLock();
            utils::PerformanceMonitor::GetInstance()->end_operation(read_operation);
            return false;
        }
        
        // Read the frame header
        FrameSlotHeader* slotHeader = static_cast<FrameSlotHeader*>(slotAddress);
        frameData.width = slotHeader->width;
        frameData.height = slotHeader->height;
        frameData.stride = slotHeader->stride;
        frameData.format = static_cast<DXGI_FORMAT>(slotHeader->format);
        frameData.timestamp = slotHeader->timestamp;
        frameData.sequence = slotHeader->sequence;
        
        // Read the frame data
        uint8_t* dataPtr = static_cast<uint8_t*>(slotAddress) + SLOT_HEADER_SIZE;
        frameData.data.resize(slotHeader->dataSize);
        memcpy(frameData.data.data(), dataPtr, slotHeader->dataSize);
        
        // Update the consumer index
        m_header->consumerIndex.store((slotIndex + 1) % m_header->maxFrames);
        
        // Release the lock
        ReleaseReadLock();
        
        utils::ErrorHandler::GetInstance()->debug(
            "Frame read successfully from slot " + std::to_string(slotIndex),
            utils::ErrorCategory::SYSTEM,
            __FUNCTION__, __FILE__, __LINE__
        );
        
        // End performance monitoring
        utils::PerformanceMonitor::GetInstance()->end_operation(read_operation);
        
        return true;
    }
    catch (const std::exception& e) {
        utils::ErrorHandler::GetInstance()->error(
            "Exception in ReadFrame: " + std::string(e.what()),
            utils::ErrorCategory::SYSTEM,
            __FUNCTION__, __FILE__, __LINE__
        );
        ReleaseReadLock();
        utils::PerformanceMonitor::GetInstance()->end_operation(read_operation);
        return false;
    }
}

bool SharedMemoryTransport::WaitForFrame(DWORD timeoutMs) {
    if (!m_newFrameEvent) {
        utils::ErrorHandler::GetInstance()->error(
            "Cannot wait for frame - event not initialized",
            utils::ErrorCategory::SYSTEM,
            __FUNCTION__, __FILE__, __LINE__
        );
        return false;
    }
    
    // Wait for the event
    DWORD result = WaitForSingleObject(m_newFrameEvent, timeoutMs);
    
    if (result == WAIT_TIMEOUT) {
        utils::ErrorHandler::GetInstance()->debug(
            "Timeout waiting for frame event",
            utils::ErrorCategory::SYSTEM,
            __FUNCTION__, __FILE__, __LINE__
        );
    } else if (result != WAIT_OBJECT_0) {
        utils::ErrorHandler::GetInstance()->error(
            "Error waiting for frame event",
            utils::ErrorCategory::SYSTEM,
            __FUNCTION__, __FILE__, __LINE__, GetLastError()
        );
    }
    
    return result == WAIT_OBJECT_0;
}

bool SharedMemoryTransport::ResizeBuffer(size_t newSize) {
    // Not implemented yet - would allow dynamic resizing of the shared memory
    // to accommodate larger frames
    utils::ErrorHandler::GetInstance()->warning(
        "SharedMemoryTransport::ResizeBuffer not implemented yet",
        utils::ErrorCategory::SYSTEM,
        __FUNCTION__, __FILE__, __LINE__
    );
    return false;
}

} // namespace DXHook
} // namespace UndownUnlock 
