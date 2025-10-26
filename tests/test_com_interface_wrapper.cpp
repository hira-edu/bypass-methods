#include "hooks/com_interface_wrapper.h"
#include <gtest/gtest.h>
#include <windows.h>
#include <d3d11.h>
#include <dxgi.h>
#include <iostream>

using namespace UndownUnlock::Hooks;

// Mock COM interface for testing
class MockCOMInterface : public IUnknown {
private:
    LONG m_refCount;
    std::string m_name;

public:
    MockCOMInterface(const std::string& name) : m_refCount(1), m_name(name) {
        std::cout << "MockCOMInterface '" << m_name << "' created" << std::endl;
    }

    ~MockCOMInterface() {
        std::cout << "MockCOMInterface '" << m_name << "' destroyed" << std::endl;
    }

    // IUnknown methods
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppvObject) override {
        if (riid == IID_IUnknown) {
            *ppvObject = this;
            AddRef();
            return S_OK;
        }
        *ppvObject = nullptr;
        return E_NOINTERFACE;
    }

    ULONG STDMETHODCALLTYPE AddRef() override {
        LONG newCount = InterlockedIncrement(&m_refCount);
        std::cout << "MockCOMInterface '" << m_name << "' AddRef: " << newCount << std::endl;
        return newCount;
    }

    ULONG STDMETHODCALLTYPE Release() override {
        LONG newCount = InterlockedDecrement(&m_refCount);
        std::cout << "MockCOMInterface '" << m_name << "' Release: " << newCount << std::endl;
        if (newCount == 0) {
            delete this;
        }
        return newCount;
    }

    const std::string& GetName() const { return m_name; }
};

class ComInterfaceWrapperTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Initialize COM for the test
        HRESULT hr = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
        ASSERT_EQ(hr, S_OK);
    }

    void TearDown() override {
        // Uninitialize COM
        CoUninitialize();
    }
};

TEST_F(ComInterfaceWrapperTest, DefaultConstructor) {
    ComInterfaceWrapper<MockCOMInterface> wrapper;
    EXPECT_FALSE(wrapper.IsValid());
    EXPECT_EQ(wrapper.Get(), nullptr);
}

TEST_F(ComInterfaceWrapperTest, ConstructorWithInterface) {
    MockCOMInterface* mock = new MockCOMInterface("test1");
    ComInterfaceWrapper<MockCOMInterface> wrapper(mock, true);
    
    EXPECT_TRUE(wrapper.IsValid());
    EXPECT_EQ(wrapper.Get(), mock);
    EXPECT_EQ(mock->GetName(), "test1");
    
    // Wrapper should release the interface when it goes out of scope
}

TEST_F(ComInterfaceWrapperTest, ConstructorWithoutOwnership) {
    MockCOMInterface* mock = new MockCOMInterface("test2");
    ComInterfaceWrapper<MockCOMInterface> wrapper(mock, false);
    
    EXPECT_TRUE(wrapper.IsValid());
    EXPECT_EQ(wrapper.Get(), mock);
    
    // Wrapper should NOT release the interface when it goes out of scope
    wrapper.Release();
    delete mock; // Manual cleanup required
}

TEST_F(ComInterfaceWrapperTest, CopyConstructor) {
    MockCOMInterface* mock = new MockCOMInterface("test3");
    ComInterfaceWrapper<MockCOMInterface> wrapper1(mock, true);
    
    // Copy constructor should AddRef the interface
    ComInterfaceWrapper<MockCOMInterface> wrapper2(wrapper1);
    
    EXPECT_TRUE(wrapper1.IsValid());
    EXPECT_TRUE(wrapper2.IsValid());
    EXPECT_EQ(wrapper1.Get(), wrapper2.Get());
    
    // Both wrappers should release the interface when they go out of scope
}

TEST_F(ComInterfaceWrapperTest, MoveConstructor) {
    MockCOMInterface* mock = new MockCOMInterface("test4");
    ComInterfaceWrapper<MockCOMInterface> wrapper1(mock, true);
    
    // Move constructor should transfer ownership
    ComInterfaceWrapper<MockCOMInterface> wrapper2(std::move(wrapper1));
    
    EXPECT_FALSE(wrapper1.IsValid());
    EXPECT_TRUE(wrapper2.IsValid());
    EXPECT_EQ(wrapper2.Get(), mock);
    
    // Only wrapper2 should release the interface when it goes out of scope
}

TEST_F(ComInterfaceWrapperTest, CopyAssignment) {
    MockCOMInterface* mock1 = new MockCOMInterface("test5a");
    MockCOMInterface* mock2 = new MockCOMInterface("test5b");
    
    ComInterfaceWrapper<MockCOMInterface> wrapper1(mock1, true);
    ComInterfaceWrapper<MockCOMInterface> wrapper2(mock2, true);
    
    // Copy assignment should AddRef the new interface and release the old one
    wrapper1 = wrapper2;
    
    EXPECT_TRUE(wrapper1.IsValid());
    EXPECT_TRUE(wrapper2.IsValid());
    EXPECT_EQ(wrapper1.Get(), wrapper2.Get());
    EXPECT_EQ(wrapper1.Get(), mock2);
    
    // Both wrappers should release the interface when they go out of scope
}

TEST_F(ComInterfaceWrapperTest, MoveAssignment) {
    MockCOMInterface* mock1 = new MockCOMInterface("test6a");
    MockCOMInterface* mock2 = new MockCOMInterface("test6b");
    
    ComInterfaceWrapper<MockCOMInterface> wrapper1(mock1, true);
    ComInterfaceWrapper<MockCOMInterface> wrapper2(mock2, true);
    
    // Move assignment should transfer ownership
    wrapper1 = std::move(wrapper2);
    
    EXPECT_TRUE(wrapper1.IsValid());
    EXPECT_FALSE(wrapper2.IsValid());
    EXPECT_EQ(wrapper1.Get(), mock2);
    
    // Only wrapper1 should release the interface when it goes out of scope
}

TEST_F(ComInterfaceWrapperTest, Release) {
    MockCOMInterface* mock = new MockCOMInterface("test7");
    ComInterfaceWrapper<MockCOMInterface> wrapper(mock, true);
    
    EXPECT_TRUE(wrapper.IsValid());
    
    wrapper.Release();
    
    EXPECT_FALSE(wrapper.IsValid());
    EXPECT_EQ(wrapper.Get(), nullptr);
}

TEST_F(ComInterfaceWrapperTest, Reset) {
    MockCOMInterface* mock1 = new MockCOMInterface("test8a");
    MockCOMInterface* mock2 = new MockCOMInterface("test8b");
    
    ComInterfaceWrapper<MockCOMInterface> wrapper(mock1, true);
    EXPECT_EQ(wrapper.Get(), mock1);
    
    wrapper.Reset(mock2, true);
    EXPECT_EQ(wrapper.Get(), mock2);
    
    // Wrapper should release mock2 when it goes out of scope
    delete mock1; // Manual cleanup for mock1 since it was released
}

TEST_F(ComInterfaceWrapperTest, Detach) {
    MockCOMInterface* mock = new MockCOMInterface("test9");
    ComInterfaceWrapper<MockCOMInterface> wrapper(mock, true);
    
    MockCOMInterface* detached = wrapper.Detach();
    EXPECT_EQ(detached, mock);
    EXPECT_FALSE(wrapper.IsValid());
    
    // Manual cleanup required for detached interface
    delete detached;
}

TEST_F(ComInterfaceWrapperTest, OperatorOverloads) {
    MockCOMInterface* mock = new MockCOMInterface("test10");
    ComInterfaceWrapper<MockCOMInterface> wrapper(mock, true);
    
    // Test operator->
    EXPECT_EQ(wrapper->GetName(), "test10");
    
    // Test operator*
    EXPECT_EQ((*wrapper).GetName(), "test10");
    
    // Test boolean conversion
    EXPECT_TRUE(static_cast<bool>(wrapper));
    
    wrapper.Release();
    EXPECT_FALSE(static_cast<bool>(wrapper));
}

TEST_F(ComInterfaceWrapperTest, ExceptionOnNullAccess) {
    ComInterfaceWrapper<MockCOMInterface> wrapper;
    
    // Test operator-> with null interface
    EXPECT_THROW(wrapper->GetName(), std::runtime_error);
    
    // Test operator* with null interface
    EXPECT_THROW((*wrapper).GetName(), std::runtime_error);
}

TEST_F(ComInterfaceWrapperTest, GetInterfaceHelper) {
    MockCOMInterface* mock = new MockCOMInterface("test11");
    
    // Test GetInterface helper function
    auto wrapper = GetInterface<MockCOMInterface>(mock, IID_IUnknown);
    EXPECT_TRUE(wrapper.IsValid());
    EXPECT_EQ(wrapper.Get(), mock);
    
    // Test GetInterfaceChecked helper function
    auto wrapper2 = GetInterfaceChecked<MockCOMInterface>(mock, IID_IUnknown, "QueryInterface");
    EXPECT_TRUE(wrapper2.IsValid());
    EXPECT_EQ(wrapper2.Get(), mock);
}

TEST_F(ComInterfaceWrapperTest, TypeAliases) {
    // Test that type aliases compile correctly
    D3D11DeviceWrapper deviceWrapper;
    D3D11DeviceContextWrapper contextWrapper;
    D3D11Texture2DWrapper textureWrapper;
    DXGISwapChainWrapper swapChainWrapper;
    DXGIOutputWrapper outputWrapper;
    DXGIOutputDuplicationWrapper duplicationWrapper;
    
    EXPECT_FALSE(deviceWrapper.IsValid());
    EXPECT_FALSE(contextWrapper.IsValid());
    EXPECT_FALSE(textureWrapper.IsValid());
    EXPECT_FALSE(swapChainWrapper.IsValid());
    EXPECT_FALSE(outputWrapper.IsValid());
    EXPECT_FALSE(duplicationWrapper.IsValid());
}

TEST_F(ComInterfaceWrapperTest, ExceptionSafety) {
    MockCOMInterface* mock = new MockCOMInterface("test12");
    ComInterfaceWrapper<MockCOMInterface> wrapper(mock, true);
    
    // Test that exceptions don't prevent cleanup
    try {
        throw std::runtime_error("Test exception");
    } catch (...) {
        // Exception should not prevent RAII cleanup
    }
    
    // Wrapper should still be valid and release properly when it goes out of scope
    EXPECT_TRUE(wrapper.IsValid());
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
} 