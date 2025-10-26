#!/usr/bin/env python
"""
Automated Test Script for UndownUnlock Accessibility Framework

This script tests the functionality of the named pipe communication
and window management features of the UndownUnlock framework.
It runs a series of tests to verify that the system is working correctly.
"""

import os
import sys
import time
import logging
import threading
import argparse
import unittest
import subprocess
import random
import string
from typing import List, Dict, Any, Optional

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("automated_test.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("AutomatedTest")

# Import the remote client for testing
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'tools'))

from remote_client import RemoteClient
from named_pipe_manager import SecurityManager

# Global variables
CONTROLLER_PROCESS = None
TEST_RESULTS = {}


def is_controller_running() -> bool:
    """Check if the controller is already running."""
    try:
        client = RemoteClient()
        is_running = client.connect()
        if is_running:
            client.disconnect()
        return is_running
    except Exception:
        return False


def start_controller(wait_time: int = 5) -> bool:
    """Start the controller process in the background."""
    global CONTROLLER_PROCESS
    
    if is_controller_running():
        logger.info("Controller is already running")
        return True
    
    logger.info("Starting accessibility controller...")
    
    # Start the controller as a separate process
    try:
        if os.name == 'nt':  # Windows
            # Use subprocess with shell=True on Windows
            command = "start /B python accessibility_controller.py"
            CONTROLLER_PROCESS = subprocess.Popen(
                command, 
                shell=True, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE
            )
        else:
            # Use direct call on Unix/Linux
            CONTROLLER_PROCESS = subprocess.Popen(
                [sys.executable, "accessibility_controller.py"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
        
        # Wait for the controller to start
        logger.info(f"Waiting {wait_time} seconds for controller to start...")
        time.sleep(wait_time)
        
        # Check if it's running
        if not is_controller_running():
            logger.error("Controller failed to start")
            return False
        
        logger.info("Controller started successfully")
        return True
        
    except Exception as e:
        logger.error(f"Error starting controller: {e}")
        return False


def stop_controller():
    """Stop the controller process."""
    global CONTROLLER_PROCESS
    
    if CONTROLLER_PROCESS is not None:
        try:
            # Try to terminate gracefully
            CONTROLLER_PROCESS.terminate()
            CONTROLLER_PROCESS.wait(timeout=5)
            logger.info("Controller stopped")
        except subprocess.TimeoutExpired:
            # Force kill if it doesn't terminate
            CONTROLLER_PROCESS.kill()
            logger.info("Controller forcefully killed")
        except Exception as e:
            logger.error(f"Error stopping controller: {e}")
        
        CONTROLLER_PROCESS = None


class NamedPipeTest(unittest.TestCase):
    """Tests for the Named Pipe communication system."""
    
    def setUp(self):
        """Set up the test case."""
        self.client = RemoteClient()
        self.connected = self.client.connect()
        self.assertTrue(self.connected, "Failed to connect to controller")
    
    def tearDown(self):
        """Tear down the test case."""
        if self.connected:
            self.client.disconnect()
    
    def test_window_list(self):
        """Test getting the list of windows."""
        response = self.client.get_window_list()
        
        self.assertIsNotNone(response, "Response should not be None")
        self.assertEqual(response.get("status"), "success", "Window list request should succeed")
        self.assertIn("windows", response, "Response should contain windows field")
        self.assertIsInstance(response.get("windows"), list, "Windows field should be a list")
        self.assertIn("count", response, "Response should contain count field")
        self.assertIsInstance(response.get("count"), int, "Count field should be an integer")
        self.assertEqual(len(response.get("windows")), response.get("count"), 
                         "Count should match list length")
        
        logger.info(f"Found {response.get('count')} windows")
    
    def test_cycle_window(self):
        """Test cycling through windows."""
        # Test cycling to next window
        next_response = self.client.cycle_window("next")
        self.assertEqual(next_response.get("status"), "success", "Cycle to next window should succeed")
        
        # Wait briefly
        time.sleep(1)
        
        # Test cycling to previous window
        prev_response = self.client.cycle_window("previous")
        self.assertEqual(prev_response.get("status"), "success", "Cycle to previous window should succeed")
    
    def test_minimize_restore(self):
        """Test minimizing and restoring windows."""
        # Minimize all windows except target
        minimize_response = self.client.minimize_windows()
        self.assertEqual(minimize_response.get("status"), "success", "Minimize windows should succeed")
        
        # Wait briefly
        time.sleep(2)
        
        # Restore all windows
        restore_response = self.client.restore_windows()
        self.assertEqual(restore_response.get("status"), "success", "Restore windows should succeed")
    
    def test_take_screenshot(self):
        """Test taking a screenshot with multiple methods."""
        # Test 1: Standard full screen screenshot
        screenshot_response = self.client.take_screenshot()
        
        self.assertEqual(screenshot_response.get("status"), "success", "Taking full screenshot should succeed")
        self.assertIn("screenshot_path", screenshot_response, "Response should contain screenshot_path")
        
        # Verify the screenshot file exists
        screenshot_path = screenshot_response.get("screenshot_path")
        self.assertTrue(os.path.exists(screenshot_path), f"Screenshot file should exist: {screenshot_path}")
        
        # Check file size is non-zero
        self.assertGreater(os.path.getsize(screenshot_path), 0, "Screenshot should have non-zero size")
        
        # Test 2: Window-specific screenshot
        # First get a list of windows
        window_list_response = self.client.get_window_list()
        
        if window_list_response.get("status") == "success" and window_list_response.get("windows"):
            # Take a screenshot of the first window in the list
            target_window = window_list_response.get("windows")[0]
            window_screenshot_response = self.client.take_screenshot(target_window)
            
            self.assertEqual(window_screenshot_response.get("status"), "success", 
                           f"Taking screenshot of specific window '{target_window}' should succeed")
            self.assertIn("screenshot_path", window_screenshot_response, "Response should contain screenshot_path")
            
            # Verify the screenshot file exists
            window_screenshot_path = window_screenshot_response.get("screenshot_path")
            self.assertTrue(os.path.exists(window_screenshot_path), 
                          f"Window-specific screenshot file should exist: {window_screenshot_path}")
            
            # Check file size is non-zero
            self.assertGreater(os.path.getsize(window_screenshot_path), 0, 
                             "Window-specific screenshot should have non-zero size")


class SecurityManagerTest(unittest.TestCase):
    """Tests for the SecurityManager encryption and authentication."""
    
    def setUp(self):
        """Set up the test case."""
        self.security_manager = SecurityManager()
    
    def test_encryption_decryption(self):
        """Test encryption and decryption of messages."""
        # Create a test message
        test_message = {
            "command": "test",
            "data": {
                "text": "Hello, World!",
                "number": 12345,
                "list": [1, 2, 3, 4, 5],
                "nested": {"a": 1, "b": 2}
            }
        }
        
        # Encrypt the message
        encrypted = self.security_manager.encrypt_message(test_message)
        
        # Decrypt the message
        decrypted = self.security_manager.decrypt_message(encrypted)
        
        # Check if the decrypted message matches the original
        self.assertEqual(decrypted, test_message, "Decrypted message should match original")
    
    def test_tampering_detection(self):
        """Test detection of message tampering."""
        # Create a test message
        test_message = {"command": "test", "data": {"value": "secret"}}
        
        # Sign the message
        signed = self.security_manager.sign_message(test_message)
        
        # Verify untampered message
        self.assertTrue(self.security_manager.verify_message(signed), 
                        "Verification should succeed for untampered message")
        
        # Tamper with the message by modifying the signature
        tampered = signed.copy()
        tampered["signature"] = tampered["signature"][:-5] + "12345"
        
        # Verify should fail
        self.assertFalse(self.security_manager.verify_message(tampered), 
                         "Verification should fail for tampered message")


class IntegrationTest(unittest.TestCase):
    """Integration tests for the entire system."""
    
    def setUp(self):
        """Set up the test case."""
        self.client = RemoteClient()
        self.connected = self.client.connect()
        self.assertTrue(self.connected, "Failed to connect to controller")
        
        # Get initial window list
        response = self.client.get_window_list()
        self.windows = response.get("windows", [])
        self.initial_count = response.get("count", 0)
    
    def tearDown(self):
        """Tear down the test case."""
        if self.connected:
            self.client.disconnect()
    
    def test_focus_specific_window(self):
        """Test focusing a specific window by name."""
        if not self.windows:
            self.skipTest("No windows available for testing")
        
        # Select a random window to focus
        test_window = random.choice(self.windows)
        
        # Try to focus the window
        response = self.client.focus_window(test_window)
        self.assertEqual(response.get("status"), "success", f"Focus window '{test_window}' should succeed")
        
        # Wait briefly to allow focus to change
        time.sleep(1)
        
        # Verify focus (indirectly) by trying to get window list again
        verify_response = self.client.get_window_list()
        self.assertEqual(verify_response.get("status"), "success", "Should be able to get window list after focus")
    
    def test_sequential_operations(self):
        """Test a sequence of operations to verify system stability."""
        operations = [
            # Take a screenshot
            lambda: self.client.take_screenshot(),
            
            # Cycle to next window
            lambda: self.client.cycle_window("next"),
            
            # Wait briefly
            lambda: time.sleep(1) or {"status": "success"},
            
            # Minimize windows
            lambda: self.client.minimize_windows(),
            
            # Wait briefly
            lambda: time.sleep(2) or {"status": "success"},
            
            # Restore windows
            lambda: self.client.restore_windows(),
            
            # Wait briefly
            lambda: time.sleep(1) or {"status": "success"},
            
            # Cycle to previous window
            lambda: self.client.cycle_window("previous"),
            
            # Get window list
            lambda: self.client.get_window_list()
        ]
        
        # Execute the operations in sequence
        for i, operation in enumerate(operations):
            try:
                response = operation()
                if isinstance(response, dict) and "status" in response:
                    self.assertEqual(response.get("status"), "success", 
                                    f"Operation {i} should succeed")
            except Exception as e:
                self.fail(f"Operation {i} failed with exception: {e}")


def run_tests(test_classes):
    """Run the specified test classes and return results."""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add tests to the suite
    for test_class in test_classes:
        suite.addTest(loader.loadTestsFromTestCase(test_class))
    
    # Run the tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Store results
    TEST_RESULTS["total"] = result.testsRun
    TEST_RESULTS["failures"] = len(result.failures)
    TEST_RESULTS["errors"] = len(result.errors)
    TEST_RESULTS["skipped"] = len(result.skipped)
    TEST_RESULTS["success"] = (
        result.testsRun - 
        len(result.failures) - 
        len(result.errors) - 
        len(result.skipped)
    )
    
    return result.wasSuccessful()


def print_test_summary():
    """Print a summary of test results."""
    print("\n" + "=" * 70)
    print(" TEST SUMMARY ".center(70, "="))
    print("=" * 70)
    
    print(f"\nTotal tests run: {TEST_RESULTS.get('total', 0)}")
    print(f"Successful tests: {TEST_RESULTS.get('success', 0)}")
    print(f"Failed tests: {TEST_RESULTS.get('failures', 0)}")
    print(f"Errors: {TEST_RESULTS.get('errors', 0)}")
    print(f"Skipped tests: {TEST_RESULTS.get('skipped', 0)}")
    
    success_rate = 0
    if TEST_RESULTS.get('total', 0) > 0:
        success_rate = (TEST_RESULTS.get('success', 0) / TEST_RESULTS.get('total', 0)) * 100
    
    print(f"\nSuccess rate: {success_rate:.2f}%")
    
    if success_rate == 100:
        print("\nAll tests passed! The system is working correctly.")
    elif success_rate >= 80:
        print("\nMost tests passed. The system is mostly working, but some issues were detected.")
    else:
        print("\nSignificant test failures detected. The system needs attention.")


def main():
    """Main entry point for the automated test script."""
    parser = argparse.ArgumentParser(
        description="Automated Test Script for UndownUnlock Accessibility Framework"
    )
    
    parser.add_argument("--start-controller", action="store_true",
                      help="Start the controller if it's not running")
    
    parser.add_argument("--stop-controller", action="store_true",
                      help="Stop the controller after tests complete")
    
    parser.add_argument("--test-suite", choices=["all", "pipes", "security", "integration"],
                      default="all", help="Which tests to run")
    
    args = parser.parse_args()
    
    print("\n" + "=" * 70)
    print(" UndownUnlock Accessibility Framework Automated Tests ".center(70, "="))
    print("=" * 70 + "\n")
    
    # Determine which test classes to run
    test_classes = []
    if args.test_suite in ["all", "pipes"]:
        test_classes.append(NamedPipeTest)
    if args.test_suite in ["all", "security"]:
        test_classes.append(SecurityManagerTest)
    if args.test_suite in ["all", "integration"]:
        test_classes.append(IntegrationTest)
    
    try:
        # Check if controller is running
        controller_already_running = is_controller_running()
        
        # Start controller if requested and not already running
        if args.start_controller and not controller_already_running:
            if not start_controller():
                print("\nError: Failed to start the controller. Tests cannot proceed.")
                return 1
        
        if not is_controller_running() and (args.test_suite in ["all", "pipes", "integration"]):
            print("\nWarning: Controller not running. Pipe and integration tests will fail.")
            print("Use --start-controller to automatically start the controller.")
        
        # Run the tests
        success = run_tests(test_classes)
        
        # Print test summary
        print_test_summary()
        
        # Return appropriate exit code
        return 0 if success else 1
    
    finally:
        # Stop controller if requested and we started it
        if args.stop_controller and args.start_controller and not controller_already_running:
            stop_controller()
    

if __name__ == "__main__":
    sys.exit(main()) 