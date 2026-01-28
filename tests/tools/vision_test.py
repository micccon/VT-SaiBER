import asyncio
import sys
import os
import time

from tools.vision.vision_scanner import VisionScanner

# ==========================================
# 📊 HELPER: Pretty Print Results
# ==========================================
def print_header(title):
    print(f"\n{'-'*60}")
    print(f"🧪 TESTING: {title}")
    print(f"{'-'*60}")

def assert_result(name, condition, details=""):
    if condition:
        print(f"✅ PASS: {name}")
    else:
        print(f"❌ FAIL: {name} | {details}")

# ==========================================
# 1. TEST: Single Standard Scan
# ==========================================
async def test_single_scan():
    print_header("Single Standard Scan (Localhost)")
    scanner = VisionScanner(timeout=10)
    
    # Run a quick ping scan
    result = await scanner.scan("127.0.0.1", "test_ping", "-sn")
    
    assert_result("Scan Success", result.success, result.error)
    assert_result("Found Hosts", len(result.hosts) > 0, f"Hosts found: {len(result.hosts)}")
    assert_result("Duration Recorded", result.duration > 0)
    print(f"   ℹ️  Output: {result.hosts}")

# ==========================================
# 2. TEST: Concurrent Multi-Scanning
# ==========================================
async def test_multiscanning():
    print_header("Concurrent Multi-Scanning (3 tasks)")
    scanner = VisionScanner(timeout=20)
    
    start_total = time.time()
    
    # Launch 3 scans simultaneously
    # Note: We use 127.0.0.1, localhost, and ::1 to simulating different targets
    print("   🚀 Launching 3 scans at once...")
    task1 = scanner.scan("127.0.0.1", "task1", "-sn")
    task2 = scanner.scan("localhost", "task2", "-sn")
    task3 = scanner.scan("::1", "task3", "-sn")
    
    # Wait for all to finish
    results = await asyncio.gather(task1, task2, task3)
    
    total_time = time.time() - start_total
    
    assert_result("All 3 Scans Finished", len(results) == 3)
    assert_result("Async Speed Check", total_time < 5, f"Took {total_time:.2f}s (Should be fast if parallel)")
    
    for i, res in enumerate(results):
        assert_result(f"Scan {i+1} Success", res.success)

# ==========================================
# 3. TEST: User Interrupt (Cancellation)
# ==========================================
async def test_interrupt():
    print_header("User Interrupt (Cancellation)")
    scanner = VisionScanner()
    
    # Start a scan that definitely takes > 1 second (-A is aggressive/slow)
    task = asyncio.create_task(scanner.scan("scanme.nmap.org", "interrupt_test", "-F"))
    
    print("   ⏳ Scan started... waiting 0.5s...")
    await asyncio.sleep(0.5)
    
    print("   🛑 SENT CANCEL SIGNAL!")
    task.cancel()
    
    # Await the result (it should return a result object, not crash)
    result = await task
    
    assert_result("Handled Cancellation", not result.success)
    assert_result("Correct Error Msg", result.error == "Scan cancelled by user interrupt", f"Got: {result.error}")

# ==========================================
# 4. TEST: Timeout Enforcement
# ==========================================
async def test_timeout():
    print_header("Timeout Enforcement")
    
    # Initialize scanner with a tiny 0.1s timeout
    fast_scanner = VisionScanner(timeout=0.1)
    
    # Try a scan that definitely takes longer than 0.1s
    result = await fast_scanner.scan("scanme.nmap.org", "timeout_test", "-F")
    
    assert_result("Marked as Failed", not result.success)
    assert_result("Correct Error Msg", "Scan timed out" in str(result.error), f"Got: {result.error}")
    assert_result("Duration Cap", result.duration >= 0.1)

# ==========================================
# 5. TEST: Invalid Target (DNS/Network)
# ==========================================
async def test_invalid_target():
    print_header("Invalid Target Handling")
    scanner = VisionScanner()
    
    # Scan a domain that definitely doesn't exist
    result = await scanner.scan("this.domain.does.not.exist.local", "invalid_test", "-sn")
    
    # Nmap usually fails resolution for bad domains
    assert_result("Scan Failed (Expected)", not result.success)
    assert_result("Error Captured", len(result.error) > 0)
    print(f"   ℹ️  Error content: {result.error.strip().splitlines()[0]}...")

# ==========================================
# 6. TEST: Invalid Arguments (Command Error)
# ==========================================
async def test_invalid_args():
    print_header("Invalid Arguments Handling")
    scanner = VisionScanner()
    
    # Pass a flag that doesn't exist in Nmap
    result = await scanner.scan("127.0.0.1", "bad_arg_test", "--not-a-real-flag")
    
    assert_result("Scan Failed (Expected)", not result.success)
    assert_result("Command Logged", "--not-a-real-flag" in result.command)
    print(f"   ℹ️  Error content: {result.error.strip().splitlines()[0]}...")

# ==========================================
# 🏁 MAIN RUNNER
# ==========================================
async def main():
    print("\n🚀 STARTING COMPREHENSIVE VISION SCANNER TESTS")
    
    try:
        await test_single_scan()
        await test_multiscanning()
        await test_interrupt()
        await test_timeout()
        await test_invalid_target()
        await test_invalid_args()
        
        print("\n" + "="*60)
        print("🎉 ALL TESTS COMPLETED")
        print("="*60 + "\n")
        
    except Exception as e:
        print(f"\n❌ CRITICAL TEST FAILURE: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(main())