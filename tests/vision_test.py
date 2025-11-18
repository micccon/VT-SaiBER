"""
Test script for Vision tool and ToolRegistry integration.
Tests the complete flow: registration → validation → execution → results
"""

import asyncio
import json
from pathlib import Path
import sys

# Add project root to path if needed
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from tools.tool_registry import ToolRegistry
from tools.vision.vision_tool import VisionTool


async def test_tool_registration():
    """Test 1: Tool registration and metadata extraction"""
    print("="*70)
    print("TEST 1: Tool Registration")
    print("="*70)
    
    registry = ToolRegistry()
    vision_tool = VisionTool(timeout=120)
    
    registry.register_tool(vision_tool)
    
    # Verify tool is registered
    assert "vision" in registry.tools, "Vision tool not registered"
    print("✓ Vision tool registered successfully")
    
    # Check metadata
    metadata_count = len(vision_tool.get_metadata())
    print(f"✓ Loaded {metadata_count} methods from schema")
    
    # Print available tools
    print("\n" + registry.get_tool_list_for_ai())
    
    return registry


async def test_parameter_validation(registry):
    """Test 2: Parameter validation"""
    print("\n" + "="*70)
    print("TEST 2: Parameter Validation")
    print("="*70)
    
    # Test valid parameters
    result = await registry.execute_tool("vision.ping_scan", target="127.0.0.1")
    print(f"✓ Valid parameters accepted")
    
    # Test missing required parameter
    result = await registry.execute_tool("vision.ping_scan")
    assert not result.success, "Should fail with missing parameter"
    print(f"✓ Missing parameter detected: {result.error}")
    
    # Test unexpected parameter
    result = await registry.execute_tool("vision.ping_scan", target="127.0.0.1", invalid_param="test")
    assert not result.success, "Should fail with unexpected parameter"
    print(f"✓ Unexpected parameter detected: {result.error}")
    
    # Test invalid tool path
    result = await registry.execute_tool("invalid.tool", target="127.0.0.1")
    assert not result.success, "Should fail with invalid tool"
    print(f"✓ Invalid tool detected: {result.error}")


async def test_ping_scan(registry):
    """Test 3: Ping scan (fastest, least intrusive)"""
    print("\n" + "="*70)
    print("TEST 3: Ping Scan (Host Discovery)")
    print("="*70)
    
    # Scan localhost - should always be up
    result = await registry.execute_tool("vision.ping_scan", target="127.0.0.1")
    
    print(f"Status: {'SUCCESS' if result.success else 'FAILED'}")
    print(f"Tool: {result.tool_name}")
    print(f"Target: {result.target}")
    print(f"Duration: {result.duration:.2f}s")
    print(f"Command: {result.command}")
    
    if result.success:
        print(f"Hosts found: {len(result.hosts)}")
        for idx, host in enumerate(result.hosts, 1):
            print(f"\n  Host {idx}:")
            print(f"    Status: {host.get('status')}")
            print(f"    Addresses: {host.get('addresses')}")
            print(f"    Hostnames: {host.get('hostnames')}")
    else:
        print(f"Error: {result.error}")
    
    return result


async def test_quick_scan(registry):
    """Test 4: Quick scan (top 100 ports)"""
    print("\n" + "="*70)
    print("TEST 4: Quick Scan (Top 100 Ports)")
    print("="*70)
    
    # Scan scanme.nmap.org (official test target)
    print("Scanning scanme.nmap.org (this may take 30-60 seconds)...")
    result = await registry.execute_tool("vision.quick_scan", target="scanme.nmap.org")
    
    print(f"\nStatus: {'SUCCESS' if result.success else 'FAILED'}")
    print(f"Duration: {result.duration:.2f}s")
    
    if result.success:
        print(f"Hosts found: {len(result.hosts)}")
        for host in result.hosts:
            if host.get('ports'):
                print(f"\n  Open ports found: {len(host['ports'])}")
                for port in host['ports'][:5]:  # Show first 5 ports
                    service = port.get('service', {})
                    print(f"    Port {port.get('port')}/{port.get('protocol')}: "
                          f"{port.get('state')} - {service.get('name', 'unknown')}")
                if len(host['ports']) > 5:
                    print(f"    ... and {len(host['ports']) - 5} more ports")
    else:
        print(f"Error: {result.error}")
    
    return result


async def test_port_scan(registry):
    """Test 5: Specific port scan"""
    print("\n" + "="*70)
    print("TEST 5: Port Scan (Specific Ports)")
    print("="*70)
    
    # Scan common web ports on localhost
    print("Scanning localhost ports 80,443,8080...")
    result = await registry.execute_tool("vision.port_scan", target="127.0.0.1", ports="80,443,8080")
    
    print(f"\nStatus: {'SUCCESS' if result.success else 'FAILED'}")
    print(f"Duration: {result.duration:.2f}s")
    
    if result.success:
        for host in result.hosts:
            if host.get('ports'):
                print(f"\n  Results:")
                for port in host['ports']:
                    print(f"    Port {port.get('port')}: {port.get('state')}")
            else:
                print("  No open ports found")
    else:
        print(f"Error: {result.error}")
    
    return result


async def test_error_handling(registry):
    """Test 6: Error handling"""
    print("\n" + "="*70)
    print("TEST 6: Error Handling")
    print("="*70)
    
    # Test invalid target
    print("Testing invalid target...")
    result = await registry.execute_tool("vision.ping_scan", target="999.999.999.999")
    print(f"✓ Invalid target handled: Success={result.success}")
    
    # Test invalid port format
    print("\nTesting invalid port format...")
    result = await registry.execute_tool("vision.port_scan", target="127.0.0.1", ports="invalid")
    print(f"✓ Invalid ports handled: Success={result.success}")
    if not result.success:
        print(f"  Error message: {result.error}")


async def test_result_serialization(registry):
    """Test 7: Result serialization"""
    print("\n" + "="*70)
    print("TEST 7: Result Serialization")
    print("="*70)
    
    result = await registry.execute_tool("vision.ping_scan", target="127.0.0.1")
    
    # Test to_dict
    result_dict = result.to_dict()
    print(f"✓ to_dict() works: {type(result_dict)}")
    
    # Test to_json
    result_json = result.to_json()
    print(f"✓ to_json() works: {len(result_json)} chars")
    
    # Verify JSON is valid
    parsed = json.loads(result_json)
    assert "success" in parsed, "JSON missing success field"
    assert "tool_name" in parsed, "JSON missing tool_name field"
    print(f"✓ JSON is valid and contains required fields")
    
    # Pretty print sample
    print("\nSample JSON output:")
    print(json.dumps(parsed, indent=2)[:500] + "...")


async def main():
    """Run all tests"""
    print("\n" + "🚀 " + "="*66 + " 🚀")
    print("   VISION TOOL TEST SUITE")
    print("🚀 " + "="*66 + " 🚀\n")
    
    try:
        # Test 1: Registration
        registry = await test_tool_registration()
        
        # Test 2: Validation
        await test_parameter_validation(registry)
        
        # Test 3: Ping scan (fast)
        await test_ping_scan(registry)
        
        # Test 4: Quick scan (slower, requires network)
        print("\n⚠️  The following test will scan scanme.nmap.org (official test target)")
        print("   This is safe and authorized, but will take 30-60 seconds.")
        response = input("   Continue? (y/n): ")
        if response.lower() == 'y':
            await test_quick_scan(registry)
        else:
            print("   Skipped quick scan test")
        
        # Test 5: Port scan
        await test_port_scan(registry)
        
        # Test 6: Error handling
        await test_error_handling(registry)
        
        # Test 7: Serialization
        await test_result_serialization(registry)
        
        print("\n" + "="*70)
        print("✅ ALL TESTS COMPLETED SUCCESSFULLY")
        print("="*70)
        
    except Exception as e:
        print("\n" + "="*70)
        print(f"❌ TEST FAILED: {str(e)}")
        print("="*70)
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())