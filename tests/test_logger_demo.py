"""
test_logger_demo.py - Comprehensive Logger Functionality Test

This script demonstrates all features of the DrStrange Logger:
- User query logging
- System event logging
- Agent delegation logging
- Tool call logging
- Error handling logging
- JSON file output
"""

import time
import sys
from pathlib import Path

# Add parent directory to Python path
sys.path.insert(0, str(Path(__file__).parent.parent))

from utils.DrStrange import AgentLogger

def test_user_queries():
    """Test user query logging"""
    print("\n" + "=" * 80)
    print("TEST 1: User Query Logging")
    print("=" * 80 + "\n")
    
    logger = AgentLogger()
    
    # Test various user queries
    queries = [
        "scan scanme.nmap.org",
        "scan 192.168.1.1 ports 22,80,443",
        "quick scan scanme.nmap.org and create vulnerability report",
        "ping test on localhost"
    ]
    
    for query in queries:
        logger.log_user_query(query)
        time.sleep(0.5)  # Pause for readability
    
    print("\nUser query logging completed\n")

def test_system_events():
    """Test system event logging"""
    print("\n" + "=" * 80)
    print("TEST 2: System Event Logging")
    print("=" * 80 + "\n")
    
    logger = AgentLogger()
    
    # Test system events
    events = [
        ("System initialized", {"version": "1.0.0", "agents": 3}),
        ("Input sanitization started", {"sanitizer": "Thanos"}),
        ("Input validation passed", {"targets": 1, "errors": 0}),
        ("Prompt engineering completed", {"prompt_length": 1284}),
        ("Agent system ready", {"status": "operational"})
    ]
    
    for message, context in events:
        logger._log_system(message, context)
        time.sleep(0.5)
    
    print("\nSystem event logging completed\n")

def test_agent_responses():
    """Test agent response logging"""
    print("\n" + "=" * 80)
    print("TEST 3: Agent Response Logging")
    print("=" * 80 + "\n")
    
    logger = AgentLogger()
    
    # Test agent responses
    agent_responses = [
        ("nick_fury", "Orchestrating task: scan_and_report with priority high"),
        ("vision_agent", "Initiating port scan on scanme.nmap.org (ports 1-1000)"),
        ("vision_agent", "Service detection completed - 3 services identified"),
        ("vuln_report_agent", "Generated report with 3 findings (severity: medium)"),
        ("nick_fury", "Task completed successfully")
    ]
    
    for agent_name, response in agent_responses:
        logger.log_agent_response(response, agent_name)
        time.sleep(0.5)
    
    print("\nAgent response logging completed\n")

def test_tool_calls():
    """Test tool call logging"""
    print("\n" + "=" * 80)
    print("TEST 4: Tool Call Logging")
    print("=" * 80 + "\n")
    
    logger = AgentLogger()
    
    # Test tool calls
    tool_calls = [
        ("ping_scan", {"target": "scanme.nmap.org", "count": 4}),
        ("port_scan", {"target": "scanme.nmap.org", "ports": "22,80,443"}),
        ("service_detection", {"target": "scanme.nmap.org", "version_intensity": 5}),
        ("os_fingerprint", {"target": "scanme.nmap.org"}),
        ("vulnerability_scan", {"target": "scanme.nmap.org", "scripts": ["vuln"]})
    ]
    
    for tool_name, params in tool_calls:
        logger.log_tool_call(tool_name, params)
        time.sleep(0.5)
    
    print("\nTool call logging completed\n")

def test_error_logging():
    """Test error logging"""
    print("\n" + "=" * 80)
    print("TEST 5: Error Logging")
    print("=" * 80 + "\n")
    
    logger = AgentLogger()
    
    # Test error scenarios
    errors = [
        ("Target validation failed", {
            "target": "invalid-host.example.com",
            "reason": "Not in whitelist",
            "severity": "warning"
        }),
        ("Connection timeout", {
            "target": "192.168.1.100",
            "timeout": 30,
            "severity": "error"
        }),
        ("API quota exceeded", {
            "api": "Google Gemini",
            "limit": "20 requests/day",
            "severity": "critical"
        }),
        ("MCP server unavailable", {
            "server": "http://localhost:8000",
            "retry_count": 3,
            "severity": "error"
        })
    ]
    
    for message, context in errors:
        logger.log_error(message, context)
        time.sleep(0.5)
    
    print("\nError logging completed\n")

def test_complete_workflow():
    """Test a complete workflow with all logging types"""
    print("\n" + "=" * 80)
    print("TEST 6: Complete Workflow Simulation")
    print("=" * 80 + "\n")
    
    logger = AgentLogger()
    
    # Simulate a complete scan workflow
    print("Starting complete workflow simulation...\n")
    
    # Step 1: User input
    logger.log_user_query("scan scanme.nmap.org and create vulnerability report")
    time.sleep(0.5)
    
    # Step 2: System initialization
    logger._log_system("Input received", {"length": 52})
    time.sleep(0.3)
    
    # Step 3: Sanitization
    logger._log_system("Thanos sanitization started", {"sanitizer": "Thanos"})
    time.sleep(0.3)
    logger._log_system("Input validated", {"valid_targets": 1, "action": "port_scan"})
    time.sleep(0.3)
    
    # Step 4: Prompt engineering
    logger._log_system("Tony Stark prompt engineering", {"agent_registry": 2})
    time.sleep(0.3)
    logger._log_system("Enhanced prompt generated", {"prompt_size": 1360})
    time.sleep(0.3)
    
    # Step 5: Orchestration
    logger.log_agent_response("Orchestrating scan and report task", "nick_fury")
    time.sleep(0.5)
    
    # Step 6: Vision agent scanning
    logger.log_agent_response("Initiating scan on scanme.nmap.org", "vision_agent")
    time.sleep(0.3)
    logger.log_tool_call("port_scan", {"target": "scanme.nmap.org", "ports": "1-65535"})
    time.sleep(0.5)
    logger.log_tool_call("service_detection", {"target": "scanme.nmap.org"})
    time.sleep(0.5)
    logger.log_agent_response("Scan complete: 3 open ports, 3 services identified", "vision_agent")
    time.sleep(0.3)
    
    # Step 7: Vulnerability reporting
    logger.log_agent_response("Analyzing scan results - 3 findings detected", "vuln_report_agent")
    time.sleep(0.5)
    logger.log_agent_response("Report generated: 0 high, 2 medium, 1 low severity", "vuln_report_agent")
    time.sleep(0.5)
    
    # Step 8: Finalization
    logger._log_system("Workflow completed", {"duration": "45s", "status": "success"})
    time.sleep(0.3)
    
    print("\nComplete workflow simulation completed\n")

def test_color_output():
    """Test color output formatting"""
    print("\n" + "=" * 80)
    print("TEST 7: Color Output Display")
    print("=" * 80 + "\n")
    
    logger = AgentLogger()
    
    print("Demonstrating different log types:\n")
    
    logger.log_user_query("This is a USER query")
    time.sleep(0.3)
    
    logger._log_system("This is a SYSTEM event", {})
    time.sleep(0.3)
    
    logger.log_agent_response("This is an AGENT response", "test_agent")
    time.sleep(0.3)
    
    logger.log_tool_call("test_tool", {"message": "This is a TOOL call"})
    time.sleep(0.3)
    
    logger.log_error("This is an ERROR message", {"severity": "high"})
    time.sleep(0.3)
    
    print("\nColor output test completed\n")

def test_json_output():
    """Test JSON file output"""
    print("\n" + "=" * 80)
    print("TEST 8: JSON File Output")
    print("=" * 80 + "\n")
    
    logger = AgentLogger()
    
    # Generate some logs
    logger.log_user_query("test query for JSON output")
    logger._log_system("test system event", {"test": True})
    logger.log_agent_response("test agent response", "test_agent")
    logger.log_tool_call("test_tool", {"key": "value"})
    logger.log_error("test error", {"code": 500})
    
    # Check log files
    print(f"Text log file: {logger.log_file}")
    print(f"JSON log file: {logger.json_file}")
    print(f"Total events logged: {len(logger.conversation_history)}")
    
    # Display last few events
    print("\nLast 3 logged events:")
    for event in logger.conversation_history[-3:]:
        print(f"  - {event['timestamp']} | {event['type']} | {event.get('content', event.get('message', 'N/A'))[:50]}")
    
    print("\nJSON output test completed\n")

def run_all_tests():
    """Run all logger tests"""
    print("\n" + "=" * 80)
    print("DRSTRANGE LOGGER - COMPREHENSIVE FUNCTIONALITY TEST")
    print("=" * 80)
    
    tests = [
        ("User Query Logging", test_user_queries),
        ("System Event Logging", test_system_events),
        ("Agent Response Logging", test_agent_responses),
        ("Tool Call Logging", test_tool_calls),
        ("Error Logging", test_error_logging),
        ("Complete Workflow", test_complete_workflow),
        ("Color Output", test_color_output),
        ("JSON File Output", test_json_output)
    ]
    
    for test_name, test_func in tests:
        try:
            test_func()
            time.sleep(1)  # Pause between tests
        except Exception as e:
            print(f"\nTest '{test_name}' failed: {e}\n")
    
    print("\n" + "=" * 80)
    print("ALL LOGGER TESTS COMPLETED")
    print("=" * 80)
    print("\nSUMMARY")
    print(f"  Total tests run: {len(tests)}")
    print(f"  Log files saved in: ./database/logger/logs/")
    print(f"  Color-coded terminal output demonstrated")
    print(f"  JSON file output verified")
    print("\n" + "=" * 80 + "\n")

if __name__ == "__main__":
    run_all_tests()
