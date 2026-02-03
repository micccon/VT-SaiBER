"""Validation Module for VT-SaiBER Orchestrator

This module provides validation functions for:
    - User input sanitization and security checks
    - Configuration file validation
    - Task plan validation
    - Network target validation (IP, hostname, CIDR)

Usage:
    from orchestrator.validators import (
        validate_user_query,
        validate_config,
        validate_execution_plan
    )
    
    # Validate user input
    is_valid, error_msg = validate_user_query(query)
    if not is_valid:
        raise ValueError(error_msg)

Security:
    All validation functions follow the principle of "fail securely".
    Invalid input returns False with descriptive error messages.
    No exceptions are raised to prevent information leakage.

Author: Mihir Patel
Date: November 2025
Status: Skeleton - To be implemented
"""

import re
import ipaddress
from pathlib import Path
from typing import Tuple, Dict, Any, List
from blueprints.schemas import ExecutionPlan, Task


# =============================================================================
# USER INPUT VALIDATION
# =============================================================================

def validate_user_query(query: str, max_length: int = 1000) -> Tuple[bool, str]:
    """
    Validate user query for security and format.
    
    Checks:
        - Length within limits
        - No malicious patterns (command injection, SQL injection)
        - Contains printable characters only
        - Not empty or whitespace-only
    
    Args:
        query: User input query string
        max_length: Maximum allowed length (default: 1000)
    
    Returns:
        Tuple[bool, str]: (is_valid, error_message)
    
    Example:
        >>> validate_user_query("Scan 192.168.1.1")
        (True, "")
        >>> validate_user_query("rm -rf /")
        (False, "Query contains potentially dangerous patterns")
    
    TODO: Implement validation logic
    """
    # TODO: Implement
    # - Check length
    # - Check for command injection patterns
    # - Check for SQL injection
    # - Check for path traversal
    # - Validate character set
    return True, ""


def validate_target(target: str) -> Tuple[bool, str]:
    """
    Validate network target (IP, hostname, or CIDR).
    
    Args:
        target: IP address, hostname, or CIDR notation
    
    Returns:
        Tuple[bool, str]: (is_valid, error_message)
    
    Example:
        >>> validate_target("192.168.1.1")
        (True, "")
        >>> validate_target("scanme.nmap.org")
        (True, "")
        >>> validate_target("../etc/passwd")
        (False, "Invalid target format")
    
    TODO: Implement validation logic
    """
    # TODO: Implement
    # - Validate IPv4/IPv6
    # - Validate hostname format
    # - Validate CIDR notation
    # - Check against blocked ranges (RFC1918, localhost, etc.)
    return True, ""


def validate_ports(ports: str) -> Tuple[bool, str]:
    """
    Validate port specification string.
    
    Args:
        ports: Port specification (e.g., "80", "80,443", "1-1000")
    
    Returns:
        Tuple[bool, str]: (is_valid, error_message)
    
    Example:
        >>> validate_ports("80,443")
        (True, "")
        >>> validate_ports("1-65535")
        (True, "")
        >>> validate_ports("99999")
        (False, "Port number out of range")
    
    TODO: Implement validation logic
    """
    # TODO: Implement
    # - Validate port numbers (1-65535)
    # - Validate range format
    # - Validate comma-separated lists
    return True, ""


# =============================================================================
# CONFIGURATION VALIDATION
# =============================================================================

def validate_config(config: Dict[str, Any]) -> Tuple[bool, str]:
    """
    Validate orchestrator configuration.
    
    Args:
        config: Loaded configuration dictionary
    
    Returns:
        Tuple[bool, str]: (is_valid, error_message)
    
    Checks:
        - Required keys present
        - File paths exist
        - Valid formats for each field
        - Security settings are properly configured
    
    TODO: Implement validation logic
    """
    # TODO: Implement
    # - Check required keys (database, llm, security)
    # - Validate file paths exist
    # - Check allowed_target_scopes format
    # - Validate log paths are writable
    return True, ""


def validate_agent_registry(registry: Dict[str, Any]) -> Tuple[bool, str]:
    """
    Validate agent registry structure.
    
    Args:
        registry: Loaded agent registry dictionary
    
    Returns:
        Tuple[bool, str]: (is_valid, error_message)
    
    Checks:
        - Required fields for each agent
        - Module and class paths are valid
        - Capabilities are properly defined
    
    TODO: Implement validation logic
    """
    # TODO: Implement
    # - Check agent structure
    # - Validate module_path and class_name
    # - Check capabilities format
    # - Ensure no duplicate agent names
    return True, ""


# =============================================================================
# EXECUTION PLAN VALIDATION
# =============================================================================

def validate_execution_plan(plan: ExecutionPlan) -> Tuple[bool, str]:
    """
    Validate execution plan structure and logic.
    
    Args:
        plan: ExecutionPlan object from LLM
    
    Returns:
        Tuple[bool, str]: (is_valid, error_message)
    
    Checks:
        - All tasks have valid structure
        - Dependencies reference valid task IDs
        - No circular dependencies
        - Agent names exist in registry
    """
    # Check if plan has tasks
    if not plan or not hasattr(plan, 'tasks'):
        return False, "Invalid execution plan: missing tasks attribute"
    
    if not plan.tasks or len(plan.tasks) == 0:
        return False, "Execution plan has no tasks"
    
    # Collect all task IDs
    task_ids = set()
    for task in plan.tasks:
        if task.task_id in task_ids:
            return False, f"Duplicate task_id found: {task.task_id}"
        task_ids.add(task.task_id)
    
    # Validate dependencies reference valid task IDs
    for task in plan.tasks:
        if hasattr(task, 'dependencies') and task.dependencies:
            for dep_id in task.dependencies:
                if dep_id not in task_ids:
                    return False, f"Task {task.task_id} depends on non-existent task {dep_id}"
    
    # Check for circular dependencies
    is_acyclic, cycle_msg = check_circular_dependencies(plan.tasks)
    if not is_acyclic:
        return False, cycle_msg
    
    return True, ""


def validate_task(task: Task, available_agents: List[str]) -> Tuple[bool, str]:
    """
    Validate individual task structure.
    
    Args:
        task: Task object
        available_agents: List of available agent names
    
    Returns:
        Tuple[bool, str]: (is_valid, error_message)
    """
    # Check required fields
    if not hasattr(task, 'task_id') or task.task_id is None:
        return False, "Task missing required field: task_id"
    
    if not hasattr(task, 'agent') or not task.agent:
        return False, f"Task {task.task_id} missing required field: agent"
    
    if not hasattr(task, 'action') or not task.action:
        return False, f"Task {task.task_id} missing required field: action"
    
    # Validate agent exists in available agents
    if available_agents and task.agent not in available_agents:
        return False, f"Task {task.task_id} references unknown agent: {task.agent}"
    
    # Validate target if present
    if hasattr(task, 'target') and task.target:
        is_valid, err = validate_target(task.target)
        if not is_valid:
            return False, f"Task {task.task_id} has invalid target: {err}"
    
    return True, ""


def check_circular_dependencies(tasks: List[Task]) -> Tuple[bool, str]:
    """
    Check for circular dependencies in task list.
    
    Args:
        tasks: List of Task objects
    
    Returns:
        Tuple[bool, str]: (is_valid, error_message)
    
    Example:
        Task 1 depends on Task 2
        Task 2 depends on Task 1  # CIRCULAR - INVALID
    """
    # Build adjacency list (dependency graph)
    graph = {}
    for task in tasks:
        task_id = task.task_id
        deps = task.dependencies if hasattr(task, 'dependencies') and task.dependencies else []
        graph[task_id] = deps
    
    # Track visited and recursion stack for cycle detection
    visited = set()
    rec_stack = set()
    
    def has_cycle(node, path):
        visited.add(node)
        rec_stack.add(node)
        path.append(node)
        
        for neighbor in graph.get(node, []):
            if neighbor not in visited:
                if has_cycle(neighbor, path):
                    return True
            elif neighbor in rec_stack:
                # Found cycle
                return True
        
        path.pop()
        rec_stack.remove(node)
        return False
    
    # Check each node for cycles
    for task_id in graph:
        if task_id not in visited:
            if has_cycle(task_id, []):
                return False, f"Circular dependency detected involving task {task_id}"
    
    return True, ""


# =============================================================================
# OUTPUT VALIDATION (Scan Results & Agent Responses)
# =============================================================================

def validate_scan_output(scan_result: Dict[str, Any]) -> Tuple[bool, str]:
    """
    Validate Nmap scan output structure.
    
    Args:
        scan_result: Dictionary containing scan results
    
    Returns:
        Tuple[bool, str]: (is_valid, error_message)
    
    Checks:
        - Required fields are present (status, output)
        - Status is valid (success, error, running)
        - Output format is correct
    """
    if not scan_result:
        return False, "Scan result is empty or None"
    
    if not isinstance(scan_result, dict):
        return False, f"Scan result must be a dictionary, got {type(scan_result)}"
    
    # Check for status field
    if 'status' not in scan_result:
        return False, "Scan result missing required field: status"
    
    valid_statuses = ['success', 'error', 'running', 'completed', 'failed']
    if scan_result['status'].lower() not in valid_statuses:
        return False, f"Invalid scan status: {scan_result['status']}"
    
    return True, ""


def validate_agent_result(result: Any) -> Tuple[bool, str]:
    """
    Validate agent response structure.
    
    Args:
        result: Agent result object or dictionary
    
    Returns:
        Tuple[bool, str]: (is_valid, error_message)
    """
    if result is None:
        return False, "Agent result is None"
    
    # Handle Google ADK response format: {'content': [...]}
    if isinstance(result, dict):
        # Check for content-based responses (MCP tools)
        if 'content' in result:
            content = result['content']
            if not isinstance(content, list) or len(content) == 0:
                return False, "Agent result has empty content array"
            # Validate each content item has required fields
            for item in content:
                if 'type' not in item:
                    return False, "Content item missing 'type' field"
            return True, ""
        
        # Check for transfer_to_agent responses
        if 'result' in result:
            # This is fine - transfer responses return {'result': None}
            return True, ""
        
        # Check for direct scan results with success field
        if 'success' in result:
            return True, ""
    
    # If it has attributes (object), check those
    elif hasattr(result, 'content') or hasattr(result, 'status'):
        return True, ""
    
    # Unknown format but not None - accept it
    return True, ""


# =============================================================================
# SECURITY VALIDATION
# =============================================================================

def validate_api_key(api_key: str) -> Tuple[bool, str]:
    """
    Validate API key format (not authenticity).
    
    Args:
        api_key: API key string
    
    Returns:
        Tuple[bool, str]: (is_valid, error_message)
    
    Note: This only validates format, not whether the key is active.
    
    TODO: Implement validation logic
    """
    # TODO: Implement
    # - Check minimum length
    # - Validate character set
    # - Check for common placeholder patterns
    return True, ""


def sanitize_filename(filename: str) -> str:
    """
    Sanitize filename to prevent path traversal.
    
    Args:
        filename: Input filename
    
    Returns:
        str: Sanitized filename safe for filesystem operations
    
    TODO: Implement sanitization logic
    """
    # TODO: Implement
    # - Remove path separators
    # - Remove null bytes
    # - Limit length
    # - Remove dangerous characters
    return filename


def is_safe_command(command: str) -> bool:
    """
    Check if command is safe to execute.
    
    Args:
        command: Command string to validate
    
    Returns:
        bool: True if command is safe
    
    TODO: Implement validation logic
    """
    # TODO: Implement
    # - Whitelist safe commands (nmap, etc.)
    # - Block shell metacharacters
    # - Check for command chaining (&&, ||, ;)
    # - Validate against command injection patterns
    return True


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def validate_ipv4(ip: str) -> bool:
    """
    Validate IPv4 address format.
    
    TODO: Implement using ipaddress module
    """
    try:
        ipaddress.IPv4Address(ip)
        return True
    except ValueError:
        return False


def validate_hostname(hostname: str) -> bool:
    """
    Validate hostname format (RFC 1123).
    
    TODO: Implement using regex
    """
    # TODO: Implement
    # - Check length (max 253 chars)
    # - Validate label format
    # - Check for valid characters
    return True


def validate_cidr(cidr: str) -> bool:
    """
    Validate CIDR notation.
    
    TODO: Implement using ipaddress module
    """
    try:
        ipaddress.IPv4Network(cidr)
        return True
    except ValueError:
        return False


# =============================================================================
# VALIDATION SUITE
# =============================================================================

class ValidationSuite:
    """
    Complete validation suite for orchestrator.
    
    Usage:
        validator = ValidationSuite(config_path="./config.yaml")
        is_valid, errors = validator.validate_all()
    
    TODO: Implement class methods
    """
    
    def __init__(self, config_path: str):
        """Initialize validator with configuration."""
        self.config_path = config_path
        self.errors: List[str] = []
    
    def validate_all(self) -> Tuple[bool, List[str]]:
        """
        Run all validation checks.
        
        Returns:
            Tuple[bool, List[str]]: (all_valid, list_of_errors)
        
        TODO: Implement
        """
        # TODO: Implement
        # - Validate config
        # - Validate agent registry
        # - Validate file permissions
        # - Check dependencies installed
        return True, []
    
    def validate_runtime_environment(self) -> Tuple[bool, List[str]]:
        """
        Validate runtime environment (nmap installed, etc.).
        
        TODO: Implement
        """
        # TODO: Implement
        # - Check nmap installed
        # - Check Python version
        # - Verify required packages
        return True, []


if __name__ == "__main__":
    # TODO: Add self-tests here
    print("Validation module loaded (not yet implemented)")
    print("Available validators:")
    print("  - validate_user_query()")
    print("  - validate_target()")
    print("  - validate_ports()")
    print("  - validate_config()")
    print("  - validate_agent_registry()")
    print("  - validate_execution_plan()")
    print("\nStatus: Skeleton ready for implementation")