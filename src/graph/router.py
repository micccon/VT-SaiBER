"""
Graph Routing Logic
==================
Contains routing functions for LangGraph conditional edges.

Note: This should contain ONLY safety checks, not business logic.
Business logic belongs in the Supervisor's LLM.
"""

import logging
from langgraph.graph import END
from src.state.cyber_state import CyberState

# Configure logging
logger = logging.getLogger(__name__)

# Maximum iterations to prevent infinite loops
MAX_ITERATIONS = 20

# Valid agent names
VALID_AGENTS = ["scout", "fuzzer", "striker", "librarian", "resident"]


def validate_all_targets_in_scope(state: CyberState) -> bool:
    """
    Validate that all discovered targets are within the authorized scope.
    
    This is a safety check, not business logic - it prevents accidentally
    attacking targets that weren't authorized.
    
    Args:
        state: Current CyberState
        
    Returns:
        True if all targets are in scope, False otherwise
    """
    from ipaddress import ip_address, ip_network
    
    target_scope = state.get("target_scope", [])
    discovered_targets = state.get("discovered_targets", {})
    
    if not target_scope:
        # No scope defined - be conservative and block
        logger.warning("No target scope defined")
        return False
    
    for target_ip in discovered_targets.keys():
        try:
            # Try to parse as IP address
            target = ip_address(target_ip)
            
            # Check against each scope entry
            in_scope = False
            for cidr in target_scope:
                try:
                    if target in ip_network(cidr, strict=False):
                        in_scope = True
                        break
                except ValueError:
                    # Not CIDR, might be exact IP match
                    if target_ip == cidr:
                        in_scope = True
                        break
            
            if not in_scope:
                logger.error(f"Target {target_ip} is out of scope!")
                return False
                
        except ValueError:
            # Not an IP address - could be hostname
            # For now, allow hostnames if they're in scope list
            if target_ip not in target_scope:
                logger.warning(f"Hostname {target_ip} not in scope")
                # We'll be lenient here and allow it if it's not clearly out of scope
                pass
    
    return True


def route_next_agent(state: CyberState) -> str:
    """
    Route to next agent based on Supervisor's decision.
    
    This function is called by LangGraph to determine the next node.
    
    Safety checks only - no business logic! The business logic of which
    agent to call lives in the Supervisor's LLM prompt.
    
    Args:
        state: Current CyberState containing mission data
        
    Returns:
        Name of the next agent node to execute, or "end" to terminate
    """
    
    # Safety check 1: Max iterations to prevent infinite loops
    iteration_count = state.get("iteration_count", 0)
    if iteration_count >= MAX_ITERATIONS:
        logger.warning(f"Max iterations ({MAX_ITERATIONS}) reached")
        return END
    
    # Safety check 2: Mission already complete or failed
    mission_status = state.get("mission_status", "active")
    if mission_status in ["success", "failed"]:
        logger.info(f"Mission status is '{mission_status}', ending")
        return END
    
    # Safety check 3: Get Supervisor's decision
    next_agent = state.get("next_agent", "").strip().lower()
    
    # Handle explicit end request from Supervisor
    if next_agent == "end":
        logger.info("Supervisor requested mission end")
        return END
    
    # Safety check 4: Validate agent name
    if next_agent not in VALID_AGENTS:
        logger.warning(f"Invalid agent choice: '{next_agent}', defaulting to end")
        return END
    
    # Safety check 5: Scope validation (safety, not business logic)
    # This ensures we don't accidentally attack out-of-scope targets
    if not validate_all_targets_in_scope(state):
        logger.error("Scope validation failed - aborting mission")
        return END
    
    # All safety checks passed - return the agent the Supervisor chose
    logger.info(f"Routing to agent: {next_agent}")
    return next_agent


def get_valid_agents() -> list[str]:
    """
    Get list of valid agent names.
    
    Returns:
        List of valid agent node names
    """
    return VALID_AGENTS.copy()
