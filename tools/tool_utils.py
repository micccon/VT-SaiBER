"""
Utilities for converting between custom tool formats and Strands tools.
Provides helpers for creating Strands-compatible tools from existing schemas.
"""

from typing import Dict, Any, Callable, List
from strands import tool
from tools.tool_result import ToolResult


def tool_result_to_dict(result: ToolResult) -> Dict[str, Any]:
    """
    Convert ToolResult to dictionary format for Strands.
    
    Args:
        result: ToolResult instance
    
    Returns:
        Dictionary representation suitable for Strands tools
    """
    return result.to_dict()


def create_strands_tool_from_schema(
    schema: Dict[str, Any],
    executor: Callable
) -> Callable:
    """
    Create a Strands-compatible tool from JSON schema and executor function.
    
    This allows you to convert your existing schema-based tools to Strands format.
    
    Args:
        schema: Tool schema with name, description, and inputSchema
        executor: Async function that executes the tool logic
    
    Returns:
        Decorated tool function ready for Strands agents
    
    Example:
        >>> schema = {
        ...     "name": "my_tool",
        ...     "description": "Does something",
        ...     "inputSchema": {
        ...         "type": "object",
        ...         "properties": {"param": {"type": "string"}},
        ...         "required": ["param"]
        ...     }
        ... }
        >>> async def execute(param: str) -> dict:
        ...     return {"result": param}
        >>> my_tool = create_strands_tool_from_schema(schema, execute)
    """
    tool_name = schema["name"]
    description = schema["description"]
    
    # Create decorated function with proper docstring
    async def tool_function(**kwargs) -> dict:
        return await executor(**kwargs)
    
    tool_function.__name__ = tool_name
    tool_function.__doc__ = description
    
    # Apply Strands tool decorator
    return tool(tool_function)


def load_tools_from_module(module_path: str) -> List[Callable]:
    """
    Load all @tool decorated functions from a module.
    
    Args:
        module_path: Path to Python module containing tools
    
    Returns:
        List of tool functions ready for Strands agents
    
    Example:
        >>> tools = load_tools_from_module("tools.vision.vision_tools")
        >>> agent = Agent(tools=tools)
    """
    import importlib
    import inspect
    
    module = importlib.import_module(module_path)
    
    tools = []
    for name, obj in inspect.getmembers(module):
        # Check if it's a Strands tool (has the tool decorator attributes)
        if callable(obj) and hasattr(obj, '__wrapped__'):
            tools.append(obj)
    
    return tools