import logging
from typing import Dict, Any
from tools.tool_result import ToolResult
from tools.base_tool import BaseTool
from tools.tool_metadata import ToolMetadata

logger = logging.getLogger(__name__)

class ToolRegistry:
    """Central registry for all tools available to the AI"""
    
    def __init__(self):
        self.tools: Dict[str, BaseTool] = {}
        self._tool_metadata: Dict[str, ToolMetadata] = {}
        
    def register_tool(self, tool: BaseTool):
        """
        Register a new tool with the system
        
        Args:
            tool: BaseTool instance to register
        """
        tool_name = tool.tool_name
        self.tools[tool_name] = tool
        
        # Extract and store metadata for each method
        for metadata in tool.get_metadata():
            full_name = f"{tool_name}.{metadata.name}"
            self._tool_metadata[full_name] = metadata
            
        logger.info(f"✓ Registered tool '{tool_name}' with {len(tool.get_metadata())} methods")
    
    def get_all_tools(self) -> Dict[str, Dict[str, Any]]:
        """Get all available tools and their metadata for AI"""
        tools_by_category = {}
        
        for tool_name, metadata in self._tool_metadata.items():
            category = metadata.category
            if category not in tools_by_category:
                tools_by_category[category] = []
            
            tools_by_category[category].append({
                "tool": tool_name,
                "description": metadata.description,
                "inputSchema": metadata.input_schema,
                "requires_admin": metadata.requires_admin
            })
        
        return tools_by_category
    
    def get_tool_list_for_ai(self) -> str:
        """Format tool list in a way that's easy for AI to understand"""
        tools = self.get_all_tools()
        output = ["Available Tools:\n"]
        
        for category, tool_list in tools.items():
            output.append(f"\n{'='*70}")
            output.append(f"{category.upper().replace('_', ' ')}")
            output.append(f"{'='*70}")
            
            for tool in tool_list:
                output.append(f"\n📦 {tool['tool']}")
                output.append(f"   {tool['description']}")
                
                # Format parameters
                schema = tool['inputSchema']
                properties = schema.get('properties', {})
                required = schema.get('required', [])
                
                if properties:
                    output.append("   Parameters:")
                    for param_name, param_info in properties.items():
                        req_marker = "REQUIRED" if param_name in required else "optional"
                        output.append(f"     • {param_name} ({req_marker}): {param_info.get('description', 'No description')}")
                
                if tool['requires_admin']:
                    output.append("   ⚠️  Requires administrator privileges")
        
        return "\n".join(output)
    
    async def execute_tool(self, tool_path: str, **kwargs) -> ToolResult:
        """
        Execute a tool method by its path (e.g., 'vision.ping_scan')
        
        Args:
            tool_path: Full path to tool method (format: 'tool_name.method_name')
            **kwargs: Parameters to pass to the method
            
        Returns:
            ToolResult with execution outcome
        """
        try:
            # Parse tool path
            parts = tool_path.split('.')
            if len(parts) != 2:
                return ToolResult(
                    success=False,
                    tool_name=tool_path,
                    error=f"Invalid tool path format. Expected 'tool.method', got '{tool_path}'"
                )
            
            tool_name, method_name = parts
            
            # Get tool
            if tool_name not in self.tools:
                return ToolResult(
                    success=False,
                    tool_name=tool_path,
                    error=f"Tool '{tool_name}' not found. Available tools: {list(self.tools.keys())}"
                )
            
            tool = self.tools[tool_name]
            
            # Validate parameters
            is_valid, error_msg = tool.validate_parameters(method_name, kwargs)
            if not is_valid:
                return ToolResult(
                    success=False,
                    tool_name=tool_path,
                    error=f"Parameter validation failed: {error_msg}"
                )
            
            # Execute method
            return await tool.execute(method_name, **kwargs)
            
        except Exception as e:
            logger.exception(f"Error executing tool {tool_path}")
            return ToolResult(
                success=False,
                tool_name=tool_path,
                error=f"Execution error: {str(e)}"
            )