"""
Mock implementations for testing orchestrator without LLM/Prompt components.

Use these until other team members finish their implementations.
"""
from orchestrator.interfaces import IPromptBuilder, ILLMClient, IReportGenerator
from blueprints.schemas import ExecutionPlan, Task, AvengerResult


class MockPromptBuilder(IPromptBuilder):
    """
    Mock prompt builder that returns a simple formatted prompt.
    
    Replace this with real implementation from prompt person.
    """
    
    def build_prompt(self, user_query: str, agent_registry: dict, context: dict = None) -> str:
        """Return a mock prompt for testing."""
        agent_names = list(agent_registry.keys())
        
        prompt = f"""
Mock Prompt for Testing
=======================
User Query: {user_query}
Available Agents: {', '.join(agent_names)}

This is a placeholder prompt. The actual prompt builder will create
a detailed, structured prompt with examples and instructions.
"""
        return prompt


class MockLLMClient(ILLMClient):
    """
    Mock LLM client that returns hardcoded plans based on keywords.
    
    Replace this with real implementation from LLM person.
    """
    
    async def generate_plan(self, prompt: str) -> ExecutionPlan:
        """
        Generate a mock execution plan based on prompt keywords.
        
        This simulates what the LLM would return.
        """
        # Simple keyword detection for different scenarios
        prompt_lower = prompt.lower()
        
        # Scenario 1: Simple port scan
        if "port" in prompt_lower:
            return ExecutionPlan(
                tasks=[
                    Task(
                        task_id=1,
                        agent="VisionAgent",
                        action="ping_scan",
                        target="scanme.nmap.org",
                        params={},
                        dependencies=[]
                    ),
                    Task(
                        task_id=2,
                        agent="VisionAgent",
                        action="port_scan",
                        target="scanme.nmap.org",
                        params={"ports": "22,80,443,8080"},
                        dependencies=[1]
                    )
                ]
            )
        
        # Scenario 2: Service detection
        elif "service" in prompt_lower or "version" in prompt_lower:
            return ExecutionPlan(
                tasks=[
                    Task(
                        task_id=1,
                        agent="VisionAgent",
                        action="service_scan",
                        target="scanme.nmap.org",
                        params={"ports": "22,80"},
                        dependencies=[]
                    )
                ]
            )
        
        # Scenario 3: Quick scan (default)
        else:
            return ExecutionPlan(
                tasks=[
                    Task(
                        task_id=1,
                        agent="VisionAgent",
                        action="quick_scan",
                        target="scanme.nmap.org",
                        params={},
                        dependencies=[]
                    )
                ]
            )


class MockReportGenerator(IReportGenerator):
    """
    Mock report generator for testing.
    
    Can be replaced with more sophisticated version later.
    """
    
    def generate_summary(self, results: list, user_query: str) -> str:
        """Generate a simple text summary from results."""
        lines = [f"Execution Summary for: '{user_query}'", "=" * 50, ""]
        
        for result in results:
            lines.append(f"Task {result.task_id}: {result.status.upper()}")
            
            if result.status == "success" and result.output:
                hosts = result.output.get('hosts', [])
                lines.append(f"  - Scanned {len(hosts)} host(s)")
                
                for host in hosts:
                    addresses = [a['addr'] for a in host.get('addresses', [])]
                    lines.append(f"  - Host: {', '.join(addresses)}")
                    lines.append(f"    Status: {host.get('status', 'unknown')}")
                    
                    ports = host.get('ports', [])
                    open_ports = [p for p in ports if p.get('state') == 'open']
                    if open_ports:
                        lines.append(f"    Open Ports: {len(open_ports)}")
                        for port in open_ports[:5]:  # Show first 5
                            service = port.get('service', {}).get('name', 'unknown')
                            lines.append(f"      - {port['port']}/{port['protocol']}: {service}")
            
            elif result.error_message:
                lines.append(f"  - Error: {result.error_message}")
            
            lines.append("")
        
        return "\n".join(lines)
        