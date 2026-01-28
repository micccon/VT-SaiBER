"""
This simplifies the tasks that are given to the agents through the agent controller
The tasks are jsons formatted like the following example:
{
  "tasks": [
    {
      "agent_name": "VisionAgent",
      "method_name": "ping_scan",
      "params": {"target": "scanme.nmap.org"}
    }
}
You will ony input the task portion, i.e. the "agent_name", "method_name"....

This module aims to:
1. Simplify and universalize the tasks given to agents
2. Provide an easy way to convert the json text given by llm to objects
"""

import json
from dataclasses import dataclass
from typing import Any, Dict

@dataclass
class AvengerTask:
    agent_name: str
    method_name: str
    params: Dict[str, Any]
    task_json: str

    def __init__(self, json_str: str):
        try:
            data = json.loads(json_str)
            self.agent_name=data["agent_name"],
            self.method_name=data["method_name"],
            self.params=data.get("params", {})
            self.task_json = json.dumps(data)
        
        except KeyError as e:
            raise KeyError(f"Missing required task field: {e}")
        
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON format: {e.msg}") from e
