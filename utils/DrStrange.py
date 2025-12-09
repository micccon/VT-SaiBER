"""
DrStrange.py - Conversation and System Logger
"""

import os
import json
from datetime import datetime
from pathlib import Path


class AgentLogger:
    """Logs all agent interactions and system events"""
    
    def __init__(self, log_dir: str = "logs"):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(exist_ok=True)
        
        # Create session-specific log file
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.log_file = self.log_dir / f"session_{timestamp}.log"
        self.json_file = self.log_dir / f"session_{timestamp}.json"
        
        self.conversation_history = []
        
        self._log_system("Logger initialized", {"log_file": str(self.log_file)})
    
    def log_user_query(self, query: str):
        """Log user input"""
        entry = {
            "timestamp": datetime.now().isoformat(),
            "type": "user_query",
            "content": query
        }
        self._write_entry(entry)
        self.conversation_history.append(entry)
    
    def log_agent_response(self, response: str, agent_name: str = "orchestrator"):
        """Log agent output"""
        entry = {
            "timestamp": datetime.now().isoformat(),
            "type": "agent_response",
            "agent": agent_name,
            "content": response
        }
        self._write_entry(entry)
        self.conversation_history.append(entry)
    
    def log_tool_call(self, tool_name: str, arguments: dict):
        """Log tool/function calls"""
        entry = {
            "timestamp": datetime.now().isoformat(),
            "type": "tool_call",
            "tool": tool_name,
            "arguments": arguments
        }
        self._write_entry(entry)
        self.conversation_history.append(entry)
    
    def log_tool_result(self, tool_name: str, result: str):
        """Log tool results"""
        entry = {
            "timestamp": datetime.now().isoformat(),
            "type": "tool_result",
            "tool": tool_name,
            "result": result[:500]  # Truncate long results
        }
        self._write_entry(entry)
        self.conversation_history.append(entry)
    
    def log_error(self, error: str, context: dict = None):
        """Log errors"""
        entry = {
            "timestamp": datetime.now().isoformat(),
            "type": "error",
            "error": error,
            "context": context or {}
        }
        self._write_entry(entry)
        self.conversation_history.append(entry)
    
    def _log_system(self, message: str, data: dict = None):
        """Log system events"""
        entry = {
            "timestamp": datetime.now().isoformat(),
            "type": "system",
            "message": message,
            "data": data or {}
        }
        self._write_entry(entry)
    
    def _write_entry(self, entry: dict):
        """Write entry to both text and JSON logs"""
        # Text log (human readable)
        with open(self.log_file, "a", encoding="utf-8") as f:
            timestamp = entry["timestamp"]
            entry_type = entry["type"].upper()
            
            if entry["type"] == "user_query":
                f.write(f"\n[{timestamp}] USER: {entry['content']}\n")
            elif entry["type"] == "agent_response":
                agent = entry.get("agent", "unknown")
                f.write(f"[{timestamp}] AGENT ({agent}): {entry['content']}\n")
            elif entry["type"] == "tool_call":
                f.write(f"[{timestamp}] TOOL CALL: {entry['tool']} - {entry['arguments']}\n")
            elif entry["type"] == "tool_result":
                f.write(f"[{timestamp}] TOOL RESULT: {entry['tool']} - {entry['result']}\n")
            elif entry["type"] == "error":
                f.write(f"[{timestamp}] ERROR: {entry['error']}\n")
            elif entry["type"] == "system":
                f.write(f"[{timestamp}] SYSTEM: {entry['message']}\n")
        
        # JSON log (machine readable)
        with open(self.json_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
    
    def save_summary(self):
        """Save conversation summary"""
        summary_file = self.log_dir / f"summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        summary = {
            "session_start": self.conversation_history[0]["timestamp"] if self.conversation_history else None,
            "session_end": datetime.now().isoformat(),
            "total_interactions": len([e for e in self.conversation_history if e["type"] in ["user_query", "agent_response"]]),
            "total_tool_calls": len([e for e in self.conversation_history if e["type"] == "tool_call"]),
            "total_errors": len([e for e in self.conversation_history if e["type"] == "error"]),
            "conversation": self.conversation_history
        }
        
        with open(summary_file, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2)
        
        print(f"\n📊 Session summary saved to: {summary_file}")
    
    def get_conversation_history(self) -> list:
        """Return full conversation history"""
        return self.conversation_history