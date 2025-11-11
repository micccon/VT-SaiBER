"""
VT-SaiBER Streamlit Frontend
A chat interface for the VT-SaiBER security scanning AI system.
"""

import streamlit as st
import requests
import json
import time
from datetime import datetime
from typing import List, Dict, Any
import asyncio
from concurrent.futures import ThreadPoolExecutor
import threading

# Import your existing modules
from interaction.api.thanos import process_user_input, validate_input
from orchestrator.shield import ShieldOrchestrator
# from config.yaml import load_config

# Page configuration
st.set_page_config(
    page_title="VT-SaiBER - Security AI Assistant",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for chat interface
st.markdown("""
<style>


.chat-message {
    margin-bottom: 1rem;
    padding: 1rem;
    border-radius: 10px;
    max-width: 80%;
}

.user-message {
    background-color: #4f4f4f;
    color: white;
    margin-left: auto;
    text-align: right;
}

.assistant-message {
    background-color: #4f4f4f;
    color: white;
    margin-right: auto;
}

.message-timestamp {
    font-size: 0.8em;
    color: white;
    margin-bottom: 0.5rem;
}


.scan-result {
    background-color: #f8f9fa;
    border: 1px solid #dee2e6;
    border-radius: 5px;
    padding: 1rem;
    margin: 0.5rem 0;
}

.scan-result h4 {
    color: #495057;
    margin-top: 0;
}

.status-indicator {
    display: inline-block;
    width: 10px;
    height: 10px;
    border-radius: 50%;
    margin-right: 0.5rem;
}

.status-success { background-color: #28a745; }
.status-warning { background-color: #ffc107; }
.status-error { background-color: #dc3545; }
.status-info { background-color: #17a2b8; }
</style>
""", unsafe_allow_html=True)

class SaiBerChat:
    def __init__(self):
        # self.config = self.load_config()
        self.orchestrator = ShieldOrchestrator("config.yaml")
        
        # Initialize session state for chat history
        if "messages" not in st.session_state:
            st.session_state.messages = []
        if "scan_history" not in st.session_state:
            st.session_state.scan_history = []
        if "current_scan" not in st.session_state:
            st.session_state.current_scan = None

    def load_config(self):
        """Load configuration from config.yaml"""
        try:
            import yaml
            with open("config.yaml", "r") as f:
                return yaml.safe_load(f)
        except Exception as e:
            st.error(f"Failed to load config: {e}")
            return {}

    def add_message(self, role: str, content: str, message_type: str = "text", metadata: Dict = None):
        """Add a message to the chat history"""
        message = {
            "role": role,
            "content": content,
            "timestamp": datetime.now(),
            "type": message_type,
            "metadata": metadata or {}
        }
        st.session_state.messages.append(message)

    def validate_user_input(self, user_input: str) -> tuple[bool, str]:
        """Validate user input using Thanos security system"""
        try:
            # Try to validate as network target
            result = process_user_input(user_input, "json")
            return True, f"Validated target: {result}"
        except ValueError as e:
            # If it's not a network target, allow general queries
            if len(user_input.strip()) > 0 and len(user_input) <= 500:
                return True, "General query accepted"
            return False, str(e)
        except Exception as e:
            return False, f"Validation error: {str(e)}"

    def execute_scan_async(self, target: str, scan_type: str = "quick_scan"):
        """Execute scan in a separate thread"""
        def run_scan():
            try:
                st.session_state.current_scan = {
                    "status": "running",
                    "target": target,
                    "scan_type": scan_type,
                    "start_time": datetime.now()
                }
                
                # Here you would integrate with your vision tools
                # For now, simulate a scan
                time.sleep(2)  # Simulate scan time
                
                # Mock scan result
                result = {
                    "target": target,
                    "scan_type": scan_type,
                    "status": "completed",
                    "findings": [
                        {
                            "port": 80,
                            "service": "http",
                            "version": "Apache 2.4.41",
                            "status": "open"
                        },
                        {
                            "port": 443,
                            "service": "https",
                            "version": "Apache 2.4.41",
                            "status": "open"
                        }
                    ],
                    "completion_time": datetime.now()
                }
                
                st.session_state.current_scan = result
                st.session_state.scan_history.append(result)
                
            except Exception as e:
                st.session_state.current_scan = {
                    "status": "error",
                    "error": str(e),
                    "target": target
                }
        
        thread = threading.Thread(target=run_scan)
        thread.start()

    def process_user_query(self, user_input: str):
        """Process user query and generate response"""
        is_valid, validation_message = self.validate_user_input(user_input)
        
        if not is_valid:
            self.add_message("assistant", f"❌ Invalid input: {validation_message}", "error")
            return

        self.add_message("user", user_input)
        
        # Check if this looks like a scan request
        scan_keywords = ["scan", "ping", "port", "service", "nmap", "network"]
        is_scan_request = any(keyword in user_input.lower() for keyword in scan_keywords)
        
        if is_scan_request:
            # Extract target from input (simplified)
            words = user_input.split()
            target = None
            for word in words:
                if any(char.isdigit() for char in word) or "." in word:
                    target = word.strip(".,!?")
                    break
            
            if target:
                self.add_message("assistant", f"🔍 Initiating security scan for target: {target}", "scan_start")
                self.execute_scan_async(target, "quick_scan")
            else:
                self.add_message("assistant", "Please specify a valid target (IP address or hostname) for scanning.", "error")
        else:
            # General AI response
            response = self.generate_ai_response(user_input)
            self.add_message("assistant", response)

    def generate_ai_response(self, query: str) -> str:
        """Generate AI response using Jarvis LLM"""
        try:
            # This would integrate with your Jarvis LLM system
            # For now, return a mock response
            responses = {
                "help": "I can help you with network security scanning. Try commands like 'scan 192.168.1.1' or 'ping scanme.nmap.org'",
                "what can you do": "I can perform various network scans including ping sweeps, port scanning, service detection, and comprehensive security assessments.",
                "how to use": "Simply type your security scanning request. For example: 'quick scan of example.com' or 'check ports 80,443 on 192.168.1.1'"
            }
            
            query_lower = query.lower()
            for key, response in responses.items():
                if key in query_lower:
                    return response
            
            return "I'm here to help with network security assessments. What would you like to scan or analyze?"
            
        except Exception as e:
            return f"Sorry, I encountered an error: {str(e)}"

    def display_chat_message(self, message: Dict):
        """Display a single chat message"""
        timestamp = message["timestamp"].strftime("%H:%M:%S")
        
        if message["role"] == "user":
            st.markdown(f"""
            <div class="chat-message user-message">
                <div class="message-timestamp">You • {timestamp}</div>
                {message["content"]}
            </div>
            """, unsafe_allow_html=True)
        else:
            if message["type"] == "scan_start":
                st.markdown(f"""
                <div class="chat-message assistant-message">
                    <div class="message-timestamp">VT-SaiBER • {timestamp}</div>
                    <div class="status-indicator status-info"></div>
                    {message["content"]}
                </div>
                """, unsafe_allow_html=True)
            elif message["type"] == "error":
                st.markdown(f"""
                <div class="chat-message assistant-message">
                    <div class="message-timestamp">VT-SaiBER • {timestamp}</div>
                    <div class="status-indicator status-error"></div>
                    {message["content"]}
                </div>
                """, unsafe_allow_html=True)
            else:
                st.markdown(f"""
                <div class="chat-message assistant-message">
                    <div class="message-timestamp">VT-SaiBER • {timestamp}</div>
                    {message["content"]}
                </div>
                """, unsafe_allow_html=True)

    def display_scan_result(self, scan_result: Dict):
        """Display scan results in a formatted way"""
        st.markdown("### 🔍 Scan Results")
        
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Target", scan_result.get("target", "Unknown"))
        with col2:
            st.metric("Scan Type", scan_result.get("scan_type", "Unknown"))
        with col3:
            status = scan_result.get("status", "Unknown")
            if status == "completed":
                st.metric("Status", "✅ Completed")
            elif status == "running":
                st.metric("Status", "🔄 Running")
            else:
                st.metric("Status", "❌ Error")
        
        if "findings" in scan_result and scan_result["findings"]:
            st.markdown("**Open Ports & Services:**")
            for finding in scan_result["findings"]:
                with st.expander(f"Port {finding['port']} - {finding['service'].upper()}"):
                    st.write(f"**Status:** {finding['status']}")
                    if "version" in finding:
                        st.write(f"**Version:** {finding['version']}")
        
        if "error" in scan_result:
            st.error(f"Scan Error: {scan_result['error']}")

    def run(self):
        """Main Streamlit application"""
        # Sidebar
        with st.sidebar:
            st.title("🛡️ VT-SaiBER")
            st.markdown("**Security AI Assistant**")
            
            st.markdown("---")
            st.markdown("### Quick Actions")
            
            if st.button("🆘 Help"):
                self.add_message("assistant", 
                    "Welcome to VT-SaiBER! I can help you with:\n\n"
                    "• Network scanning (ping, port, service)\n"
                    "• Security assessments\n"
                    "• Vulnerability analysis\n\n"
                    "Try: 'scan 192.168.1.1' or 'ping scanme.nmap.org'"
                )
            
            if st.button("📊 Scan History"):
                if st.session_state.scan_history:
                    st.markdown("### Recent Scans")
                    for scan in reversed(st.session_state.scan_history[-5:]):
                        status_icon = "✅" if scan.get("status") == "completed" else "❌"
                        st.write(f"{status_icon} {scan.get('target', 'Unknown')} - {scan.get('scan_type', 'Unknown')}")
                else:
                    st.write("No scan history yet.")
            
            st.markdown("---")
            st.markdown("### System Status")
            st.success("🟢 Orchestrator Online")
            st.success("🟢 Security Validation Active")
            st.info("🔵 Ready for commands")

        # Main chat interface
        st.markdown('<div class="sticky-header">', unsafe_allow_html=True)
        st.title("VT-SaiBER Security AI Assistant")
        st.markdown("Ask me to scan networks, analyze security, or perform reconnaissance.")
        st.markdown('</div>', unsafe_allow_html=True)
        
        # Chat container
        st.markdown('<div class="chat-container">', unsafe_allow_html=True)
        
        # Display chat history
        for message in st.session_state.messages[-50:]:  # Show last 50 messages
            self.display_chat_message(message)
        
        # Display current scan status
        if st.session_state.current_scan:
            if st.session_state.current_scan.get("status") == "running":
                with st.spinner("🔍 Scanning in progress..."):
                    time.sleep(0.5)  # Allow UI to update
            elif st.session_state.current_scan.get("status") == "completed":
                self.display_scan_result(st.session_state.current_scan)
                st.session_state.current_scan = None  # Clear after displaying
        
        st.markdown('</div>', unsafe_allow_html=True)
        
        # Input area
        st.markdown('<div class="input-container">', unsafe_allow_html=True)
        col1, col2 = st.columns([6, 1])
        
        with col1:
            user_input = st.text_input(
                "Type your security command or question...",
                key="user_input",
                placeholder="e.g., 'scan 192.168.1.1' or 'what can you do?'",
                label_visibility="collapsed"
            )
        
        with col2:
            send_button = st.button("Send 🚀", use_container_width=True)
        
        st.markdown('</div>', unsafe_allow_html=True)
        
        # Handle user input
        if send_button and user_input.strip():
            self.process_user_query(user_input.strip())
            st.rerun()

def main():
    chat_app = SaiBerChat()
    chat_app.run()

if __name__ == "__main__":
    main()
