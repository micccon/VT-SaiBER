"""
VT-SaiBER Orchestrator Frontend - Stark HUD

A Streamlit-based frontend that uses the ShieldOrchestrator to provide
an interactive cybersecurity scanning interface.
"""

import streamlit as st
import asyncio
import os
import logging
from datetime import datetime
from typing import Dict, Any, List, Optional

# VT-SaiBER imports
from orchestrator.shield import ShieldOrchestrator
from orchestrator.mocks import MockPromptBuilder, MockLLMClient, MockReportGenerator
from blueprints.schemas import UserQueryRequest, FinalReport
from interaction.api.thanos import process_user_input

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class StarkHUD:
    """
    Stark HUD - Orchestrator Frontend for VT-SaiBER
    
    Provides an interactive web interface for the ShieldOrchestrator.
    """
    
    def __init__(self):
        self.orchestrator = st.session_state.get('orchestrator')
        self.session_id = "stark_hud_session"
        
        # Configure page
        st.set_page_config(
            page_title="VT-SaiBER - Stark HUD",
            page_icon="🛡️",
            layout="wide",
            initial_sidebar_state="expanded"
        )
        
        # Initialize session state
        if 'messages' not in st.session_state:
            st.session_state.messages = []
        if 'scan_history' not in st.session_state:
            st.session_state.scan_history = []
        if 'orchestrator_ready' not in st.session_state:
            st.session_state.orchestrator_ready = False
    
    def setup_orchestrator(self):
        """Initialize ShieldOrchestrator with mock components."""
        try:
            # Initialize orchestrator with mock components
            # In a real scenario, we would load these from config or dependency injection
            self.orchestrator = ShieldOrchestrator(
                config_path="./config.yaml",
                prompt_builder=MockPromptBuilder(),
                llm_client=MockLLMClient(),
                report_generator=MockReportGenerator()
            )
            
            # Persist orchestrator in session state
            st.session_state.orchestrator = self.orchestrator
            st.session_state.orchestrator_ready = True
            return True
            
        except Exception as e:
            st.error(f"❌ Failed to initialize Orchestrator: {str(e)}")
            return False
    
    def validate_target(self, target: str) -> tuple[bool, str]:
        """Validate a target using Thanos input validation."""
        try:
            result = process_user_input(f"scan {target}", output_context="dict")
            if result.get("validation_errors"):
                return False, f"Validation errors: {', '.join(result['validation_errors'])}"
            if not result.get("sanitized_targets"):
                return False, "No valid targets found"
            return True, f"Valid target: {result['sanitized_targets'][0]['value']}"
        except Exception as e:
            return False, f"Validation failed: {str(e)}"
    
    def render_sidebar(self):
        """Render the sidebar with controls."""
        with st.sidebar:
            st.title("🛡️ VT-SaiBER")
            st.subheader("Stark HUD v2.0")
            
            # Orchestrator Status
            if st.session_state.orchestrator_ready:
                st.success("✅ Orchestrator Online")
            else:
                st.error("❌ Orchestrator Offline")
                if st.button("Initialize Orchestrator"):
                    with st.spinner("Initializing Shield Orchestrator..."):
                        self.setup_orchestrator()
                        st.rerun()
            
            st.divider()
            
            # Quick Actions
            st.subheader("Quick Scans")
            
            target = st.text_input("Target IP/Host:", placeholder="scanme.nmap.org")
            
            col1, col2 = st.columns(2)
            with col1:
                if st.button("🔍 Quick Scan", use_container_width=True):
                    if target:
                        valid, msg = self.validate_target(target)
                        if valid:
                            self.handle_query(f"Perform a quick scan of {target}")
                        else:
                            st.error(msg)
                    else:
                        st.error("Please enter a target")
            
            with col2:
                if st.button("🏠 Host Discovery", use_container_width=True):
                    if target:
                        valid, msg = self.validate_target(target)
                        if valid:
                            self.handle_query(f"Discover live hosts around {target}")
                        else:
                            st.error(msg)
                    else:
                        st.error("Please enter a target")
            
            st.divider()
            
            # Scan History
            st.subheader("Recent Scans")
            if st.session_state.scan_history:
                for scan in st.session_state.scan_history[-5:]:
                    st.caption(f"• {scan['target']} ({scan['type']})")
            else:
                st.caption("No recent scans")
            
            # Clear History
            if st.button("🗑️ Clear History"):
                st.session_state.messages = []
                st.session_state.scan_history = []
                st.rerun()
    
    def handle_query(self, prompt_text: str):
        """Handle a user query by sending it to the orchestrator."""
        if not st.session_state.orchestrator_ready:
            st.error("Orchestrator not initialized. Please check the sidebar.")
            return

        # Add user message
        st.session_state.messages.append({
            "role": "user", 
            "content": prompt_text,
            "timestamp": datetime.now()
        })
        
        # Process with Thanos validation for history
        if any(word in prompt_text.lower() for word in ["scan", "ping", "port", "service"]):
            processed = process_user_input(prompt_text, output_context="dict")
            if processed.get("sanitized_targets"):
                target = processed["sanitized_targets"][0]["value"]
                st.session_state.scan_history.append({
                    "target": target,
                    "type": processed.get("action", "unknown"),
                    "timestamp": datetime.now()
                })
        
        # Execute Orchestrator Workflow
        with st.spinner("Shield Orchestrator executing plan..."):
            try:
                # Create query object
                query = UserQueryRequest(
                    prompt=prompt_text,
                    session_id=self.session_id
                )
                
                # Run orchestrator
                # We need to run the async execute method
                report = asyncio.run(self.orchestrator.execute(query))
                
                # Format response
                response_content = self._format_report(report)
                
                # Add assistant response
                st.session_state.messages.append({
                    "role": "assistant", 
                    "content": response_content,
                    "timestamp": datetime.now()
                })
                
                st.rerun()
                
            except Exception as e:
                st.error(f"Orchestration failed: {str(e)}")
                logger.error(f"Orchestration failed: {e}", exc_info=True)

    def _format_report(self, report: FinalReport) -> str:
        """Format the FinalReport into a markdown string for the chat."""
        md = f"### Execution Summary\n\n{report.summary}\n\n"
        md += "---\n\n"
        md += f"**Session ID:** `{report.session_id}`\n\n"
        md += f"**Total Tasks:** {len(report.results)}\n\n"
        
        md += "### Detailed Results\n\n"
        for result in report.results:
            status_icon = "✅" if result.status == "success" else "❌"
            md += f"#### {status_icon} Task {result.task_id}\n"
            
            if result.error_message:
                md += f"**Error:** {result.error_message}\n"
            
            if result.output:
                md += "```json\n"
                # Convert output to string if it's a dict/list, or just use str()
                import json
                try:
                    md += json.dumps(result.output, indent=2)
                except:
                    md += str(result.output)
                md += "\n```\n"
            
            md += "\n"
            
        return md

    def render_main_interface(self):
        """Render the main chat interface."""
        st.title("🔬 Network Security Scanner")
        st.markdown("*Powered by Shield Orchestrator*")
        
        # Chat container
        chat_container = st.container(height=600)
        
        with chat_container:
            # Display messages
            for message in st.session_state.messages:
                with st.chat_message(message["role"]):
                    st.markdown(message["content"])
                    if "timestamp" in message:
                        st.caption(f"🕒 {message['timestamp'].strftime('%H:%M:%S')}")
        
        # Input area
        if prompt := st.chat_input("Ask about network security scanning...", disabled=not st.session_state.orchestrator_ready):
            self.handle_query(prompt)
    
    def render_footer(self):
        """Render the footer with information."""
        st.divider()
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.markdown("**🛡️ Security Notice**")
            st.caption("Only scan networks you own or have permission to scan")
        
        with col2:
            st.markdown("**🔧 Tech Stack**")
            st.caption("Shield Orchestrator + Mock LLM + Nmap")
        
        with col3:
            st.markdown("**📊 Status**")
            if st.session_state.orchestrator_ready:
                st.caption("System: Online 🟢")
            else:
                st.caption("System: Offline 🔴")
    
    def run(self):
        """Main application loop."""
        # Initialize orchestrator if not ready
        if not st.session_state.orchestrator_ready:
            self.setup_orchestrator()
        
        # Render interface
        self.render_sidebar()
        self.render_main_interface()
        self.render_footer()


def main():
    """Main entry point for the Stark HUD application."""
    app = StarkHUD()
    app.run()


if __name__ == "__main__":
    main()