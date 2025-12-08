"""
main.py - CLI Entry Point

Prerequisites:
1. Start MCP server: python mcp_server.py (in another terminal)
2. Run this: python main.py
"""

import os
import asyncio
import streamlit as st
from orchestrator.agent_system import AgentSystem

# Config
os.environ["GOOGLE_GENAI_USE_VERTEXAI"] = "False"

# Page Config
st.set_page_config(page_title="VT-SaiBER", page_icon="🛡️")

@st.cache_resource
def get_agent_system() -> AgentSystem:
    """Initialize AgentSystem once and cache it"""
    return AgentSystem()

async def main():
    st.title("VT-SaiBER 🛡️")
    st.caption("Multi-Agent Security Scanner & Reporter")

    # API Key Handling
    with st.sidebar:
        api_key = st.text_input("Enter Google API Key", type="password")
        if api_key:
            os.environ["GOOGLE_API_KEY"] = api_key
            st.success("API Key accepted!")
        else:
            st.warning("Please enter your Google API Key to continues.")
            st.stop()


    # Initialize state
    if "messages" not in st.session_state:
        st.session_state.messages = []

    # Get cached system
    system = get_agent_system()
    
    # Initialize system if needed (idempotent check)
    if system.runner is None:
        with st.spinner("Initializing Agent System..."):
            await system.initialize()
            st.success("System Ready!")

    # Sidebar info
    with st.sidebar:
        st.header("Available Agents")
        st.markdown("""
        - **Scanner**: Network security scanning
        - **Vulnerability Report**: Vulnerability assessment
        - **Orchestrator**: Workflow coordination
        """)
        
        st.header("Example Queries")
        st.code("Scan 192.168.1.1")
        st.code("Scan scanme.nmap.org and create a vulnerability report")

    # Display chat history
    for message in st.session_state.messages:
        with st.chat_message(message["role"]):
            st.markdown(message["content"])

    # Chat input
    if prompt := st.chat_input("How can I help you secure the network?"):
        # Add user message to history
        st.session_state.messages.append({"role": "user", "content": prompt})
        with st.chat_message("user"):
            st.markdown(prompt)

        # Generate response
        with st.chat_message("assistant"):
            with st.spinner("Processing..."):
                response = await system.run_query(prompt)
                st.markdown(response)
        
        # Add assistant message to history
        st.session_state.messages.append({"role": "assistant", "content": response})

if __name__ == "__main__":
    asyncio.run(main())