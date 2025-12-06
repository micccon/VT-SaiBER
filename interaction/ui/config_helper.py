"""
Configuration Helper for Google ADK Setup

This utility helps users configure their Google ADK environment
for the VT-SaiBER Stark HUD frontend.
"""

import os
import sys
from pathlib import Path

def setup_google_adk():
    """Interactive setup for Google ADK configuration."""
    print("🔧 VT-SaiBER Google ADK Configuration Setup")
    print("=" * 50)
    
    # Check current configuration
    api_key = os.getenv("GOOGLE_API_KEY")
    if api_key:
        print(f"✅ GOOGLE_API_KEY is set (ends with: ...{api_key[-4:]})")
    else:
        print("❌ GOOGLE_API_KEY not set")
    
    vertex_ai = os.getenv("GOOGLE_GENAI_USE_VERTEXAI", "False")
    print(f"ℹ️  Vertex AI: {vertex_ai}")
    
    print("\n📋 Setup Steps:")
    print("1. Get a Google AI API key from: https://makersuite.google.com/app/apikey")
    print("2. Set the environment variable: export GOOGLE_API_KEY='your-key-here'")
    print("3. Ensure you have credits/quota for Gemini models")
    
    if not api_key:
        print("\n💡 Quick Setup:")
        api_key = input("Enter your Google AI API key (or press Enter to skip): ").strip()
        if api_key:
            print(f"Run this command in your terminal:")
            print(f"export GOOGLE_API_KEY='{api_key}'")
            
            # Optionally set it for current session
            set_now = input("Set it for current session? (y/n): ").lower().strip()
            if set_now == 'y':
                os.environ["GOOGLE_API_KEY"] = api_key
                print("✅ API key set for current session")
    
    print("\n🔍 Testing Configuration...")
    
    try:
        # Test basic connectivity using google-adk
        from google.adk.agents import Agent
        
        # Try to create a basic agent to test API connectivity
        test_agent = Agent(
            name="test_agent",
            model="gemini-2.0-flash",
            description="Test agent for API connectivity",
            instruction="You are a test agent."
        )
        
        print("✅ Google ADK connection successful")
        print("📊 Agent creation test passed")
            
    except Exception as e:
        print(f"❌ ADK test failed: {e}")
        print("Check your API key and internet connection")
        print("Make sure google-adk is properly installed")
        return False
    
    print("\n🎯 Next Steps:")
    print("1. Start the MCP server: python tools/vision/vision_mcp_server.py")
    print("2. Launch the HUD: python interaction/ui/launch_hud.py")
    print("3. Enjoy AI-powered network security scanning!")
    
    return True

def create_env_file():
    """Create a .env file template."""
    env_path = Path(".env")
    if env_path.exists():
        overwrite = input(".env file already exists. Overwrite? (y/n): ").lower().strip()
        if overwrite != 'y':
            return
    
    template = """# VT-SaiBER Environment Configuration
# Copy this file and rename to .env, then fill in your values

# Google AI API Key (required for ADK frontend)
GOOGLE_API_KEY=your-google-ai-api-key-here

# Google ADK Configuration
GOOGLE_GENAI_USE_VERTEXAI=False

# Optional: OpenAI API (for alternative LLM backend)
OPENAI_API_KEY=your-openai-key-here

# Optional: Anthropic API (for alternative LLM backend)
ANTHROPIC_API_KEY=your-anthropic-key-here
"""
    
    with open(env_path, 'w') as f:
        f.write(template)
    
    print(f"✅ Created .env template at {env_path}")
    print("Edit the file with your API keys before running the application")

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--create-env":
        create_env_file()
    else:
        setup_google_adk()
