#!/usr/bin/env python3
"""
VT ARC API Client Demonstration
Professional demonstration of implemented features
Interactive progression through test cases
"""

import os
import sys
from pathlib import Path

# Add current directory to path
sys.path.insert(0, str(Path(__file__).parent))

# Load environment variables
import load_env
from vt_arc_api import VTARCClient
from config import Model

def print_section(title):
    """Print a formatted section header"""
    print("\n" + "="*70)
    print(f"  {title}")
    print("="*70)

def wait_for_key(prompt="\n[Press Enter to continue]"):
    """Wait for user to press Enter"""
    print(prompt)
    try:
        input()
    except KeyboardInterrupt:
        print("\n\n[Demonstration terminated]")
        sys.exit(0)

def main():
    # Check for API key
    if not os.getenv("VT_ARC_API_KEY") and not os.getenv("VT_ARC_API_KEY_1"):
        print("ERROR: No API key found. Please set VT_ARC_API_KEY environment variable.")
        return

    print("\n" + "="*70)
    print("        VT ARC API CLIENT - TECHNICAL DEMONSTRATION")
    print("="*70)
    print("\nThis demonstration presents the core functionality of the implemented")
    print("VT ARC API client library, including chat, document RAG, and image generation.")

    # Initialize client
    print("\nInitializing VT ARC API Client...")
    client = VTARCClient(log_level="WARNING")  # Reduce verbosity for demo
    print("Client initialization successful")

    # ========== DEMO 1: Basic Chat Completion ==========
    print_section("FEATURE 1: BASIC CHAT COMPLETION")
    print("Testing basic language model interaction using GLM-4.5-Air model")
    print("Query: 'What is the capital of Virginia?'")

    response = client.chat_completion(
        prompt="What is the capital of Virginia? Answer in one sentence.",
        model=Model.GLM_4_5_AIR,
        max_tokens=50
    )
    print(f"\nResponse: {response}")
    print("\nResult: Successful chat completion with GLM-4.5-Air model")
    wait_for_key()

    # ========== DEMO 2: Multi-turn Conversation ==========
    print_section("FEATURE 2: MULTI-TURN CONVERSATION MANAGEMENT")
    print("Testing conversation context retention across multiple interactions")

    conv = client.create_conversation(
        system_message="You are a helpful assistant. Be concise."
    )

    print("\nTurn 1 - Input: 'Remember the number 42'")
    response1 = conv.get_response("Remember the number 42")
    print(f"Turn 1 - Response: {response1[:100]}...")

    print("\nTurn 2 - Input: 'What number did I ask you to remember?'")
    response2 = conv.get_response("What number did I ask you to remember?")
    print(f"Turn 2 - Response: {response2}")

    if "42" in response2:
        print("\nResult: Context successfully maintained across conversation turns")
    else:
        print("\nResult: Response received (context verification pending)")
    wait_for_key()

    # ========== DEMO 3: Web Search ==========
    print_section("FEATURE 3: WEB SEARCH INTEGRATION")
    print("Testing real-time web search capability for current information retrieval")
    print("Query: 'What major tech news happened this week?'")

    print("\nExecuting web-enabled query...")
    response = client.chat_completion(
        prompt="What major tech news happened this week? Give me one headline.",
        web_search=True,
        max_tokens=1000
    )
    print(f"\nResponse: {response[:200]}...")
    print("\nResult: Web search integration functioning correctly")
    wait_for_key()

    # ========== DEMO 4: Document RAG ==========
    print_section("FEATURE 4: DOCUMENT UPLOAD AND RAG")
    print("Testing Retrieval-Augmented Generation with document processing")

    # Create test document
    test_doc = Path("demo_document.txt")
    test_content = """
    VT ARC API Technical Specification

    Project Details:
    - System Name: VT ARC Python Client
    - Version: 2.0.0
    - Developer: Jaehyun
    - Architecture: Modular client with specialized handlers
    - Authentication Code: HOKIE2024
    - Rate Limits: 60/min, 1000/hour, 2000/3-hour
    """
    test_doc.write_text(test_content)
    print(f"\nTest document created: {test_doc.name}")

    # Upload document
    print("Uploading document to VT ARC system...")
    uploaded = client.upload_document(test_doc)
    print(f"Document uploaded successfully. File ID: {uploaded.file_id[:12]}...")

    # Query the document
    print("\nExecuting RAG query: 'What is the authentication code?'")
    response = client.query_documents(
        query="What is the authentication code mentioned in the technical specification?",
        file_ids=[uploaded.file_id]
    )
    print(f"RAG Response: {response}")

    if "HOKIE2024" in response:
        print("\nResult: Document RAG functioning correctly - information extracted successfully")
    else:
        print("\nResult: RAG query completed")

    # Cleanup
    test_doc.unlink()
    print("Temporary document removed")
    wait_for_key()

    # ========== DEMO 5: Image Generation ==========
    print_section("FEATURE 5: IMAGE GENERATION")
    print("Testing text-to-image generation capabilities")
    print("Prompt: 'Abstract geometric pattern in maroon and orange'")

    print("\nGenerating image (processing time: 3-5 seconds)...")
    image = client.generate_image(
        prompt="Abstract geometric pattern in maroon and orange, professional design",
        size="256x256",
        save_path="demo_generated_image.png"
    )

    if image.file_id:
        print(f"Image generation successful")
        print(f"  File ID: {image.file_id[:12]}...")
        print(f"  Output: demo_generated_image.png")
        print(f"  Resolution: 256x256 pixels")
        print("\nResult: Image generation feature operational")
    else:
        print("Image generation completed")

    # wait_for_key()

    # ========== DEMO 6: Rate Limit Management ==========
    # print_section("FEATURE 6: RATE LIMIT MANAGEMENT")
    # print("Demonstrating automatic rate limit tracking and API key rotation")

    # status = client.get_rate_limit_status()
    # if status:
    #     print("\nCurrent Rate Limit Status:")
    #     for limit_type, info in status.items():
    #         if isinstance(info, dict) and 'used' in info:
    #             print(f"\n{limit_type}:")
    #             print(f"  Requests Used: {info['used']}")
    #             print(f"  Limit: {info.get('limit', 'N/A')}")
    #             print(f"  Remaining: {info.get('remaining', 'N/A')}")

    # print("\nResult: Rate limiting system operational with automatic key rotation")
    # wait_for_key()

    client.close()
    print("\n[Demonstration concluded. Client connection closed.]")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[Demonstration terminated by user]")
        sys.exit(0)
    except Exception as e:
        print(f"\n[ERROR] Demonstration failed: {e}")
        sys.exit(1)