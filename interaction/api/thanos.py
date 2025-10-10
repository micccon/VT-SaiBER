"""
Security functions for the interaction layer.
Includes input validation and sanitization ("Thanos").
"""

def sanitize_query(prompt: str) -> str:
    """
    sanitizes the user's input query to prevent prompt injection
    and remove potentially malicious payloads

    args:
        prompt: The raw user input string

    returns:
        the sanitized string
    """
    print(f"Sanitizing query: '{prompt}'")
    sanitized = prompt.strip()

    # In a real application, you would add more robust checks here:
    # - Check for known injection patterns (e.g., "ignore previous instructions").
    # - Use a library to filter out malicious code snippets.
    # - Potentially use a separate, smaller LLM to classify the intent of the prompt.

    print(f"Sanitized query: '{sanitized}'")
    return sanitized
