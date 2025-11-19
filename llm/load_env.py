"""
Environment variable loader for VT ARC API Client
Automatically loads API keys from .env file
"""

import os
from pathlib import Path


def load_env_file():
    """Load environment variables from .env file"""
    env_file = Path(__file__).parent / '.env'

    if not env_file.exists():
        return False

    try:
        with open(env_file, 'r') as f:
            for line in f:
                line = line.strip()
                # Skip comments and empty lines
                if line and not line.startswith('#'):
                    # Parse key=value
                    if '=' in line:
                        key, value = line.split('=', 1)
                        key = key.strip()
                        value = value.strip()
                        # Remove quotes if present
                        if value.startswith('"') and value.endswith('"'):
                            value = value[1:-1]
                        elif value.startswith("'") and value.endswith("'"):
                            value = value[1:-1]
                        # Set environment variable
                        os.environ[key] = value
        return True
    except Exception as e:
        print(f"Warning: Could not load .env file: {e}")
        return False


# Auto-load when imported
load_env_file()