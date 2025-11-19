# VT ARC API Client

Professional Python client for Virginia Tech Advanced Research Computing (ARC) LLM API. This client provides a robust, enterprise-grade interface to the VT ARC LLM platform with support for multiple API keys, automatic rate limiting, and all available features.

## Features

### Core Capabilities
- **Chat Completions**: Interactive conversations with multiple models
- **Document Processing (RAG)**: Upload and query documents
- **Image Generation**: Create images from text prompts
- **Image Analysis**: Analyze and extract text from images
- **Web Search**: Enable real-time web search in responses
- **Multimodal Queries**: Combine text, images, and documents

### Enterprise Features
- **Multiple API Key Support**: Rotate between up to 5 API keys automatically
- **Rate Limiting**: Built-in rate limit management with automatic backoff
- **Retry Logic**: Exponential backoff with configurable retry policies
- **Prompt Injection**: Customizable system prompts and templates
- **Comprehensive Logging**: Detailed logging with performance metrics
- **Error Handling**: Robust exception handling and recovery

## Installation

### Requirements
- Python 3.7+
- VT ARC API Key (obtain from https://llm.arc.vt.edu)

### Install Dependencies
```bash
pip install -r requirements.txt
```

## Quick Start

### Basic Setup
```python
from official_api import VTARCClient

# Initialize with API key from environment
client = VTARCClient()

# Or provide API keys directly (up to 5)
client = VTARCClient(api_keys=["sk-key1", "sk-key2", "sk-key3"])
```

### Simple Chat
```python
response = client.chat_completion(
    prompt="Explain quantum computing",
    model="GLM-4.5-Air",
    temperature=0.7
)
print(response)
```

### Document RAG
```python
# Upload and query a document
uploaded = client.upload_document("research_paper.pdf")
response = client.query_documents(
    query="What are the main findings?",
    file_ids=[uploaded.file_id]
)
```

### Image Generation
```python
image = client.generate_image(
    prompt="A futuristic city at sunset",
    size="512x512",
    save_path="city.png"
)
```

## Configuration

### Environment Variables
Set API keys via environment variables:
```bash
# Single key
export VT_ARC_API_KEY="sk-your-key-here"

# Multiple keys (for better rate limits)
export VT_ARC_API_KEY_1="sk-key1"
export VT_ARC_API_KEY_2="sk-key2"
export VT_ARC_API_KEY_3="sk-key3"
```

### Custom Configuration
```python
from official_api import APIConfig, VTARCClient

config = APIConfig(
    api_keys=["sk-key1", "sk-key2"],
    default_model="GLM-4.5-Air",
    max_retries=5,
    enable_logging=True,
    log_file="api.log"
)

client = VTARCClient(config=config)
```

## Advanced Usage

### Conversations
```python
# Multi-turn conversations with context
conversation = client.create_conversation(
    system_message="You are a helpful assistant"
)

response1 = conversation.get_response("What is Python?")
response2 = conversation.get_response("What are its main uses?")
```

### Prompt Injection
```python
from official_api import PromptInjectionConfig

# Configure prompt injection
prompt_config = PromptInjectionConfig(
    enabled=True,
    system_role="You are an expert programmer",
    system_instructions="Always provide clean, documented code"
)

client = VTARCClient(prompt_injection=prompt_config)

# Add custom templates
client.add_prompt_template(
    "code_review",
    "Review this code for bugs and improvements"
)

# Use template
response = client.chat_completion(
    prompt="def add(a,b): return a+b",
    template_name="code_review"
)
```

### Multimodal Queries
```python
# Combine text, images, and documents
response = client.multimodal_query(
    text_prompt="Analyze this data and chart",
    image_paths=["chart.png"],
    document_paths=["data.csv"],
    web_search=True
)
```

### Streaming Responses
```python
stream = client.chat_completion(
    prompt="Write a story",
    stream=True
)

for chunk in stream:
    # Process streaming chunks
    print(chunk, end='', flush=True)
```

## Available Models

- **GLM-4.5-Air**: High-performance general model
- **GLM-4.5V-AWQ**: Vision-capable model for image tasks
- **gpt-oss-120b**: OpenAI's flagship public model

## API Limits

- 60 requests per minute
- 1000 requests per hour
- 2000 requests per 3-hour window

Using multiple API keys allows automatic rotation to maximize throughput.

## Testing

Run the comprehensive test suite:
```bash
python test_api.py
```

Run usage examples:
```bash
python examples/basic_usage.py
```

## Project Structure

```
official-api/
├── __init__.py           # Package initialization
├── vt_arc_api.py        # Main unified client
├── config.py            # Configuration classes
├── exceptions.py        # Custom exceptions
├── core/               # Core functionality
│   ├── base_client.py  # Base HTTP client
│   ├── chat_client.py  # Chat completions
│   ├── document_client.py # Document/RAG
│   └── image_client.py    # Image generation/analysis
├── utils/              # Utilities
│   ├── rate_limiter.py # Rate limiting
│   ├── retry.py        # Retry logic
│   └── logger.py       # Logging utilities
├── examples/           # Usage examples
│   └── basic_usage.py  # Example code
├── test_api.py        # Test suite
├── requirements.txt   # Dependencies
└── README.md         # Documentation
```

## Error Handling

The client includes comprehensive error handling:

```python
from official_api.exceptions import (
    RateLimitError,
    AuthenticationError,
    FileUploadError
)

try:
    response = client.chat_completion("Hello")
except RateLimitError as e:
    print(f"Rate limited. Retry after: {e.retry_after}s")
except AuthenticationError:
    print("Invalid API key")
except Exception as e:
    print(f"Error: {e}")
```

## Performance Monitoring

```python
# Check rate limit status
status = client.get_rate_limit_status()
print(status)

# Test connection
if client.test_connection():
    print("API connection successful")

# Get available models
models = client.get_models()
print(f"Available models: {models}")
```

## Best Practices

1. **Use Multiple API Keys**: Distribute load and avoid rate limits
2. **Enable Logging**: Track API usage and debug issues
3. **Handle Errors**: Implement proper error handling
4. **Use Streaming**: For long responses to improve UX
5. **Cache Documents**: Reuse uploaded file IDs
6. **Monitor Rate Limits**: Check status before batch operations

## Security Notes

- Keep API keys secure and never commit them to version control
- Use environment variables for API key storage
- The client masks API keys in logs automatically
- All communications use HTTPS

## Support

For API access and keys: https://llm.arc.vt.edu
For ARC support: Contact Virginia Tech ARC team

## License

This client is provided as-is for use with the VT ARC LLM API platform.