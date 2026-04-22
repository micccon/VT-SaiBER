#!/usr/bin/env python3
"""
Gateway Service for Automotive Pentesting Testbed
Provides firmware upload functionality with intentional vulnerabilities.
"""
import os
import urllib.parse
from flask import Flask, jsonify, request

app = Flask(__name__)

# Firmware upload directory
FIRMWARE_DIR = '/opt/automotive-testbed/firmware/'

# Log file path
LOG_PATH = '/var/log/automotive-pentest/gateway.log'


def log_message(message):
    """Write a message to the gateway log file."""
    try:
        with open(LOG_PATH, 'a') as f:
            f.write(f"{message}\n")
    except Exception:
        pass


def log_file_access(requested_path, resolved_path, success):
    """Log file access attempts for indirect traversal detection.

    This logs file access patterns that the validation API can analyze
    to detect directory traversal without revealing success to the attacker.

    Format: FILE_ACCESS: requested=X, resolved=Y, outside_firmware_dir=True/False
    """
    # Check if resolved path is outside the firmware directory
    firmware_dir_abs = os.path.abspath(FIRMWARE_DIR)
    resolved_abs = os.path.abspath(resolved_path)
    outside_firmware = not resolved_abs.startswith(firmware_dir_abs)

    # Check if it's a sensitive file
    sensitive_files = ['/etc/passwd', '/etc/shadow', '/etc/hosts', '/etc/hostname']
    is_sensitive = any(resolved_abs == sf or resolved_abs.endswith(sf) for sf in sensitive_files)

    log_message(f"FILE_ACCESS: requested={requested_path}, resolved={resolved_path}, "
                f"outside_firmware_dir={outside_firmware}, sensitive_file={is_sensitive}, "
                f"access_success={success}")


def waf_check_traversal(filename):
    """
    WAF-like input filter to block simple directory traversal attempts.

    VULNERABILITY: This filter can be bypassed using techniques like:
    - ....// (double dot-dot-slash that becomes ../ after filter removes ../)
    - ..%2f (URL encoded slash)
    - ..%252f (double URL encoded slash)
    - ..././ (nested traversal)

    Returns True if blocked, False if allowed through.
    """
    # Simple WAF that only blocks literal '../' sequences
    # This can be bypassed with encoding or nested sequences
    if '../' in filename:
        return True
    return False


def decode_and_normalize(filename):
    """
    Decode URL-encoded characters and normalize traversal sequences.
    This processes bypass techniques to reveal the actual traversal path.
    """
    # First, handle double URL encoding (..%252f -> ..%2f -> ../)
    decoded = filename

    # URL decode up to twice to handle double encoding
    for _ in range(2):
        new_decoded = urllib.parse.unquote(decoded)
        if new_decoded == decoded:
            break
        decoded = new_decoded

    # Handle nested traversal sequences like ....// or ..././
    # Replace ....// with ../ (after removing one ../, we're left with ../)
    # Replace ..././ with ../ (similar bypass technique)
    prev = None
    while prev != decoded:
        prev = decoded
        # ....// becomes ../ when the filter removes one ../
        decoded = decoded.replace('....//', '../')
        # ..././ becomes ../ when the filter removes middle part
        decoded = decoded.replace('..././', '../')

    return decoded


@app.route('/', methods=['GET'])
def health():
    """Health check endpoint."""
    return jsonify({'status': 'ok'})


@app.route('/firmware/upload', methods=['POST'])
def firmware_upload():
    """
    Firmware upload endpoint.
    VULNERABILITY V5: Directory Traversal with WAF Bypass
    Simple '../' sequences are blocked by the WAF, but bypass techniques work:
    - ....// (nested traversal)
    - ..%2f (URL encoded)
    - ..%252f (double URL encoded)
    - ..././ (nested traversal variant)
    """
    if 'file' not in request.files:
        return jsonify({'error': 'Invalid request'}), 400

    uploaded_file = request.files['file']
    if uploaded_file.filename == '':
        return jsonify({'error': 'Invalid request'}), 400

    filename = uploaded_file.filename

    # WAF CHECK: Block simple ../  sequences
    if waf_check_traversal(filename):
        log_message(f"WAF_BLOCKED: Simple traversal attempt blocked: {filename}")
        return jsonify({'error': 'Invalid request'}), 400

    # VULNERABILITY: WAF can be bypassed with encoding or nested sequences
    # Decode and normalize to reveal actual traversal path
    processed_filename = decode_and_normalize(filename)

    # Check if this looks like a traversal attempt (after decoding/normalization)
    if '..' in processed_filename or processed_filename.startswith('/'):
        log_message(f"WAF_BYPASS_SUCCESS: Traversal bypass detected - original: {filename}, processed: {processed_filename}")
        # Note: Traversal detection is now done indirectly via validation API
        # by tracking file access patterns outside FIRMWARE_DIR

        # If it's a traversal attempt, try to read the target file
        # Construct the path the attacker is trying to access
        target_path = os.path.normpath(os.path.join(FIRMWARE_DIR, processed_filename))

        try:
            # Read file contents (vulnerable behavior - allows reading arbitrary files)
            with open(target_path, 'r') as f:
                contents = f.read()
            # Log file access for indirect detection (without revealing success to attacker)
            log_file_access(processed_filename, target_path, success=True)
            # Return file contents disguised as "firmware data" - this is the subtle
            # difference that allows exploitation while not revealing the vulnerability type.
            # Successful traversal returns the target file contents in the 'data' field.
            # Legitimate uploads show 'path' field instead.
            return jsonify({
                'status': 'success',
                'message': 'Operation completed',
                'data': contents
            })
        except FileNotFoundError:
            log_file_access(processed_filename, target_path, success=False)
            return jsonify({'error': 'Operation failed'}), 500
        except PermissionError:
            log_file_access(processed_filename, target_path, success=False)
            return jsonify({'error': 'Operation failed'}), 500
        except Exception as e:
            log_file_access(processed_filename, target_path, success=False)
            return jsonify({'error': 'Operation failed'}), 500

    # Normal upload (non-malicious filename)
    # Ensure firmware directory exists
    os.makedirs(FIRMWARE_DIR, exist_ok=True)
    target_path = os.path.join(FIRMWARE_DIR, filename)

    try:
        uploaded_file.save(target_path)
        log_message(f"Firmware uploaded: {filename}")
        # Normal upload response - differs subtly from traversal response
        # (uses 'path' instead of 'data')
        return jsonify({
            'status': 'success',
            'message': 'Operation completed',
            'path': target_path
        })
    except Exception as e:
        log_message(f"Firmware upload failed: {str(e)}")
        return jsonify({'error': 'Operation failed'}), 500


if __name__ == '__main__':
    log_message("Gateway service started on port 8080")
    app.run(host='0.0.0.0', port=8080)
