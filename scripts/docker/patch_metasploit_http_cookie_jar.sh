#!/bin/sh

set -eu

MSF_ROOT=""
for candidate in /usr/share/metasploit-framework /usr/src/metasploit-framework; do
    if [ -d "$candidate" ]; then
        MSF_ROOT="$candidate"
        break
    fi
done

if [ -z "$MSF_ROOT" ]; then
    echo "Could not locate the Metasploit framework root." >&2
    exit 1
fi

TARGET_FILE="$MSF_ROOT/lib/msf/core/exploit/remote/http/http_cookie_jar.rb"
if [ ! -f "$TARGET_FILE" ]; then
    echo "Expected Metasploit HTTP cookie jar file not found: $TARGET_FILE" >&2
    exit 1
fi

python3 - "$TARGET_FILE" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
text = path.read_text()

original = """# 3rd party gems
require 'http/cookie_jar/hash_store'
require 'http/cookie_jar'
require 'http/cookie'
"""

patched = """# 3rd party gems
require 'http/cookie_jar'
require 'http/cookie_jar/hash_store'
require 'http/cookie'
"""

if patched in text:
    print(f"Metasploit HTTP cookie jar load-order patch already present: {path}")
    raise SystemExit(0)

if original not in text:
    raise SystemExit(f"Expected require-order block not found in {path}")

path.write_text(text.replace(original, patched, 1))
print(f"Patched Metasploit HTTP cookie jar load order in {path}")
PY
