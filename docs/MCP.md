# MCP Server Endpoints Documentation

## Kali MCP Server

**Base URL:** `http://kali-mcp:5000` (inside Docker network)

### Health Check
```
GET /health
Response: {"status": "healthy", "service": "kali-mcp"}
```

### Available Tools

#### nmap
```
POST /tools/nmap
Body: {
  "target": "192.168.1.50",
  "flags": "-sV -sC"
}
```

#### gobuster
```
POST /tools/gobuster
Body: {
  "url": "http://192.168.1.50",
  "wordlist": "/usr/share/wordlists/dirb/common.txt"
}
```

#### ffuf
```
POST /tools/ffuf
Body: {
  "url": "http://192.168.1.50/FUZZ",
  "wordlist": "/usr/share/wordlists/dirb/common.txt"
}
```

---

## Metasploit MCP Server

**Base URL:** `http://msf-mcp:8085` (inside Docker network)

### Health Check
```
GET /health
Response: {"status": "healthy", "service": "msf-mcp"}
```

### Available Tools

#### search_modules
```
POST /tools/search_modules
Body: {
  "query": "vsftpd"
}
```

#### run_exploit
```
POST /tools/run_exploit
Body: {
  "module": "exploit/unix/ftp/vsftpd_234_backdoor",
  "options": {
    "RHOSTS": "192.168.1.50"
  }
}
```

#### list_sessions
```
GET /tools/list_sessions
Response: {
  "sessions": {
    "1": {
      "type": "shell",
      "info": "Command shell",
      "via": "exploit/unix/ftp/vsftpd_234_backdoor"
    }
  }
}
```

---

## Authentication

### Kali MCP
- No authentication required (internal Docker network)

### Metasploit MCP
- Authenticates with msfrpcd using MSF_PASSWORD environment variable
- Password: Set in .env file
- Handled automatically by MetasploitMCP server