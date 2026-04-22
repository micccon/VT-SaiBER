Note: Options with `+` require an argument

| Option | Description |
| --- | --- |
|        -ask+         | Whether to ask about submitting updates:<br> &nbsp; &nbsp; `yes`&nbsp;– Ask about each (default)<br> &nbsp; &nbsp; `no`&nbsp;– Don't ask, don't send <br> &nbsp; &nbsp; `auto`– Don't ask, just send |
|        -Add-header+  | Add a custom header to all requests, format is "Header: value" |
|        -Cgidirs+     | Scan these CGI dirs:<br> &nbsp; &nbsp; `none`<br> &nbsp; &nbsp; `all`<br> &nbsp; &nbsp; or values like `"/cgi/ /cgi-a/"` |
|        -config+      | Use this config file |
|        -Display+     | Turn on/off display outputs:<br> &nbsp; &nbsp; `1` – Show redirects<br> &nbsp; &nbsp; `2` – Show cookies received<br> &nbsp; &nbsp; `3` – Show all 200/OK responses<br> &nbsp; &nbsp; `4` – Show URLs which require authentication<br> &nbsp; &nbsp; `D` – Debug output<br> &nbsp; &nbsp; `E` – Display all HTTP errors<br> &nbsp; &nbsp; `P` – Print progress to STDOUT<br> &nbsp; &nbsp; `S` – Scrub output of IPs and hostnames<br> &nbsp; &nbsp; `V` – Verbose output |
|        -dbcheck      | Check database and other key files for syntax errors |
|        -check6       | Verify IPv6 connectivity before scanning |
|        -evasion+     | Encoding technique:<br> &nbsp; &nbsp; `1` – Random URI encoding (non-UTF8)<br> &nbsp; &nbsp; `2` – Directory self-reference (/./)<br> &nbsp; &nbsp; `3` – Premature URL ending<br> &nbsp; &nbsp; `4` – Prepend long random string<br> &nbsp; &nbsp; `5` – Fake parameter<br> &nbsp; &nbsp; `6` – TAB as request spacer<br> &nbsp; &nbsp; `7` – Change the case of the URL<br> &nbsp; &nbsp; `8` – Use Windows directory separator (\)<br> &nbsp; &nbsp; `A` – Use a carriage return (0x0d) as a request spacer<br> &nbsp; &nbsp; `B` – Use binary value 0x0b as a request spacer |
|        -followredirects | Follow 3xx redirects to new location |
|        -Format+      | Save file (-o) format. Can specify multiple formats separated by commas (e.g., htm,sql,txt,json,xml):<br> &nbsp; &nbsp; `csv` – Comma-separated-value<br> &nbsp; &nbsp; `json` – JSON Format<br> &nbsp; &nbsp; `htm` – HTML Format<br> &nbsp; &nbsp; `sql` – Generic SQL (see documentation/nikto_schema_mysql.sql or nikto_schema_postgresql.sql)<br> &nbsp; &nbsp; txt` – Plain text<br> &nbsp; &nbsp; `xml` – XML Format<br> &nbsp; &nbsp; (if not specified the format will be taken from the file extension passed to -output) |
|        -Help         | This help information |
|        -host+        | Target host/URL (alias of `-url`) |
|        -404code      | Ignore these HTTP codes as negative responses (always). Format is "302,301". |
|        -404string    | Ignore this string in response body content as negative response (always). Can be a regular expression. |
|        -id+          | Host authentication to use, format is id:pass or id:pass:realm |
|        -ipv4         | IPv4 Only |
|        -ipv6         | IPv6 Only |
|        -key+         | Client certificate key file |
|        -list-plugins | List all available plugins, perform no testing |
|        -maxtime+     | Maximum testing time per host (e.g., 1h, 60m, 3600s) |
|        -mutate+      | Guess additional file names:<br> &nbsp; &nbsp; `1` – Test all files with all root directories<br> &nbsp; &nbsp; `2` – Guess for password file names<br> &nbsp; &nbsp; `3` – Enumerate user names via Apache (/~user type requests)<br> &nbsp; &nbsp; `4` – Enumerate user names via cgiwrap (/cgi-bin/cgiwrap/~user type requests)<br> &nbsp; &nbsp; `6` – Attempt to guess directory names from the supplied dictionary file |
|        -mutate-options | Provide information for mutates |
|        -nocheck       | Don't check for updates on startup |
|        -nocookies     | Do not use cookies from responses in requests (cookies are stored and sent by default) |
|        -nointeractive | Disables interactive features |
|        -nolookup      | Disables DNS lookups |
|        -noslash       | Strip trailing slash from URL (e.g., '/admin/' to '/admin') |
|        -nossl         | Disables the use of SSL |
|        -no404         | Disables nikto attempting to guess a 404 page |
|        -Option        | Over-ride an option in nikto.conf, can be issued multiple times |
|        -output+       | Write output to this file ('.' for auto-name) |
|        -Pause+        | Pause between tests (seconds, integer or float) |
|        -Plugins+      | List of plugins to run (default: ALL) |
|        -port+         | Port to use (default 80) |
|        -RSAcert+      | Client certificate file |
|        -root+         | Prepend root value to all requests, format is /directory |
|        -Save          | Save positive responses to this directory ('.' for auto-name) |
|        -ssl           | Force ssl mode on port |
|        -Tuning+       | Scan tuning:<br> &nbsp; &nbsp; `1` – Interesting File / Seen in logs<br> &nbsp; &nbsp; `2` – Misconfiguration / Default File<br> &nbsp; &nbsp; `3` – Information Disclosure<br> &nbsp; &nbsp; `4` – Injection (XSS/Script/HTML)<br> &nbsp; &nbsp; `5` – Remote File Retrieval - Inside Web Root<br> &nbsp; &nbsp; `6` – Denial of Service<br> &nbsp; &nbsp; `7` – Remote File Retrieval - Server Wide<br> &nbsp; &nbsp; `8` – Command Execution / Remote Shell<br> &nbsp; &nbsp; `9` – SQL Injection<br> &nbsp; &nbsp; `0` – File Upload<br> &nbsp; &nbsp; `a` – Authentication Bypass<br> &nbsp; &nbsp; `b` – Software Identification<br> &nbsp; &nbsp; `c` – Remote Source Inclusion<br> &nbsp; &nbsp; `d` – WebService<br> &nbsp; &nbsp; `e` – Administrative Console<br> &nbsp; &nbsp; `x` – Reverse Tuning Options (i.e., include all except specified) |
|        -timeout+      | Timeout for requests (default 10 seconds) |
|        -Userdbs       | Load only user databases, not the standard databases:<br> &nbsp; &nbsp; `all` – Disable standard dbs and load only user dbs<br> &nbsp; &nbsp; `tests` – Disable only db_tests and load udb_tests |
|        -useragent     | Over-rides the default random useragents |
|        -url+          | Target host/URL (alias of -host) |
|        -useproxy      | Use the proxy defined in nikto.conf, or argument http://server:port |
|        -Version       | Print plugin and database versions |
|        -vhost+        | Virtual host (for Host header) |
