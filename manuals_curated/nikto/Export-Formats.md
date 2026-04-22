Nikto allows output to be saved in a variety of formats, including text:
* CSV
* HTML
* XML
* JSON
* SQL

When using -output, an output format may be specified with -Format. **Multiple formats can be specified simultaneously** by separating them with commas (e.g., `-F htm,sql,txt,json,xml`). Each format will be written to its own file.

If no -Format is specified, Nikto will try to guess the format from the file extension. If Nikto cannot guess the file format then output will only be sent to stdout.

The DTD for the Nikto XML format can be found in the 'docs' directory (nikto.dtd) and should be found by default.

**SQL Format Schema**

The schema for the table used in SQL output can be found in `documentation/nikto_schema_mysql.sql` (for MySQL/MariaDB) and `documentation/nikto_schema_postgresql.sql` (for PostgreSQL).

**MySQL/MariaDB Schema:**
```sql
CREATE TABLE `nikto_table` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `scanid` varchar(32) DEFAULT NULL,
  `testid` varchar(6) NOT NULL,
  `ip` varchar(15) DEFAULT NULL,
  `hostname` text DEFAULT NULL,
  `port` int(5) DEFAULT NULL,
  `tls` tinyint(1) DEFAULT NULL,
  `refs` text DEFAULT NULL,
  `httpmethod` text DEFAULT NULL,
  `uri` text DEFAULT NULL,
  `message` text DEFAULT NULL,
  `request` blob DEFAULT NULL,
  `response` mediumblob DEFAULT NULL,
  PRIMARY KEY (`id`)
);
```

**PostgreSQL Schema:**
```sql
CREATE TABLE nikto_table (
  id serial NOT NULL,
  scanid varchar(32) DEFAULT NULL,
  testid varchar(6) NOT NULL,
  ip varchar(15) DEFAULT NULL,
  hostname text DEFAULT NULL,
  port integer DEFAULT NULL,
  tls smallint DEFAULT NULL,
  refs text DEFAULT NULL,
  httpmethod text DEFAULT NULL,
  uri text DEFAULT NULL,
  message text DEFAULT NULL,
  request bytea DEFAULT NULL,
  response bytea DEFAULT NULL,
  PRIMARY KEY (id)
);
```

**Field Descriptions:**
- `id` - Auto-incrementing primary key (auto_increment in MySQL, serial in PostgreSQL)
- `scanid` - Unique identifier for each scan session (varchar(32))
- `testid` - Nikto test identifier (varchar(6))
- `ip` - Target IP address (varchar(15))
- `hostname` - Target hostname (text)
- `port` - Target port number (int(5) in MySQL, integer in PostgreSQL)
- `tls` - TLS/SSL enabled flag (tinyint(1) in MySQL, smallint in PostgreSQL)
- `refs` - Vulnerability references (CVE IDs, URLs, etc.) (text)
- `httpmethod` - HTTP method used (GET, POST, etc.) (text)
- `uri` - URI/path tested (text)
- `message` - Finding description/message (text)
- `request` - HTTP request data (blob/mediumblob in MySQL, bytea in PostgreSQL)
- `response` - HTTP response data (mediumblob in MySQL, bytea in PostgreSQL)

**Note:** The `request` and `response` fields are automatically truncated to ensure compatibility:
- Request: 48KB raw (fits in 64KB BLOB after base64 encoding in MySQL)
- Response: 12MB raw (fits in 16MB MEDIUMBLOB after base64 encoding in MySQL)

**TLS Information**

TLS (SSL) information is now included as a finding type in all report formats. This includes details about TLS certificates, cipher suites, and TLS-related vulnerabilities detected during scanning.