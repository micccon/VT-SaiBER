Each test, whether it comes from one of the databases or in code, must have a unique identifier. The numbering scheme for writing tests is as follows:

| Range | Usage |
| -- | -- |
| 000000 | db_tests |
| 400000 | user defined tests (udb* files) |
| 500000 | db_favicon |
| 600000 | db_outdated |
| 700000 | db_realms |
| 750000 | db_content_search |
| 800000 | db_server_msgs |
| 900000 | tests defined in code |

As much data as possible in the %TESTS hash should be populated for each new test that is defined in code (plugins). These fields include URI for the test, message to print on success, HTTP method and references. Without a 'message' value in %TESTS output will not be saved in reports. Not all tests are expected to have a uri, method or references. Here is an example of setting those fields:

```
$TESTS{999999}{uri}="/~root";
$TESTS{999999}{message}="Enumeration of users is possible by requesting ~username";
$TESTS{999999}{method}="GET";
$TESTS{999999}{references}="CVE-2023-1234";
```