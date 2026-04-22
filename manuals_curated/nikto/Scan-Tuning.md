# Scan Tuning

Scan tuning can be used to decrease the number of tests performed
against a target. By specifying the type of test to include or exclude,
faster, focused testing can be completed. This is useful in situations
where the presence of certain file types are undesired \-- such as XSS
or simply \"interesting\" files.

Test types can be controlled at an individual level by specifying their
identifier to the `-T` (`-Tuning`) option. In the default mode, if `-T`
is invoked only the test type(s) specified will be executed. For
example, only the tests for \"Remote file retrieval\" and \"Command
execution\" can performed against the target:

    perl nikto.pl -h 192.168.0.1 -T 58

If an \"x\" is passed to `-T` then this will negate all tests of types
following the x. This is useful where a test may check several different
types of exploit. For example:

    perl nikto.pl -h 192.168.0.1 -T 58xb

The valid tuning options are:

-   0 - File Upload. Exploits which allow a file to be uploaded to the
    target server.

-   1 - Interesting File / Seen in logs. An unknown but suspicious file
    or attack that has been seen in web server logs (note: if you have
    information regarding any of these attacks, please contact CIRT,
    Inc.).

-   2 - Misconfiguration / Default File. Default files or files which
    have been misconfigured in some manner. This could be documentation,
    or a resource which should be password protected.

-   3 - Information Disclosure. A resource which reveals information
    about the target. This could be a file system path or account name.

-   4 - Injection (XSS/Script/HTML). Any manner of injection, including
    cross site scripting (XSS) or content (HTML). This does not include
    command injection.

-   5 - Remote File Retrieval - Inside Web Root. Resource allows remote
    users to retrieve unauthorized files from within the web server\'s
    root directory.

-   6 - Denial of Service. Resource allows a denial of service against
    the target application, web server or host (note: no intentional DoS
    attacks are attempted).

-   7 - Remote File Retrieval - Server Wide. Resource allows remote
    users to retrieve unauthorized files from anywhere on the target.

-   8 - Command Execution / Remote Shell. Resource allows the user to
    execute a system command or spawn a remote shell.

-   9 - SQL Injection. Any type of attack which allows SQL to be
    executed against a database.

-   a - Authentication Bypass. Allows client to access a resource it
    should not be allowed to access.

-   b - Software Identification. Installed software or program could be
    positively identified.

-   c - Remote source inclusion. Software allows remote inclusion of
    source code.

-   d - WebService. Web service endpoints or related functionality.

-   e - Administrative Console. Administrative interfaces or consoles.

-   f - XML Injection. XML-related injection vulnerabilities.

-   x - Reverse Tuning Options. Perform exclusion of the specified
    tuning type instead of inclusion of the specified tuning type.
