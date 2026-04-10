In addition to the plugins, several macro "names" exist for ease of use.
* @@DEFAULT = "@@ALL;-@@EXTRAS;tests(report:500)"
  * Default plugin set excluding extras
* @@EXTRAS
  * Expanded = "dictionary;siebel"
  * Additional plugins that can be excluded from default runs
* @@ALL 
  * Dynamically generated from all loaded plugins. Includes all available plugins.
* @@NONE 
  * Expanded = ""
  * No plugins (useful when only report formats are needed)

***

* **Plugin: report_csv**

  * CSV reports - Produces a CSV report.

* **Plugin: outdated**

  * Outdated - Checks to see whether the web server is the latest version.

* **Plugin: ssl**

  * SSL and cert checks - Perform checks on SSL/Certificates

* **Plugin: content_search**

  * Content Search - Search resultant content for interesting strings

* **Plugin: cgi**

  * CGI - Enumerates possible CGI directories.

* **Plugin: favicon**

  * Favicon - Checks the web server's favicon against known favicons.

* **Plugin: headers**

  * HTTP Headers - Performs various checks against the headers returned from an HTTP request.

* **Plugin: report_json**

  * JSON reports - Produces a JSON report.

* **Plugin: shellshock**

  * shellshock - Look for the bash 'shellshock' vulnerability.
  * Options:
  *  uri: uri to assess

* **Plugin: sitefiles**

  * Site Files - Look for interesting files based on the site's IP/name

* **Plugin: negotiate**

  * Negotiate - Checks the mod_negotiation MultiViews.

* **Plugin: put_del_test**

  * Put/Delete test - Attempts to upload and delete files through the PUT and DELETE HTTP methods.

* **Plugin: report_sqlg**

  * Generic SQL reports - Produces SQL inserts into a generic database.

* **Plugin: cookies**

  * HTTP Cookie Internal IP - Looks for internal IP addresses in cookies returned from an HTTP request.

* **Plugin: ms10_070**

  * Determine if a site is vulnerable to [MS10-070](https://docs.microsoft.com/en-us/security-updates/securitybulletins/2010/ms10-070)

* **Plugin: fileops**

  * File Operations - Saves results to a text file.

* **Plugin: report_html**

  * Report as HTML - Produces an HTML report.

* **Plugin: auth**

  * Guess authentication - Attempt to guess authentication realms

* **Plugin: httpoptions**

  * HTTP Options - Performs a variety of checks against the HTTP options returned from the server.

* **Plugin: report_xml**

  * Report as XML - Produces an XML report.

* **Plugin: dictionary_attack**

  * Dictionary attack - Attempts to dictionary attack commonly known directories/files
  * Options:
    *  method: Method to use to enumerate.
    *  dictionary: Dictionary of paths to look for.

* **Plugin: robots**

  * Robots - Checks whether there's anything within the robots.txt file and analyses it for other paths to pass to other scripts.
  * Options:
    *  nocheck: Flag to disable checking entries in robots file.

* **Plugin: msgs**

  * Server Messages - Checks the server version against known issues.

* **Plugin: paths**

  * Path Search - Look at link paths to help populate variables

* **Plugin: parked**

  * Parked Detection - Checks to see whether the host is parked at a registrar or ad location.

* **Plugin: optionsbleed**

  * OPTIONSBLEED (CVE-2017-9798) check - Detects OPTIONSBLEED vulnerability

* **Plugin: springboot**

  * Spring Boot Actuator endpoint check - Detects exposed Spring Boot Actuator endpoints and basic info leaks

* **Plugin: apache_expect_xss**

  * Apache Expect XSS - Checks whether the web servers has a cross-site scripting vulnerability through the Expect: HTTP header

* **Plugin: report_text**

  * Text reports - Produces a text report.

* **Plugin: siebel**

  * Siebel Checks - Performs a set of checks against an installed Siebel application
  * Options:
    *  enumerate: Flag to indicate whether we shall attempt to enumerate known apps
    *  applications: List of applications
    *  application: Application to attack
    *  languages: List of Languages

* **Plugin: apacheusers**

  * Apache Users - Checks whether we can enumerate usernames directly from the web server
  * Options:
    *  enumerate: Flag to indicate whether to attempt to enumerate users
    *  cgiwrap: User cgi-bin/cgiwrap to enumerate
    *  dictionary: Filename for a dictionary file of users
    *  size: Maximum size of username if bruteforcing
    *  home: Look for ~user to enumerate

* **Plugin: tests**

  * Nikto Tests - Test host with the standard Nikto tests
  * Options:
    *  tids: A range of testids that will only be run
    *  report: Report a status after the passed number of tests
    *  passfiles: Flag to indicate whether to check for common password files
    *  all: Flag to indicate whether to check all files with all directories

* **Plugin: multiple_index**

  * Multiple Index - Checks for multiple index files

