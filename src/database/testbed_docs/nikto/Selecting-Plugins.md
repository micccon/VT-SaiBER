Starting in Nikto 2.1.2 [plugins](Plugin-list) can be selected on an individual basis and may have parameters passed directly to them.

A plugin selection string may be passed on the command line through the -Plugin parameter. It consists of a semi-colon separated list of plugin names with option parameters placed in brackets. In simple form a plugin statement is like:

`plugin-name[(parameter name[:parameter value ][,other parameters] )]`

For example we can do:

`tests(report:500,verbose)`

Which will set the parameters report to a value of 500 and verbose to a value of 1. The parameters and plugin names can be found be running:

`./nikto.pl -list-plugins`

This also means that we deprecate the mutate options and replace them with parameters passed to plugins, so the mutate options now internally translate to:

* tests(all)
* tests(passfiles)
* apacheusers(enumerate,home[,dictionary:dict.txt])
* apacheusers(enumerate,cgiwrap[,dictionary:dict.txt])
* dictionary(dictionary:dict.txt)

**Note:** Mutate option 5 (subdomain enumeration) has been removed.

Macros for commonly run plugin sets can also be defined in nikto.conf, for example:
* @@MUTATE=dictionary
* @@DEFAULT=@@ALL;-@@MUTATE;tests(report:500)

These are expanded by using -list-plugins and can be overridden through -Plugins.

Altogether this can allow a customized set of plugins that may need to be run for a specific circumstance. For example, if a normal test bought up that the server was vulnerable to the apache Expect header XSS attack, and we want to run a test just to see that it is vulnerable by adding debugging, we can run:

`nikto.pl -host target.txt -Plugins "apache_expect_xss(verbose,debug)"`

And then manually check the output to see whether it was truly vulnerable.

It should be noted that reports are also plugins, so if you need to customize the plugin string and want an output, include the report plugin directly:

`nikto.pl -host targets.txt -Plugins "apacheusers(enumerate,dictionary:users.txt);report_xml" -output apacheusers.xml`
