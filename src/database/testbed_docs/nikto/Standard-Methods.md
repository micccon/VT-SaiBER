Several standard methods are defined in `nikto_core.plugin` that can be
used for all plugins. It is strongly advised that these should be used
where possible instead of writing new methods.

For some methods, such as `add_vulnerability` which write to global
variables, these *must* be the only interface to those global variables.

```
array change_variables(line);
string line
```

Expands any variables in the line parameter. The expansions are
variables defined in the global array `@VARIABLES`, which may be read
from `db_variables`, or added by reconnaisance plugin methods.

```
int is_404(mark, uri, response);
hashref mark
string uri
hashref response
```

Makes a guess whether the result is a real web page or an error page. As
several web servers are badly configured and don\'t return HTTP 404
codes when a page isn\'t found, Nikto uses dynamic 404 detection based
on matcher strength and cached entries. The detection is performed on-demand
and caches patterns for efficient subsequent checks. Returns 1 if the page
looks like an error.

**Note:** Pre-flight checks have been removed. Detection now happens dynamically
based on the actual response patterns observed during scanning.

```
string get_ext(uri);
string uri
```

Attempts to work out the extension of the uri. Will return the extension
or the special cases: DIRECTORY, DOTFILE, NONE.

```
string date_disp();
```

Returns the current time in a human readable format (YYYY-mm-dd
hh:mm:ss)

```
string rm_active(content)
string content
```

Attempts to remove active content (e.g. dates, adverts etc.) from a
page. Returns a filtered version of the content.

```
string get_banner(mark);
hashref mark
```

Pulls the web servers banner. This is automatically performed for all
targets before a mark is passed to the plugin.

```boolean content_present(HTTPcode)
string HTTPcode
```

Checks the HTTPresponse against known \"found\" responses. TRUE
indicates that the request was probably successful.

```
string HTTPCode, string content nfetch(mark, uri, method, content, headers, flags, testid);
hashref mark
string uri
string method
string content
hashref headers
hashref flags
string testid
```

Makes a simple request through libwhisker with the passed parameters.
nfetch is hook aware and will cause all requests to be passed through
the prefetch and postfetch hooks.

The `flags` hash is a selection of flags that may modify the behaviour
of the request. The current flags are defined:


| Key | Description|
| --- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| noclean | Tells nfetch not to perform sanity checks on the structure. Normally requests will be checked to ensure that a valid Host header is included and that the Content-Length header matches the size of any content, setting this flag prevents the checks |
| noprefetch | Tells nfetch not to run the prefetch hook. |
| nopostfetch | Tells nfetch not to run the postfetch hook. |
| noerror |Tells nfetch not to report error responses from the request. |


```
hashref setup_hash(requesthash, mark;
hashref requesthash
hashref mark
```

Sets up up a libwhisker hash with the normal Nikto variables. This
should be used if any custom calls to libwhisker are used.

```
string char_escape(line);
string line
```

Escapes any characters within line.

```
array parse_csv(text);
string text
```

Breaks a line of CSV text into an array of items.

```
arrayref init_db(dbname);
string dbname
```

Initializes a database that is in `PLUGINDIR` and returns an arrayref.
The arrayref is to an array of hashrefs, each hash member is configured
by the first line in the database file, for example:

    "nikto_id","md5hash","description"

This will result in an array of hashrefs with parameters:

    array[0]->{nikto_id}
    array[0]->{md5hash}
    array[0]->{description}

```
void add_vulnerability(mark, message, nikto_id, references, method, uri, data);
hashref mark
string message
string nikto_id
string references
string method
string uri
string data
````

Adds a vulnerability for the mark, displays it to standard out and sends
it to any reporting plugins.

```
void nprint(message, display);
string message
string display
```

Prints `message` to standard out. `Display` specifies a filter for the
message, currently this can be \"v\" for verbose and \"d\" for debug output.
