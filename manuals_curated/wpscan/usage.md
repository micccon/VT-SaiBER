<a href="https://wpscan.com/">
  <img src="https://raw.githubusercontent.com/wpscanteam/wpscan/gh-pages/images/wpscan_logo.png" alt="WPScan logo">
</a>

# WPScan User Documentation

## Introduction

WPScan is a free, for non-commercial use, black box WordPress security scanner written for security professionals and blog maintainers to test the security of their sites.

WPScan is written in the Ruby programming language. The first version of WPScan was released on the [16th of June 2011](https://web.archive.org/web/20120214033644/http://www.ethicalhack3r.co.uk/security/introducing-wpscan-wordpress-security-scanner/).

## What can WPScan check for?

- The version of WordPress installed and any associated vulnerabilities
- What plugins are installed and any associated vulnerabilities
- What themes are installed and any associated vulnerabilities
- Username enumeration
- Users with weak passwords via password brute forcing
- Backed up and publicly accessible wp-config.php files
- Database dumps that may be publicly accessible
- If error logs are exposed by plugins
- Media file enumeration
- Vulnerable Timthumb files
- If the WordPress readme file is present
- If WP-Cron is enabled
- If user registration is enabled
- Full Path Disclose
- Upload directory listing
- And much more...

## License

WPScan is *not* Open Source software. WPScan is licensed with a custom license that requires a fee to be paid if used commercially. Please find the full license terms [here](https://github.com/wpscanteam/wpscan/blob/master/LICENSE).

## Installation

### Ruby Gem

WPScan is shipped as a Ruby gem, and can be installed with the following command:

`gem install wpscan`

### Docker

We also support Docker. Pull the repo with:

`docker pull wpscanteam/wpscan`

Example Docker command to enumerate usernames:

`docker run -it --rm wpscanteam/wpscan --url https://example.com/ --enumerate u`

### Homebrew (macOS)

`brew install wpscanteam/tap/wpscan` to install the latest stable version

`brew install wpscanteam/tap/wpscan --HEAD` to install the latest code from the master branch

## Updating

### WPScan

To update the WPScan software:

`gem update wpscan`

### Kali Linux

To update WPScan in Kali Linux:

`apt-get update && apt-get upgrade`

### Metadata Data

WPScan keeps a local database of metadata that is used to output useful information, such as the latest version of a plugin. The local database can be updated with the following command:

`wpscan --update`

_Metadata does not include the vulnerability data._

## Optional: WordPress Vulnerability Database API

The WPScan CLI tool uses the [WordPress Vulnerability Database API](https://wpscan.com/api) to retrieve WordPress vulnerability data in real time. For WPScan to retrieve the vulnerability data an API token must be supplied via the `--api-token` option, or via a configuration file. An API token can be obtained by registering an account on [WPScan.com](https://wpscan.com/register).

Up to 25 API requests per day are given free of charge, that should be suitable to scan most WordPress websites at least once per day. When the daily 25 API requests are exhausted, WPScan will continue to work as normal but without any vulnerability data.

#### The Free plan allows 25 API requests per day. View the different [available API plans](https://wpscan.com/api).

### How many API requests do you need?

- Our WordPress scanner makes one API request for the WordPress version, one request per installed plugin and one request per installed theme.
- On average, a WordPress website has 22 installed plugins.
- The Free plan should cover around 50% of all WordPress websites.

## Enumeration Modes

When enumerating the WordPress version, installed plugins or installed themes, you can use three different "modes", which are:

- passive
- aggressive
- mixed

If you want the most results use the "mixed" mode. However, if you are worried that the server may not be able to handle a large number of requests, use the "passive" mode. The default mode is "mixed", with the exception of plugin enumeration, which is "passive". You will need to manually override the plugin detection mode, if you want to use anything other than the default, with the `--plugins-detection` option.

## Enumeration Options

WPScan can enumerate various things from a remote WordPress application, such as plugins, themes, usernames, backed up files wp-config.php files, Timthumb files, database exports and more. To use WPScan's enumeration capabilities supply the `-e` option.

The following enumeration options exist:

 - `vp`   (Vulnerable plugins)
 - `ap`   (All plugins)
 - `p`    (Popular plugins)
 - `vt`   (Vulnerable themes)
 - `at`   (All themes)
 - `t`    (Popular themes)
 - `tt`   (Timthumbs)
 - `cb`   (Config backups)
 - `dbe`  (Db exports)
 - `u`    (User IDs range. e.g: u1-5)
 - `m`    (Media IDs range. e.g m1-15)

If no option is supplied to the `-e` flag, then the default will be: `vp,vt,tt,cb,dbe,u,m`


## Cheat Sheet

Here we have put together a bunch of common commands that will help you get started quickly.

_NOTE: Get your API token from [wpscan.com](https://wpscan.com/) if you also want the vulnerabilities associated with the detected plugin displaying._

#### Enumerate all plugins with known vulnerabilities

`wpscan --url example.com -e vp --plugins-detection mixed --api-token YOUR_TOKEN`

#### Enumerate all plugins in our database (could take a very long time)

`wpscan --url example.com -e ap --plugins-detection mixed --api-token YOUR_TOKEN`

#### Password brute force attack

`wpscan --url example.com -e u --passwords /path/to/password_file.txt`

#### The remote website is up, but does not seem to be running WordPress

If you get the `Scan Aborted: The remote website is up, but does not seem to be running WordPress.` error, it means that for some reason WPScan did not think that the site you are trying to scan is actually WordPress. If you think WPScan is wrong, you can supply the `--force` option to force WPScan to scan the site regardless. You may also need to set other options in this case, such as `--wp-content-dir` and `--wp-plugins-dir`.

#### Redirects

By default WPScan will follow in scope redirects, unless the `--ignore-main-redirect` option is given.

### Docker Cheat Sheet

#### Pull the Docker repository

`docker pull wpscanteam/wpscan`

#### Run WPScan and enumerate usernames

`docker run -it --rm wpscanteam/wpscan --url https://target.tld/ --enumerate u`

#### When using `--output` flag along with the WPScan Docker image, a bind mount must be used. Otherwise, the file is written inside the Docker container, which is then thrown away.

```
mkdir ~/docker-bind
docker run --rm --mount type=bind,source=$HOME/docker-bind,target=/output wpscanteam/wpscan:latest -o /output/wpscan-output.txt --url 'https://example.com'
```

The `wpscan-output.txt` file now exists on the host machine at `~/docker-bind/wpscan-output.txt`.

#### Pass password list to Docker container

```
docker run -it --rm -v /Users/__macuser__/:/__containerdirectory__ wpscanteam/wpscan --url http://example..com/ --passwords /__containerdirectory__/passwords.txt
```

See: https://github.com/wpscanteam/wpscan/issues/1256#issuecomment-609055053

## Bypassing Simple WAFs

To bypass some simple WAFs you can try the `--random-user-agent` option.

## Troubleshooting

If WPScan is not working as expected, you can use the `--proxy` option, and use a web proxy to inspect WPScan's HTTP requests, and the remote server's HTTP responses. This is useful when you do not know why you are getting false positives, or false negatives.

## Keeping Informed

We blog here - [https://blog.wpscan.com/](https://blog.wpscan.com/)

We tweet here - [https://twitter.com/\_wpscan\_](https://twitter.com/\_wpscan\_)