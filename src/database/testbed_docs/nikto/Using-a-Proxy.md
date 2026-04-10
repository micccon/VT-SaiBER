There are two ways to use an HTTP(S) proxy with Nikto--via the nikto.conf file, or directly via the command line.

To use the [nikto.conf](nikto.conf) file, set the PROXY* variables (as described in the [Config Variables](Config-Variables)), and then execute Nikto with the -useproxy option. All connections will be relayed through the proxy specified in the configuration file.

`perl nikto.pl -h localhost -p 80 -useproxy`

To set the proxy on the command line, you can also use the -useproxy option with the proxy set as the argument, for example:

`./nikto.pl -h localhost -useproxy http://localhost:8080/`

[SOCKS Proxies](SOCKS-Proxies) are not directly supported, however can be used via proxychains or similar program.

---
When testing against Cloudflare and some other WAF protected targets, TLS stack fingerprinting can cause blocking. PERL's TLS/SSL modules do not offer
fine-grained control to better mimic a browser's TLS connection settings. In these situations, it is recommended to use an intermediary proxy for better 
TLS support, such as [Burp Suite](https://portswigger.net/), [ZAP](https://www.zaproxy.org/), or [mitmproxy](https://www.mitmproxy.org/).
