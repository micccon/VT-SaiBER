**Single Port**
The most basic Nikto scan requires simply a host to target, since port 80 is assumed if none is specified. The host can either be the IP or a hostname of a machine, and is specified using the -h (-host) option. This will scan the IP 192.168.0.1 on TCP port 80:

`perl nikto.pl -h 192.168.0.1`

To check on a different port, specify the port number with the -p (-port) option. This will scan the IP 192.168.0.1 on TCP port 443:

`perl nikto.pl -h 192.168.0.1 -p 443`

Hosts, ports and protocols may also be specified by using a full URL syntax, and it will be scanned:

`perl nikto.pl -h https://192.168.0.1:443/`

There is no need to specify that port 443 is encrypted, as Nikto will first test regular HTTP and if that fails, HTTPS. If you are sure it is an SSL/TLS server, specifying -s (-ssl) very slightly will speed up the test (this is also useful for servers that respond HTTP on port 443 even though content is only served when encryption is used).

`perl nikto.pl -h 192.168.0.1 -p 443 -ssl`

**Multiple Ports**

Nikto can scan multiple ports in the same scanning session. To test more than one port on the same host, specify the list of ports in the -p (-port) option. Ports can be specified as a range (i.e., 80-90), or as a comma-delimited list, (i.e., 80,88,90). This will scan the host on ports 80, 88 and 443.

`perl nikto.pl -h 192.168.0.1 -p 80,88,443`

**Multiple Hosts**

Nikto support scanning multiple hosts in the same session via a text file of host names or IPs. Instead of giving a host name or IP for the -h (-host) option, a file name can be provided. A file of hosts must be formatted as one host per line, with the port number(s) at the end of each line. Ports can be separated from the host and other ports via a colon or a comma. If no port is specified, port 80 is assumed.

This is an example of a valid hosts file:

`192.168.0.1:80`

`http://192.168.0.1:8080/`

`192.168.0.3`

Note: Although this functionality can be used, Nikto+Perl's memory utilization is not awesome and should be taken into consideration. It is likely a better idea to use a  bash script wrapper or other program to run the host/port combinations sequentially so that memory is freed after each scan. 
