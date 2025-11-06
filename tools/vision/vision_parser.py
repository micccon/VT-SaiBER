"""
Parser of raw xml output from nmap scans, makes it into VisionScanResult for mcp

This module is responsible for:
1. Ensuring nmap raw output is valid
2. Converting stupid out-of-date xml (L msoft) into beautiful clean hot json
"""

import xml.etree.ElementTree as ET
from typing import Dict

class VisionParser:
    
    # Big huge massive extravagant method that is called that parses all hosts
    @staticmethod
    def parse_xml(xml_output: str) -> Dict:
        try:
            root = ET.fromstring(xml_output)
            hosts = []
            
            for host in root.findall("host"):
                host_data = VisionParser._parse_host(host)
                hosts.append(host_data)
            
            return {"hosts": hosts}
            
        except ET.ParseError as e:
            return {"hosts": [], "parse_error": str(e)}
    
    # parse each host that is found
    @staticmethod
    def _parse_host(host) -> Dict:
        host_data = {
            "status": "unknown",
            "addresses": [],
            "hostnames": [],
            "ports": []
        }
        
        # parsing the status (up and running or dowwwwwwnnnn)
        status = host.find("status")
        if status is not None:
            host_data["status"] = status.get("state", "unknown")
        
        # parsing the addresses (ip addressess......nuff said)
        for addr in host.findall("address"):
            host_data["addresses"].append({
                "addr": addr.get("addr"),
                "type": addr.get("addrtype")
            })
        
        # parsing the hostnames (the url bruh come on now)
        hostnames = host.find("hostnames")
        if hostnames is not None:
            for hostname in hostnames.findall("hostname"):
                name = hostname.get("name")
                if name:
                    host_data["hostnames"].append(name)
        
        # ports to parse (if u don't know what ports are....cmon bruh)
        ports = host.find("ports")
        if ports is not None:
            for port in ports.findall("port"):
                port_data = VisionParser._parse_port(port)
                host_data["ports"].append(port_data)
        
        return host_data
    
    # Parse port things like the portid, protocol, etc
    @staticmethod
    def _parse_port(port) -> Dict:
        port_data = {
            "port": port.get("portid"),
            "protocol": port.get("protocol"),
            "state": "unknown"
        }
        
        # parsing the states that port is listed in (open, closed)
        state = port.find("state")
        if state is not None:
            port_data["state"] = state.get("state")
            port_data["reason"] = state.get("reason")
        
        # parsing services (could be anything tbh, usually ssh)
        service = port.find("service")
        if service is not None:
            port_data["service"] = {
                "name": service.get("name"),
                "product": service.get("product"),
                "version": service.get("version"),
                "extrainfo": service.get("extrainfo")
            }
        
        return port_data