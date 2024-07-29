import subprocess
import json
import re
import logging
import os
from datetime import datetime
import argparse
from llm_analyzer import analyze_investigation


# Set up logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


def run_command(command, timeout=30):
    """
    Execute a shell command and return its output.
    """
    logger.debug(f"Executing command: {command}")
    try:
        result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True, timeout=timeout)
        logger.debug(f"Command output: {result.stdout}")
        return result.stdout.strip()
    except subprocess.TimeoutExpired:
        logger.error(f"Command timed out after {timeout} seconds: {command}")
        return None
    except subprocess.CalledProcessError as e:
        logger.error(f"Command failed with error: {e}")
        logger.error(f"Error output: {e.stderr}")
        return None

def get_whois_info(ip):
    """
    Get WHOIS information for the IP using the 'whois' command.
    """
    logger.info(f"Fetching WHOIS information for IP: {ip}")
    whois_output = run_command(f"whois {ip}")
    if whois_output:
        # Extract relevant information from WHOIS output
        org_match = re.search(r"OrgName:\s+(.+)", whois_output)
        country_match = re.search(r"Country:\s+(.+)", whois_output)
        netrange_match = re.search(r"NetRange:\s+(.+)", whois_output)
        
        org = org_match.group(1) if org_match else "Not found"
        country = country_match.group(1) if country_match else "Not found"
        netrange = netrange_match.group(1) if netrange_match else "Not found"
        
        logger.info(f"WHOIS info - Organization: {org}, Country: {country}, NetRange: {netrange}")
        return {"organization": org, "country": country, "netrange": netrange}
    return None

def get_reverse_dns(ip):
    """
    Perform a reverse DNS lookup using the 'dig' command.
    """
    logger.info(f"Performing reverse DNS lookup for IP: {ip}")
    reverse_dns = run_command(f"dig +short -x {ip}")
    if reverse_dns:
        logger.info(f"Reverse DNS result: {reverse_dns}")
        return reverse_dns
    return None

def get_traceroute(ip):
    """
    Perform a traceroute to the IP using the 'traceroute' command.
    """
    logger.info(f"Performing traceroute to IP: {ip}")
    traceroute_output = run_command(f"traceroute -m 15 {ip}")
    if traceroute_output:
        # Process traceroute output to extract hop information
        hops = re.findall(r"\s*\d+\s+([^\s]+)", traceroute_output)
        logger.info(f"Traceroute hops: {hops}")
        return hops
    return None

def get_nmap_info(ip, os_detection=False):
    """
    Perform a comprehensive Nmap scan to get detailed information about the IP.
    OS detection is optional and requires root privileges.
    """
    logger.info(f"Performing Nmap scan on IP: {ip}")
    
    nmap_command = f"nmap -sV -sC -p- -T4 -Pn --reason"
    
    if os_detection:
        if os.geteuid() == 0:  # Check if running as root
            nmap_command += " -O"
            logger.info("Running Nmap with OS detection (root privileges detected)")
        else:
            logger.warning("OS detection requested but not running as root. Skipping OS detection.")
    
    nmap_command += f" {ip}"
    
    logger.info(f"Running Nmap command: {nmap_command}")
    nmap_output = run_command(nmap_command, timeout=300)  # 5 minutes timeout
    
    if nmap_output:
        # Extract open ports and services
        port_info = re.findall(r"(\d+/\w+)\s+(\w+)\s+(\w+)\s+(.+)", nmap_output)
        ports = [{"port": p.split('/')[0], 
                  "protocol": p.split('/')[1], 
                  "state": s, 
                  "service": srv, 
                  "details": d.strip()} 
                 for p, s, srv, d in port_info]
        
        result = {
            "ports": ports
        }
        
        # Parse OS detection results if available
        if os_detection and os.geteuid() == 0:
            os_match = re.search(r"OS details: (.+)", nmap_output)
            if os_match:
                result["os"] = os_match.group(1)
            else:
                result["os"] = "OS detection failed or not supported for this host"
        
        logger.info(f"Nmap scan results: {result}")
        return result
    return None

def get_ssl_cert_info(ip):
    """
    Retrieve SSL certificate information using OpenSSL.
    """
    logger.info(f"Fetching SSL certificate information for IP: {ip}")
    ssl_output = run_command(f"openssl s_client -connect {ip}:443 -servername {ip} < /dev/null 2>/dev/null | openssl x509 -noout -text")
    if ssl_output:
        # Extract relevant certificate information
        subject = re.search(r"Subject: (.+)", ssl_output)
        issuer = re.search(r"Issuer: (.+)", ssl_output)
        valid_from = re.search(r"Not Before: (.+)", ssl_output)
        valid_to = re.search(r"Not After : (.+)", ssl_output)
        
        cert_info = {
            "subject": subject.group(1) if subject else "Not found",
            "issuer": issuer.group(1) if issuer else "Not found",
            "valid_from": valid_from.group(1) if valid_from else "Not found",
            "valid_to": valid_to.group(1) if valid_to else "Not found"
        }
        logger.info(f"SSL certificate info: {cert_info}")
        return cert_info
    return None

def investigate_ip(ip_address, os_detection=False):
    logger.info(f"Starting investigation for IP: {ip_address}")

    results = {
        "ip_address": ip_address,
        "timestamp": datetime.now().isoformat(),
    }

    try:
        results["whois"] = get_whois_info(ip_address)
    except Exception as e:
        logger.error(f"Error getting WHOIS info: {e}")
        results["whois"] = str(e)

    try:
        results["reverse_dns"] = get_reverse_dns(ip_address)
    except Exception as e:
        logger.error(f"Error getting reverse DNS: {e}")
        results["reverse_dns"] = str(e)

    try:
        results["traceroute"] = get_traceroute(ip_address)
    except Exception as e:
        logger.error(f"Error performing traceroute: {e}")
        results["traceroute"] = str(e)

    try:
        results["nmap_scan"] = get_nmap_info(ip_address, os_detection)
    except Exception as e:
        logger.error(f"Error performing Nmap scan: {e}")
        results["nmap_scan"] = str(e)

    try:
        results["ssl_cert"] = get_ssl_cert_info(ip_address)
    except Exception as e:
        logger.error(f"Error getting SSL cert info: {e}")
        results["ssl_cert"] = str(e)

    logger.info("Investigation completed")
    return results

if __name__ == "__main__":
    # Keep your command-line interface logic here if you want to run it directly
    import argparse
    parser = argparse.ArgumentParser(description="Investigate an IP address using various tools.")
    parser.add_argument("ip", help="The IP address to investigate")
    parser.add_argument("--os-detection", action="store_true", help="Enable OS detection in Nmap scan (requires root privileges)")
    args = parser.parse_args()

    results = investigate_ip(args.ip, args.os_detection)
    print(json.dumps(results, indent=2))
