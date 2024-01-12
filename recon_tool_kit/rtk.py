#!/usr/bin/env python3
import sys

# Output Colours
class c:
    PURPLE = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    UNDERLINE = '\033[4m'

# Libraries
try:
    import requests
    import re
    import socket
    import socks
    import json
    import argparse
    import platform
    import dns.resolver
    import dns.exception
    import dns.query
    import dns.zone
    import warnings
    import pydig
    import ipaddress
    from time import sleep
    import codecs
    import os
    import urllib3
    from urllib.parse import urlparse
    import tldextract
    import sys
    import nmap
    import threading
    from tabulate import tabulate
    import subprocess
    import asyncio
    import concurrent.futures
    from bs4 import BeautifulSoup

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception as e:
    print(e)
    print(c.YELLOW + "\n[" + c.RED + "-" + c.YELLOW + "] ERROR requirements missing try to install the requirements: pip3 install -r requirements.txt" + c.END)
    sys.exit(0)

def banner():
    print(c.BLUE + ",---.    ,---.   ,--,  .---.  .-. .-.  _______  .---.   .---.  ,-.     ,-. .-.,-. _______ ")
    print("| .-.\   | .-' .' .') / .-. ) |  \| | |__   __|/ .-. ) / .-. ) | |     | |/ / |(||__   __|")
    print("| `-'/   | `-. |  |(_)| | |(_)|   | |   )| |   | | |(_)| | |(_)| |     | | /  (_)  )| | ")  
    print(c.PURPLE + "|   (    | .-' \  \   | | | | | |\  |  (_) |   | | | | | | | | | |     | | \  | | (_) | ")  
    print("| |\ \   |  `--.\  `-.\ `-' / | | |)|    | |   \ `-' / \ `-' / | `--.  | |) \ | |   | | ") 
    print("|_| \)\  /( __.' \____\)---'  /(  (_)    `-'    )---'   )---'  |( __.' |((_)-'`-'   `-'   ")
    print(c.RED + "    (__)(__)          (_)    (__)              (_)     (_)     (_)     (_)" + c.END)
    print(c.BLUE + "\nPython version: " + c.GREEN + platform.python_version() + c.END)
    print(c.BLUE + "Current OS: " + c.GREEN + platform.system() + " " + platform.release() + c.END)

    internet_check = socket.gethostbyname(socket.gethostname())
    if internet_check == "127.0.0.1":
        if platform.system() == "Windows":
            print(c.BLUE + "Internet connection: " + c.RED + "-" + c.END)
        else:
            print(c.BLUE + "Internet connection: " + c.RED + "✕" + c.END)
    else:
        if platform.system() == "Windows":
            print(c.BLUE + "Internet connection: " + c.GREEN + "+" + c.END)
        else:
            print(c.BLUE + "Internet connection: " + c.GREEN + "✔" + c.END)

    print(c.BLUE + "Target: " + c.GREEN + domain + c.END)

# Argument parser Function
def parseArgs():
    p = argparse.ArgumentParser(description="RTK - Recon Tool Kit")
    p.add_argument("-d", "--domain", help="domain to search its subdomains", required=True)
    p.add_argument("-o", "--output", help="file to store the scan output", required=False)
    p.add_argument("-p", "--portscan", help="perform a fast and stealthy scan of the most common ports", action='store_true', required=False)
    p.add_argument("-a", "--axfr", help="try a domain zone transfer attack", action='store_true', required=False)
    p.add_argument("-m", "--mail", help="try to enumerate mail servers", action='store_true', required=False)
    p.add_argument('-e', '--extra', help="look for extra dns information", action='store_true', required=False)
    p.add_argument("-n", "--nameservers", help="try to enumerate the name servers", action='store_true', required=False)
    p.add_argument("-i", "--ip", help="it reports the ip or ips of the domain", action='store_true', required=False)
    p.add_argument('-6', '--ipv6', help="enumerate the ipv6 of the domain", action='store_true', required=False)
    p.add_argument("-w", "--waf", help="discover the WAF of the domain main page", action='store_true', required=False)
    p.add_argument("-b", "--backups", help="discover common backups files in the web page", action='store_true', required=False)
    p.add_argument("-s", "--subtakeover", help="check if any of the subdomains are vulnerable to Subdomain Takeover", action='store_true', required=False)
    p.add_argument("-r", "--repos", help="try to discover valid repositories and s3 servers of the domain (still improving it)", action='store_true', required=False)
    p.add_argument("-c", "--check", help="check active subdomains and store them into a file", action='store_true', required=False)
    p.add_argument("--secrets", help="crawl the web page to find secrets and api keys (e.g. Google Maps API Key)", action='store_true', required=False)
    p.add_argument("--enum", help="stealthily enumerate and identify common technologies", action='store_true', required=False)
    p.add_argument("--whois", help="perform a whois query to the domain", action='store_true', required=False)
    p.add_argument("--all", help="perform all the enumeration at once (best choice)", action='store_true', required=False)
    p.add_argument("--quiet", help="don't print the banner", action='store_true', required=False)
    p.add_argument("--version", help="display the script version", action='store_true', required=False)
    p.add_argument('-ipv4', '--ipv4_portscan', help='perform IPv4 port scanning', action='store_true', required=False)
    p.add_argument('-cn', '--cname', help='Enumerate CNAME', action='store_true', required=False)
    p.add_argument('-tv', '--wappalyzer', help='Enumerate technologies and their versions', action='store_true', required=False)
    p.add_argument('-end', '--endpoints', help='Enumerate Endpoints', action='store_true', required=False)
    p.add_argument('-am', '--emailauth', help='Enumerate Email Authentication', action='store_true', required=False)

    return p.parse_args()

# Nameservers Function 
def ns_enum(domain):
    print(c.BLUE + "\n[" + c.END + c.GREEN + "+" + c.END + c.BLUE + "] Trying to discover valid name servers...\n" + c.END)
    sleep(0.2)
    """
    Query to get NS of the domain
    """
    data = ""
    try:
        data = dns.resolver.resolve(f"{domain}", 'NS')
    except:
        pass
    ns_list = []
    if data:
        for ns in data:
            print(c.YELLOW + str(ns) + c.END)
            ns_list.append(ns)
    else:
        print(c.YELLOW + "Unable to enumerate" + c.END)
    return ns_list

# Function to discover the IPv6 addresses of the target domain
def ipv6_enum(domain):
    try:
        ipv6_list = []
        data = dns.resolver.resolve(domain, 'AAAA')
        ipv6_list = [ip.to_text() for ip in data]
        ipv6_addresses = '\n'.join(ipv6_list)
        output = f"{c.BLUE}\n[{c.END}{c.GREEN}+{c.END}{c.BLUE}] Trying to discover IPv6 addresses...\n{c.END}"
        output += f"{c.YELLOW}\n{ipv6_addresses}\n{c.END}"
        print(output)
        return ipv6_list
    except dns.resolver.NoAnswer:
        output = f"{c.BLUE}\n[{c.END}{c.GREEN}+{c.END}{c.BLUE}] Trying to discover IPv6 addresses of the domain...\n{c.END}"
        output += f"{c.YELLOW}\nUnable to enumerate IPv6 addresses.\n{c.END}"
        print(output)
        return None
    except dns.resolver.NXDOMAIN:
        output = f"{c.BLUE}\n[{c.END}{c.GREEN}+{c.END}{c.BLUE}] Trying to discover IPv6 addresses of the domain...\n{c.END}"
        output += f"{c.YELLOW}\nDomain does not exist.\n{c.END}"
        print(output)
        return None

# Function to discover the IPv4 addresses of the target domain
def ipv4_enumeration(domain):
    ipv4_list = []
    try:
        data = dns.resolver.resolve(domain, 'A')
        ipv4_list = [ip.to_text() for ip in data]
        ipv4_addresses = '\n'.join(ipv4_list)
        output = c.BLUE + "\n[" + c.END + c.GREEN + "+" + c.END + c.BLUE + "] Trying to discover IPv4 addresses...\n" + c.END
        output += c.YELLOW + f"\n{ipv4_addresses}\n" + c.END
        print(output)
        return ipv4_list
    except:
        output = c.BLUE + "\n[" + c.END + c.GREEN + "+" + c.END + c.BLUE + "] Trying to discover IPv4 addresses of the domain...\n" + c.END
        output += c.BLUE + "\n[" + c.END + c.GREEN + "+" + c.END + c.BLUE + "] Unable to enumerate IPv4 addresses.\n" + c.END
        print(output)
        return None

async def ipv4_enum(domain):
    ipv4_list = []
    try:
        data = dns.resolver.resolve(domain, 'A')
        ipv4_list = [ip.to_text() for ip in data]
        return ipv4_list
        print(ipv4_list)
    except:
        return None

async def ipv4_port_scan(ipv4_list):
    results = []
    try:
        nm = nmap.PortScanner()
        for ipv4 in ipv4_list:
            await asyncio.to_thread(nm.scan, ipv4, arguments='-sS -sV -Pn -T3')
            for host in nm.all_hosts():
                for proto in nm[host].all_protocols():
                    lport = nm[host][proto].keys()
                    for port in lport:
                        service_name = nm[host][proto][port]['name']
                        service_version = nm[host][proto][port]['version']
                        result = [host, port, nm[host][proto][port]['state'], service_name, service_version, nm[host][proto][port]['product']]
                        results.append(result)
    except Exception as e:
        print(c.YELLOW + f"[!] Error scanning {ipv4}: {e}" + c.END)
    return results


async def get_cves(service, version):
    cve_list = []
    try:
        query = f"{service} {version}".replace(' ', '+')
        url = f"https://services.nvd.nist.gov/rest/json/cves/1.0?keyword={query}"
        response = requests.get(url)
        if response.ok:
            cves = response.json()['result']['CVE_Items']
            if cves:
                for cve in cves:
                    cve_list.append(cve['cve']['CVE_data_meta']['ID'])
    except Exception as e:
        print(c.YELLOW + f"[!] Error retrieving CVEs for {service} {version}: {e}" + c.END)
    return cve_list


async def scan_ipv4_ports(domain):
    ipv4_addresses = await ipv4_enum(domain)
    if ipv4_addresses:
        print(c.BLUE + "\n[" + c.END + c.GREEN + "+" + c.END + c.BLUE + "] Starting port scanning of IPv4 addresses...\n" + c.END)
        tasks = [ipv4_port_scan(ipv4_addresses)]
        results = await asyncio.gather(*tasks)
        flat_results = [item for sublist in results if sublist for item in sublist]
        headers = ['IPv4 Address', 'Port', 'State', 'Service', 'Version', 'Product']
        print(c.YELLOW + tabulate(flat_results, headers=headers, tablefmt="grid") + c.END)

        print(c.BLUE + "\n[" + c.END + c.GREEN + "+" + c.END + c.BLUE + "] Starting CVE search...\n" + c.END)
        cve_results = []
        for result in flat_results:
            service = result[3]
            version = result[4]
            cves = await get_cves(service, version)
            if cves:
                cve_str = ', '.join(cves)
                # Format CVE column to limit width and number of lines
                cve_str_formatted = ''
                for i, cve in enumerate(cves):
                    if i > 0 and i % 5 == 0:
                        cve_str_formatted += '\n'
                    cve_str_formatted += f'{cve}, '
                cve_results.append([service, version, cve_str_formatted[:-2]])

        cve_headers = ['Service', 'Version', 'CVEs']
        if cve_results:
            print(c.YELLOW + tabulate(cve_results, headers=cve_headers, tablefmt="grid", colalign=("left", "left", "left")) + c.END)

        else:
            print(c.YELLOW + "\nNo CVEs found.\n" + c.END)
    else:
        print(c.YELLOW + "\nIPv4 address enumeration failed. Port scanning and CVE search aborted.\n" + c.END)
    
    return cve_results,results,flat_results


# Extra DNS info Function
def txt_enum(domain):
    print(c.BLUE + "\n[" + c.END + c.GREEN + "+" + c.END + c.BLUE + "] Enumerating extra DNS information...\n" + c.END)
    sleep(0.2)
    """
    Query to get extra info about the dns
    """
    data = []

    try:
        data = dns.resolver.resolve(domain, 'TXT')
        data = [info.to_text() for info in data]
    except dns.resolver.NoAnswer:
        data = ["No TXT records found"]
    except dns.resolver.NXDOMAIN:
        data = ["Domain does not exist"]
    except dns.exception.Timeout:
        data = ["Query timed out"]
    
    if data:
        result = "\n".join(data)
        print(c.YELLOW + result + c.END)
        return data, result
    else:
        data = ["Unable to enumerate"]
        result = "\n".join(data)
        print(c.YELLOW + result + c.END)
        return data, result

    #return data

# Function to define the resolver object and its nameservers
def get_resolver():
    resolver = dns.resolver.Resolver()
    dns_server = '8.8.8.8'
    resolver.nameservers = [dns_server, '8.8.4.4', '1.1.1.1']
    return resolver

# Function to discover the CNAME of the target
def cname_enum(domain):
    print(c.BLUE + "\n[" + c.END + c.GREEN + "+" + c.END + c.BLUE + "] Enumerating CNAME information...\n" + c.END)
    
    resolver = get_resolver()
    results = []
    try:
        answers = resolver.resolve(domain, 'CNAME')
        for rdata in answers:
            cname_record = str(rdata.target)
            print(c.YELLOW + "CNAME record found for", domain + ":", cname_record + c.END)
            results.append(cname_record)
        return results
    except dns.resolver.NoAnswer:
        print(c.YELLOW + "No CNAME records found for " + domain + c.END)
        results.append("No CNAME records found for " + domain)
    except dns.resolver.NXDOMAIN:
        print(c.YELLOW + "Domain does not exist" + c.END)
        results.append("Domain does not exist")
    except dns.exception.Timeout:
        print(c.YELLOW + "Query timed out" + c.END)
        results.append("Query timed out")
    return results

def emailAuthentication(domain):
    print(c.BLUE + "\n[" + c.END + c.GREEN + "+" + c.END + c.BLUE + "] Performing email authentication check...\n" + c.END)
    resolver = get_resolver()

    # Check for DMARC records
    dmarc_results = []
    try:
        dmarc_records = resolver.resolve('_dmarc.' + domain, 'TXT')
        print(c.YELLOW + "DMARC record found for " + domain + c.END)
        for rdata in dmarc_records:
            dmarc_results.append(str(rdata))
            print(c.YELLOW + str(rdata) + c.END)
    except dns.resolver.NXDOMAIN:
        print(c.YELLOW + "No DMARC record found for "  + domain + c.END)
        dmarc_results.append("No DMARC record found for " + domain)
    except dns.resolver.NoAnswer:
        print(c.YELLOW + "No DMARC record found for " + domain + c.END)
        dmarc_results.append("No DMARC record found for " + domain)
    except dns.exception.Timeout:
        print(c.YELLOW + "Query timed out" + c.END)
        dmarc_results.append("Query timed out")


    # Check for SPF records
    spf_results = []
    try:
        spf_records = resolver.resolve(domain, 'TXT')
        for record in spf_records:
            if 'spf1' in str(record):
                spf_record = str(record).replace('"', '')
                if '-all' in spf_record:
                    spf_results.append("-all found in SPF record")
                    print(c.YELLOW + "SPF record found for", domain + c.END)
                    print(c.YELLOW + "-all found in SPF record" + c.END)
                elif '~all' in spf_record:
                    spf_results.append("~all found in SPF record")
                    print(c.YELLOW + "SPF record found for", domain + c.END)
                    print(c.YELLOW + "~all found in SPF record" + c.END)
                else:
                    spf_results.append("SPF record found for " + domain)
                    print(c.YELLOW + "SPF record found for", domain + c.END)
                break
        else:
            print(c.YELLOW + "No SPF record found for", domain + c.END)
            spf_results.append("No SPF record found for " + domain)
    except dns.resolver.NXDOMAIN:
        print(c.YELLOW + "No SPF record found for", domain + c.END)
        spf_results.append("No SPF record found for " + domain)
    except dns.resolver.NoAnswer:
        print(c.YELLOW + "No SPF record found for", domain + c.END)
        spf_results.append("No SPF record found for " + domain)
    except dns.exception.Timeout:
        print(c.YELLOW + "Query timed out" + c.END)
        spf_results.append("Query timed out")

    # Combine results and return
    results = {'dmarc': dmarc_results, 'spf': spf_results}
    return results

# Mail servers Function
def mail_enum(domain):
    print(c.BLUE + "\n[" + c.END + c.GREEN + "+" + c.END + c.BLUE + "] Finding valid mail servers...\n" + c.END)
    sleep(0.2)
    """
    Query to get mail servers
    """
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
    except dns.resolver.NoAnswer:
        print(c.YELLOW + "No MX records found." + c.END)
        return []
    except dns.exception.DNSException as e:
        print(c.YELLOW + f"Error resolving MX records: {e}" + c.END)
        return []

    mail_servers = []
    for rdata in mx_records:
        mail_servers.append(str(rdata.exchange).strip('.'))
    
    if mail_servers:
        print(c.YELLOW + "\n".join(mail_servers) + c.END)
    else:
        print(c.YELLOW + "No mail servers found." + c.END)
    
    return mail_servers

 
# Domain Zone Transfer Attack Function
def axfr(domain):
    print(c.BLUE + "\n[" + c.END + c.GREEN + "+" + c.END + c.BLUE + "] Starting Domain Zone Transfer attack...\n" + c.END)
    sleep(0.2)
    """
    Iterate through the name servers and try an AXFR attack on everyone
    """
    print("domain :: ", domain)
    ns_answer = dns.resolver.resolve(domain, 'NS')
    result = []
    for server in ns_answer:
        ip_answer = dns.resolver.resolve(server.target, 'A')
        for ip in ip_answer:
            try:
                zone = dns.zone.from_xfr(dns.query.xfr(str(ip), domain))
                for host in zone:
                    found_host = "Found Host: {}".format(host)
                    result.append(found_host)
                    print(c.GREEN + found_host + c.END)
            except Exception as e:
                ns_refused = "NS {} refused zone transfer!".format(server)
                result.append(ns_refused)
                print(c.YELLOW + ns_refused + c.END)
                continue
    if result:
        return result
    else:
        no_result = "No results found."
        result.append(no_result)
        print(c.YELLOW + no_result + c.END)
        return result

# Modified function from https://github.com/Nefcore/CRLFsuite WAF detector script <3
def wafDetector(domain):
    """
    Get WAFs list in a file
    """
    r = requests.get("https://github.com/SkylarFlyp123/Recon-Tool-Kit/blob/main/utils/wafsign.json")
    f = open('wafsign.json', 'w', encoding='utf-8')  # Use utf-8 encoding
    f.write(r.text)
    f.close()

    with open('wafsign.json', 'r', encoding='utf-8') as file:  # Use utf-8 encoding
        wafsigns = json.load(file)

    print(c.BLUE + "\n[" + c.END + c.GREEN + "+" + c.END + c.BLUE + "] Discovering active WAF on the main web page...\n" + c.END)
    sleep(1)
    """
    Payload to trigger the possible WAF
    """
    payload = "../../../../etc/passwd"
    result = []
    try:
        """
        Check the domain and modify if necessary 
        """
        if domain.endswith("/") and domain.startswith("https://"):
            response = requests.get(domain + payload, verify=False)
        elif domain.endswith("/") and not domain.startswith("https://"):
            response = requests.get('https://' + domain + payload, verify=False)
        elif not domain.endswith("/") and domain.startswith("https://"):
            response = requests.get(domain + '/' + payload, verify=False)
        elif not domain.endswith("/") and not domain.startswith("https://"):
            response = requests.get('https://' + domain + '/' + payload, verify=False)
    except:
        result.append("An error has occurred")
        try:
            os.remove('wafsign.json')
        except:
            pass
        print(c. YELLOW + result + c.END) # print error in the terminal
        return result

    code = str(response.status_code)
    page = response.text
    headers = str(response.headers)
    cookie = str(response.cookies.get_dict())
    """
    Check if WAF has blocked the request
    """
    if int(code) >= 400:
        bmatch = [0, None]
        for wafname, wafsign in wafsigns.items():
            total_score = 0
            pSign = wafsign["page"]
            cSign = wafsign["code"]
            hSign = wafsign["headers"]
            ckSign = wafsign["cookie"]
            if pSign:
                if re.search(pSign, page, re.I):
                    total_score += 1
            if cSign:
                if re.search(cSign, code, re.I):
                    total_score += 0.5
            if hSign:
                if re.search(hSign, headers, re.I):
                    total_score += 1
            if ckSign:
                if re.search(ckSign, cookie, re.I):
                    total_score += 1
            if total_score > bmatch[0]:
                del bmatch[:]
                bmatch.extend([total_score, wafname])

        if bmatch[0] != 0:
            result.append("WAF Detected: {}".format(bmatch[1]))
        else:
            result.append("WAF not detected or doesn't exist")
    else:
        result.append("An error has occurred or unable to enumerate")

    try:
        os.remove('wafsign.json')
    except:
        pass

    print(c.YELLOW + "\n".join(result) + c.END) # print result in the terminal
    return result


# Function to check subdomain takeover
def subTakeover(all_subdomains):
    """
    Iterate through all the subdomains to check if anyone is vulnerable to subdomain takeover
    """
    vulnerable_subdomains = []
    print(c.BLUE + "\n[" + c.GREEN + "+" + c.BLUE + "] Checking if any subdomain is vulnerable to takeover\n" + c.END)
    sleep(1)
    results = []
    
    for subdom in all_subdomains:
        try:
            sleep(0.05)
            resquery = dns.resolver.resolve(subdom, 'CNAME')
            for resdata in resquery:
                resdata = (resdata.to_text())
                if subdom[-8:] in resdata:
                    r = requests.get("https://" + subdom, allow_redirects=False)
                    if r.status_code == 200:
                        vulnerable_subdomains.append(subdom)
                        result = subdom + " appears to be vulnerable"
                        results.append(result)
                        print(c.YELLOW + result + c.END)
                else:
                    pass
        except KeyboardInterrupt:
            sys.exit(c.RED + "\n[!] Interrupt handler received, exiting...\n" + c.END)
        except:
            pass
    
    if len(vulnerable_subdomains) == 0:
        result = "No subdomains are vulnerable \n"
        results.append(result)
        print(c.YELLOW + result + c.END)
    else:
        results.append(result)
        print(c.YELLOW + result + c.END)
    
    return results

# Function to enumerate github and cloud
def cloudgitEnum(domain):
    print(c.BLUE + "\n[" + c.END + c.GREEN + "+" + c.END + c.BLUE + "] Looking for git repositories and public development info\n" + c.END)
    sleep(0.2)
    results = []
    
    try:
        r = requests.get("https://" + domain + "/.git/", verify=False)
        results.append("Git repository URL: https://" + domain + "/.git/ - " + str(r.status_code) + " status code")
    except:
        pass
    
    try:
        r = requests.get("https://bitbucket.org/" + domain.split(".")[0])
        results.append("Bitbucket account URL: https://bitbucket.org/" + domain.split(".")[0] + " - " + str(r.status_code) + " status code")
    except:
        pass
    
    try:
        r = requests.get("https://github.com/" + domain.split(".")[0])
        results.append("Github account URL: https://github.com/" + domain.split(".")[0] + " - " + str(r.status_code) + " status code")
        
    except:
        pass
    
    try:
        r = requests.get("https://gitlab.com/" + domain.split(".")[0])
        results.append("Gitlab account URL: https://gitlab.com/" + domain.split(".")[0] + " - " + str(r.status_code) + " status code")
    except:
        pass
    
    if not results:
        print(c.YELLOW + "No git repositories or public development info found." + c.END)
        return ["No git repositories or public development info found."]
    else:
        print(c.YELLOW + "\n".join(results) + c.END)
        return results

# Query the domain
def whoisLookup(domain):
    print(c.BLUE + "\n[" + c.END + c.GREEN + "+" + c.END + c.BLUE + "] Performing Whois lookup..." + c.END)
    import whois
    sleep(1.2)

    try:
        w = whois.whois(domain) # Two different ways to avoid a strange error
    except:
        w = whois.query(domain)

    # Check if any data is available in whois result
    if not w.domain_name and not w.registrar and not w.whois_server and not w.referral_url \
            and not w.updated_date and not w.creation_date and not w.expiration_date \
            and not w.name_servers and not w.status and not w.emails and not w.dnssec \
            and not w.name and not w.org and not w.address and not w.city and not w.state \
            and not w.registrant_postal_code and not w.country:
        result = ["No Whois data found for " + domain]
    else:
        result = str(w).split("\n")

    print(c.YELLOW + "\n" + str(result) + c.END)
    return result


# Function to thread when probing active subdomains
def checkStatus(domain, subdomains):
    results = []
    try:
        for subdomain in subdomains:
            r = requests.get("https://" + subdomain, timeout=2)
            # Just check if the web is up and https
            if r.status_code:
                results.append("https://" + subdomain)
    except:
        try:
            for subdomain in subdomains:
                r = requests.get("http://" + subdomain, timeout=2)
                # Check if is up and http
                if r.status_code:
                    results.append("http://" + subdomain)
        except:
            pass
    return results


# Check status function
def checkActiveSubs(domain, doms):
    import threading

    print(c.BLUE + "\n[" + c.END + c.GREEN + "+" + c.END + c.BLUE + "] Probing active subdomains..." + c.END)

    """ Define filename """
    domain_name = domain.split(".")[0]
    results = []
    """
    Iterate through all subdomains in threads
    """
    threads_list = []
    for subdomain in doms:
        t = threading.Thread(target=lambda subdomain: results.extend(checkStatus(domain, [subdomain])), args=(subdomain,))
        t.start()
        threads_list.append(t)
    for proc_thread in threads_list: # Wait until all thread finish
        proc_thread.join()

    with open(f"{domain_name}-active-subs.txt", "w") as file:
        for result in results:
            file.write(result + "\n")

    print(c.YELLOW + f"\nActive subdomains stored in {domain_name}-active-subs.txt" + c.END)
    return results

# Fuzz a little looking for backups
def findBackups(domain):
    print(c.BLUE + "\n[" + c.END + c.GREEN + "+" + c.END + c.BLUE + "] Looking for common backup files...\n" + c.END)
    back_counter = 0
    hostname = domain.split(".")[0]
    protocols = ["http", "https"]
    filenames = [hostname, domain, "backup", "admin"]
    extensions = ["sql.tar","tar","tar.gz","gz","tar.bzip2","sql.bz2","sql.7z","zip","sql.gz","7z"]
    results = []
    # Some common backup filenames with multiple extensions
    for protocol in protocols:
        for filename in filenames:
            for ext in extensions:
                url = protocol + "://" + domain + "/" + filename + "." + ext
                try:
                    r = requests.get(url, verify=False)
                    code = r.status_code
                except:
                    continue
                if code != 404:
                    back_counter += 1
                    result_str = url + " - " + str(code)
                    results.append(result_str)
                    print(c.YELLOW + result_str + c.END)

    if back_counter == 0:
        print(c.YELLOW + "No backup files found" + c.END)
        results.append("No backup files found")
    return results


# Look for Google Maps API key and test if it's vulnerable
def findSecrets(domain):
    print(c.BLUE + "\n[" + c.END + c.GREEN + "+" + c.END + c.BLUE + "] Trying to find possible secrets and API keys...\n" + c.END)
    results = []
    for protocol in ["https", "http"]:
        res = findSecretsFromUrl(protocol + "://" + domain)
        if res:
            print(c.YELLOW + "\nResults from " + protocol + ":\n" + c.END)
            for r in res:
                print(c.YELLOW + r + c.END)
            results += res

    return results

def findSecretsFromUrl(url):
    # Initial request
    try:
        r = requests.get(url, verify=False)
    except:
        return []

    js_list = []
    key_counter = 0
    url_list = re.findall(r'src="(.*?)"', r.text) + re.findall(r'href="(.*?)"', r.text)

    # Get JS endpoints
    for endpoint in url_list:
        if ".js" in endpoint and "https://" not in endpoint:
            js_list.append(endpoint)

    results = []
    for js_endpoint in js_list:
        try:
            r = requests.get(url + js_endpoint, verify=False)
        except:
            continue
        if "https://maps.googleapis.com/" in r.text:
            maps_api_key = re.findall(r'src="https://maps.googleapis.com/(.*?)"', r.text)[0]
            results.append("\nMaps API key found: " + maps_api_key)
            key_counter = 1
        try:
            google_api = re.findall(r'AIza[0-9A-Za-z-_]{35}', r.text)[0]
            if google_api:
                results.append("\nGoogle API found: " + google_api)
                key_counter = 1
        except:
            pass
        try:
            google_oauth = re.findall(r'ya29\.[0-9A-Za-z\-_]+', r.text)[0]
            if google_oauth:
                results.append("\nGoogle OAuth found: " + google_oauth)
                key_counter = 1
        except:
            pass
        try:
            amazon_aws_url = re.findall(r's3\.amazonaws.com[/]+|[a-zA-Z0-9_-]*\.s3\.amazonaws.com', r.text)[0]
            if amazon_aws_url:
                results.append("\nAmazon AWS URL found on " + js_endpoint)
                key_counter = 1
        except:
            pass
        try:
            stripe_key = re.findall(r'"pk_live_.*"', r.text)[0].replace('"', '')
            if stripe_key:
                results.append("\nStripe key found on " + js_endpoint)
                key_counter = 1
        except:
            pass

    if len(js_list) >= 1:
        results.append("\nDiscovered JS endpoints:")
        for js in js_list:
            results.append(url + js)

    if key_counter != 1:
        results.append("\nNo secrets found")

    return results

# Look for technologies used in the web app, their versions and search for CVE
def search_cves(technology, version):
    """
    Search for CVEs using the NVD API.
    """
    cve_ids = []
    try:
        # format query string with technology and version
        query = f"{technology} {version}".replace(' ', '+')
        url = f"https://services.nvd.nist.gov/rest/json/cves/1.0?keyword={query}"
        response = requests.get(url)

        if response.ok:
            data = response.json()
            for cve_item in data['result']['CVE_Items']:
                cve_id = cve_item['cve']['CVE_data_meta']['ID']
                cve_ids.append(cve_id)
        else:
            pass
    except:
        print(f"An error has occurred while searching for CVEs for {technology} {version}")

    return cve_ids

def enumerate_with_wappalyzer(domain):
    # Suppress the UserWarning
    warnings.filterwarnings("ignore", message="Caught 'unbalanced parenthesis at position 119' compiling regex")

    """
    Perform enumeration using Wappalyzer.
    """
    print(c.BLUE + "\n[" + c.END + c.GREEN + "+" + c.END + c.BLUE + "] Performing enumeration using Wappalyzer...\n" + c.END)

    results = []

    try:
        from Wappalyzer import Wappalyzer, WebPage
        wappalyzer = Wappalyzer.latest()
        webpage = WebPage.new_from_url('https://' + domain)
        info = wappalyzer.analyze_with_versions(webpage)

        if info != "{}":
            data = []
            for technology, versions in info.items():
                if versions:
                    version = list(versions.values())[0]
                    version_str = ', '.join(version)
                    cves = search_cves(technology, version_str)
                    # Format CVE column to limit width and number of lines
                    if len(cves) > 5:
                        cve_lines = [', '.join(cves[i:i+5]) for i in range(0, len(cves), 5)]
                        cve_formatted = '\n'.join(cve_lines)
                    else:
                        cve_formatted = ', '.join(cves)
                    data.append({'Technology': technology, 'Version': version_str, 'CVE': cve_formatted})
                else:
                    cves = search_cves(technology, '')
                    # Format CVE column to limit width and number of lines
                    if len(cves) > 5:
                        cve_lines = [', '.join(cves[i:i+5]) for i in range(0, len(cves), 5)]
                        cve_formatted = '\n'.join(cve_lines)
                    else:
                        cve_formatted = ', '.join(cves)
                    data.append({'Technology': technology, 'Version': '', 'CVE': cve_formatted})
            table = tabulate(data, headers='keys', tablefmt='grid', colalign=('left', 'left', 'left'))
            print(c.YELLOW + table + c.END)
            results.append(data)
        else:
            print(c.YELLOW + "\nNo common technologies found \n" + c.END)
            results.append("\nNo common technologies found\n")
    except:
        print(c.YELLOW +  "An error has occurred or unable to enumerate \n")
        results.append("\nAn error has occurred or unable to enumerate\n")

    '''json_data = json.dumps(results).replace(r'\n','')
    print(c.YELLOW + json_data + c.END)'''
    return results


def enumerate_with_endpoints(domain):
    """
    Test common endpoints for enumeration.
    """
    print(c.BLUE + "\n[" + c.END + c.GREEN + "+" + c.END + c.BLUE + "] Testing common endpoints for enumeration...\n" + c.END)

    results = []

    endpoints = ["robots.txt","xmlrpc.php","wp-cron.php","actuator/heapdump","datahub/heapdump","datahub/actuator/heapdump","heapdump","admin/",".env",".config","version.txt","README.md","license.txt","config.php.bak","api/","feed.xml","CHANGELOG.md","config.json","cgi-bin/","env.json",".htaccess","js/","kibana/","log.txt"]
    for end in endpoints:
        try:
            r = requests.get(f"https://{domain}/{end}", timeout=4)
            print(c.YELLOW + f"https://{domain}/{end} - " + str(r.status_code) + c.END)
            results.append(f"\nhttps://{domain}/{end} - {str(r.status_code)}\n")
        except:
            print(c.YELLOW + f"Unable to access https://{domain}/{end}" + c.END + "\n")
            results.append(f"\nUnable to access https://{domain}/{end}\n")

    return results
    print(results)

# Main Domain Discoverer Function
def SDom(domain,filename):
    print(c.BLUE + "\n[" + c.END + c.GREEN + "+" + c.END + c.BLUE + "] Discovering subdomains using passive techniques...\n" + c.END)
    sleep(0.1)
    global doms
    doms = []
    """
    Get valid subdomains from crt.sh
    """
    try:
        r = requests.get("https://crt.sh/?q=" + domain + "&output=json", timeout=20)
        formatted_json = json.dumps(json.loads(r.text), indent=4)
        crt_domains = sorted(set(re.findall(r'"common_name": "(.*?)"', formatted_json)))
        # Only append new valid subdomains
        for dom in crt_domains:
            if dom.endswith(domain) and dom not in doms:
                doms.append(dom)

    except KeyboardInterrupt:
        sys.exit(c.RED + "\n[!] Interrupt handler received, exiting...\n" + c.END)
    except:
        pass      
    """
    Get subdomains from AlienVault
    """
    try:
        r = requests.get(f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns", timeout=20)
        alienvault_domains = sorted(set(re.findall(r'"hostname": "(.*?)"', r.text)))
        # Only append new valid subdomains
        for dom in alienvault_domains:
            if dom.endswith(domain) and dom not in doms:
                doms.append(dom)
    except KeyboardInterrupt:
        sys.exit(c.RED + "\n[!] Interrupt handler received, exiting...\n" + c.END)
    except:
        pass
    """
    Get subdomains from Hackertarget
    """
    try:
        r = requests.get(f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=20)
        hackertarget_domains = re.findall(r'(.*?),', r.text)
        # Only append new valid subdomains
        for dom in hackertarget_domains:
            if dom.endswith(domain) and dom not in doms:
                doms.append(dom)        
    except KeyboardInterrupt:
        sys.exit(c.RED + "\n[!] Interrupt handler received, exiting...\n" + c.END)
    except:
        pass    
    """
    Get subdomains from RapidDNS
    """
    try:
        r = requests.get(f"https://rapiddns.io/subdomain/{domain}", timeout=20)
        rapiddns_domains = re.findall(r'target="_blank".*?">(.*?)</a>', r.text)
        # Only append new valid subdomains
        for dom in rapiddns_domains:
            if dom.endswith(domain) and dom not in doms:
                doms.append(dom)          
    except KeyboardInterrupt:
        sys.exit(c.RED + "\n[!] Interrupt handler received, exiting...\n" + c.END)
    except:
        pass
    """
    Get subdomains from Riddler
    """
    try:
        r = requests.get(f"https://riddler.io/search/exportcsv?q=pld:{domain}", timeout=20)
        riddler_domains = re.findall(r'\[.*?\]",.*?,(.*?),\[', r.text)
        # Only append new valid subdomains
        for dom in riddler_domains:
            if dom.endswith(domain) and dom not in doms:
                doms.append(dom)        
    except KeyboardInterrupt:
        sys.exit(c.RED + "\n[!] Interrupt handler received, exiting...\n" + c.END)
    except:
        pass
    """
    Get subdomains from ThreatMiner
    """
    try:
        r = requests.get(f"https://api.threatminer.org/v2/domain.php?q={domain}&rt=5", timeout=20)
        raw_domains = json.loads(r.content)
        threatminer_domains = raw_domains['results']
        # Only append new valid subdomains
        for dom in threatminer_domains:
            if dom.endswith(domain) and dom not in doms:
                doms.append(dom)
    except KeyboardInterrupt:
        sys.exit(c.RED + "\n[!] Interrupt handler received, exiting...\n" + c.END)
    except:
        pass
    """
    Get subdomains from URLScan
    """
    try:
        r = requests.get(f"https://urlscan.io/api/v1/search/?q={domain}", timeout=20)
        urlscan_domains = sorted(set(re.findall(r'https://(.*?).' + domain, r.text)))
        # Only append new valid subdomains
        for dom in urlscan_domains:
            dom = dom + "." + domain
            if dom.endswith(domain) and dom not in doms:
                doms.append(dom)        
    except KeyboardInterrupt:
        sys.exit(c.RED + "\n[!] Interrupt handler received, exiting...\n" + c.END)
    except:
        pass
                
    if filename != None:
        f = open(filename, "a")
    
    if doms:
        """
        Iterate through the subdomains and check the lenght to print them in a table format
        """
        print(c.YELLOW + "+" + "-"*47 + "+")
        for value in doms:
    
            if len(value) >= 10 and len(value) <= 14:
                print("| " + value + "    \t\t\t\t|")
                if filename != None:
                    f.write(value + "\n")
            if len(value) >= 15 and len(value) <= 19:
                print("| " + value + "\t\t\t\t|")
                if filename != None:
                    f.write(value + "\n")
            if len(value) >= 20 and len(value) <= 24:
                print("| " + value + "   \t\t\t|")
                if filename != None:
                    f.write(value + "\n")
            if len(value) >= 25 and len(value) <= 29:
                print("| " + value + "\t\t\t|")
                if filename != None:
                    f.write(value + "\n")
            if len(value) >= 30 and len(value) <= 34:
                print("| " + value + " \t\t|")
                if filename != None:
                    f.write(value + "\n")
            if len(value) >= 35 and len(value) <= 39:
                print("| " + value + "   \t|")
                if filename != None:
                    f.write(value + "\n")
            if len(value) >= 40 and len(value) <= 44:
                print("| " + value + " \t|")
                if filename != None:
                    f.write(value + "\n")
        """
        Print summary
        """
        print("+" + "-"*47 + "+" + c.END)
        print(c.YELLOW + "\nTotal discovered sudomains: " + str(len(doms)) + c.END)
        """
        Close file if "-o" parameter was especified
        """
        if filename != None:
            f.close()
            print(c.BLUE + "\n[" + c.GREEN + "+" + c.BLUE + "] Output stored in " + filename)
    else:
        print(c.YELLOW + "No subdomains discovered through SSL transparency" + c.END)
    
    return doms

# Check if the given target is active
def checkDomain(domain):

    try:
        addr = socket.gethostbyname(domain)
    except:
        print(c.YELLOW + "\nTarget doesn't exists or is down" + c.END)
        sys.exit(1)

# Program workflow starts here
if __name__ == '__main__':
    program_version = 1.7
    urllib3.disable_warnings()
    warnings.simplefilter('ignore')

    if "--version" in sys.argv:
        print("\nAll in One Recon Tool v" + str(program_version) + " - By D3Ext")
        print("Contact me: <d3ext@proton.me>\n")
        sys.exit(0)

    parse = parseArgs()

    # Check domain format
    if "." not in parse.domain:
        print(c.YELLOW + "\nInvalid domain format, example: domain.com" + c.END)
        sys.exit(0)

    # If --output is passed (store subdomains in file)
    if parse.output:
        store_info=1
        filename = parse.output
    else:
        filename = None

    global domain

    domain = parse.domain
    checkDomain(domain)
    """
    If --all is passed do all enumeration processes
    """
    if parse.domain and parse.all:

        if domain.startswith('https://'):
            domain = domain.split('https://')[1]
        if domain.startswith('http://'):
            domain = domain.split('http://')[1]

        try:
            if not parse.quiet:
                banner()
            whoisLookup(domain)
            SDom(domain,filename)
            checkActiveSubs(domain,doms)
            subTakeover(doms)
            axfr(domain)
            ns_enum(domain)
            txt_enum(domain)
            cname_enum(domain)
            mail_enum(domain)
            emailAuthentication(domain)
            wafDetector(domain)
            ipv4_enumeration(domain)
            ipv6_enum(domain)
            asyncio.run(scan_ipv4_ports(domain)) 
            findBackups(domain)
            findSecrets(domain)
            cloudgitEnum(domain)
            enumerate_with_wappalyzer(domain)
            enumerate_with_endpoints(domain)
            
            
            try:
                file.close()
            except:
                pass
        except KeyboardInterrupt:
            sys.exit(c.RED + "\n[!] Interrupt handler received, exiting...\n" + c.END)

        sys.exit(0)

    """
    Enter in this part if the --all isn't passed
    """
    if parse.domain:
        domain = parse.domain

        if domain.startswith('https://'):
            domain = domain.split('https://')[1]
        if domain.startswith('http://'):
            domain = domain.split('http://')[1]

        try:
            if not parse.quiet:
                banner()
            SDom(domain,filename)
            """
            Check the passed arguments via command line
            """
            
            if parse.nameservers:
                ns_enum(domain)
            if parse.axfr:
                axfr(domain)
            if parse.mail:
                mail_enum(domain)
            if parse.ip:
                ipv4_enumeration(domain)
            if parse.ipv6:
                ipv6_enum(domain)
            if parse.extra:
                txt_enum(domain)
            if parse.cname:
                cname_enum(domain)
            if parse.whois:
                whoisLookup(domain)
            if parse.enum:
                basicEnum(domain)
            if parse.backups:
                findBackups(domain)
            if parse.secrets:
                findSecrets(domain)
            if parse.repos:
                cloudgitEnum(domain)
            if parse.waf:
                wafDetector(domain)
            if parse.check:
                checkActiveSubs(domain,doms)
            if parse.wappalyzer:
                enumerate_with_wappalyzer(domain)
            if parse.endpoints:
                enumerate_with_endpoints(domain)
            if parse.subtakeover:
                subTakeover(doms)
            if parse.emailauth:
                emailAuthentication(domain)
            if parse.ipv4_portscan:
                asyncio.run(scan_ipv4_ports(domain))
            
            '''if parse.portscan:
                portScan(domain)'''
            
    
        except KeyboardInterrupt:
            sys.exit(c.RED + "\n[!] Interrupt handler received, exiting...\n" + c.END)


