from recon_tool_kit import app, db
from recon_tool_kit.rtk import * 
from flask import Flask, render_template, request
from recon_tool_kit import logging
from recon_tool_kit.models import *
from recon_tool_kit.helpers import *
import json

logging.basicConfig(filename='app.log', level=logging.DEBUG, format=f'%(asctime)s %(levelname)s %(name)s %(threadName)s : %(message)s')
logger = logging.getLogger(__name__)

@app.route('/')
@app.route('/home/')
def home():
    return render_template('home.html')

@app.route('/results/', methods=['GET', 'POST'])
def subdomain():
    if request.method == 'POST':
        domain = request.form['domain']
        
        email = request.form['email'] 
        dbDomain = saveDomain(domain, email)

        logger.info(f"Whois Lookup started for {domain}")
        whois = whoisLookup(domain)
        logger.info(f"Whois Lookup completed for {domain}")
        # Create and store Whois object in the database
        dbWhois = saveWhois(dbDomain.id, json.dumps(whois))

        logger.info(f"Subdomain enumeration started for {domain}")
        filename = 'random.txt'
        subdomains = SDom(domain, filename)
        logger.info(f"Subdomain enumeration completed for {domain}")
        # Create and store Subdomain objects in the database 
        for subdomain in subdomains:
            dbSubdomain = saveSubdomain(dbDomain.id, subdomain)

        logger.info(f"Checking active subs started for {domain}")
        active_subs = checkActiveSubs(domain, subdomains)
        logger.info(f"Checking active subs completed for {domain}")
        
        for active_subdomain in active_subs:
            dbActiveSubs = saveActiveSubs(dbDomain.id, active_subdomain)

        logger.info(f"Subdomain takeover test started for {domain}")
        subdomain_takeover = subTakeover(subdomains)
        logger.info(f"Subdomain takeover test started for {domain}")

        for taken_over_subdomain in subdomain_takeover:
            dbSubdomainTakeover = saveSubdomainTakeover(dbDomain.id, taken_over_subdomain)

        logger.info(f"Zone transfer started for {domain}")
        zone_transfer = axfr(domain)
        logger.info(f"Zone transfer completed for {domain}")

        for zone_transfer_subdomain in zone_transfer:
            dbZoneTransfer = saveZoneTransfer(dbDomain.id, zone_transfer_subdomain)

        logger.info(f"DNS enumeration started for {domain}")
        dns_records = ns_enum(domain)
        logger.info(f"DNS enumeration completed for {domain}")

        for dns_record in dns_records:
            dbDnsRecord = saveDNSRecords(dbDomain.id, dns_record)

        logger.info(f"TXT enumeration started for {domain}")
        txt_records = txt_enum(domain)
        logger.info(f"TXT enumeration completed for {domain}")

        for txt_record in txt_records:
            if type(txt_record) in (tuple, list):
                for record in txt_record:
                    dbTxtRecord = saveTXTRecords(dbDomain.id, record)
            else:
                dbTxtRecord = saveTXTRecords(dbDomain.id, txt_record)

        logger.info(f"CNAME enumeration started for {domain}")
        cname_info = cname_enum(domain)
        logger.info(f"CNAME enumeration completed for {domain}")

        logger.info(f"Mail server enumeration started for {domain}")
        mail_servers = mail_enum(domain)
        logger.info(f"Mail server enumeration completed for {domain}")

        for mail_server in mail_servers:
            dbMailServer = saveMailServer(dbDomain.id, mail_server)

        logger.info(f"Email authentication check started fro {domain}")
        email_auth = emailAuthentication(domain)
        logger.info(f"Email authentication check completed for {domain}")

        for email_authentication_key in email_auth:
            for email_authentication in email_auth[email_authentication_key]:
                dbEmailAuth = saveEmailAuthentication(dbDomain.id, email_authentication)

        logger.info(f"WAF detection started for {domain}")
        waf = wafDetector(domain)
        logger.info(f"WAF detection completed for {domain}")

        for waf_detection in waf:
            dbWAF = saveWAF(dbDomain.id, waf_detection)

        logger.info(f"IPv4 enumeration started for {domain}")
        ipv4_addresses = ipv4_enumeration(domain)
        logger.info(f"IPv4 enumeration completed for {domain}")

        for ipv4_address in ipv4_addresses:
            dbIPv4 = saveIPv4(dbDomain.id, ipv4_address)
        
        logger.info(f"IPv6 enumeration started for {domain}")
        ipv6_addresses = ipv6_enum(domain)
        logger.info(f"IPv6 enumeration completed for {domain}")

        if ipv6_addresses is not None:
            for ipv6_address in ipv6_addresses:
                dbIPv6 = saveIPv6(dbDomain.id, ipv6_address)

        logger.info(f"Port scanning started for IPv4 of {domain}")
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        cve_results, results, flat_results = loop.run_until_complete(scan_ipv4_ports(domain))
        logger.info(f"Port scanning completed for IPv4 of {domain}")
        
        logger.info(f"Looking for common backup files started for {domain}")
        common_backups = findBackups(domain)
        logger.info(f"Looking for common backup files completed for {domain}")

        for common_backup in common_backups:
            dbCommonBackups = saveCommonBackups(dbDomain.id, common_backup)

        logger.info(f"Looking for possible secrets and api keys started for {domain}")
        find_secrets = findSecrets(domain)
        logger.info(f"Looking for possible secrets and api keys completed for {domain}")

        for find_secret in find_secrets:
            dbFindSecrets = saveFindSecrets(dbDomain.id, find_secret)

        logger.info(f"Looking for git repositories and public development info started for {domain}")
        cloudgit_enumeration = cloudgitEnum(domain)
        logger.info(f"Looking for git repositories and public development info completed for {domain}")

        for cloudgit_findings in cloudgit_enumeration:
            dbCloudgitEnumeration = saveCloudgitEnumeration(dbDomain.id, cloudgit_findings)
        
        logger.info(f"Checking status started for {domain}")
        status_check = checkStatus(subdomain, filename)
        logger.info(f"Checking status completed for {domain}")

        
        logger.info(f"Version detection from wappalyzer started for {domain}")
        wappalyzer_version = enumerate_with_wappalyzer(domain)
        logger.info(f"Version detection from wappalyzer completed for {domain}")

        for wappalyzer in wappalyzer_version:
            for analyzer in wappalyzer:
                dbWappalyzerVersion = saveWappalyzerVersion(dbDomain.id, analyzer['Technology'], analyzer['Version'], analyzer['CVE'])
        

        logger.info(f"Searching for common endpoints started for {domain}")
        endpoints_enumeration = enumerate_with_endpoints(domain)
        logger.info(f"Searching for common endpoints completed for {domain}")

        for endpoints in endpoints_enumeration:
            dbEndpointsEnumeration = saveEndpointsEnumeration(dbDomain.id, endpoints)
        
        '''
        logger.info(f"Mail detection started for {domain}")
        mail_id = crawlMails(domain, api_token)
        logger.info(f"Mail detection completed for {domain}")'''

        return render_template('index.html', domain=domain, subdomains=subdomains, dns_records=dns_records, txt_records=txt_records, ipv4_addresses=ipv4_addresses, ipv6_addresses=ipv6_addresses, mail_servers=mail_servers, dmarc_results=email_auth['dmarc'], spf_results=email_auth['spf'], zone_transfer=zone_transfer, waf=waf, subdomain_takeover=subdomain_takeover, cloudgit_enumeration=cloudgit_enumeration, whois=whois, status_check=status_check, active_subs=active_subs, common_backups=common_backups, find_secrets=find_secrets, wappalyzer_version=wappalyzer_version, endpoints_enumeration=endpoints_enumeration, cname_info=cname_info, results=results, flat_results=flat_results, cve_results=cve_results), 200, {'Content-Type': 'text/html;'}
        # return render_template('index.html', domain=domain, whois=whois), 200, {'Content-Type': 'text/html;'}

    else:
        return render_template('home.html')

# 