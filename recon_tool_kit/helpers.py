from recon_tool_kit import db
from recon_tool_kit.models import *

def saveDomain(domain, email):
    dbDomain = Domain.query.filter_by(domain_name=domain).first()

    if dbDomain is None:        
        newDomain = Domain(domain_name=domain)
        db.session.add(newDomain)
        db.session.commit()
        dbDomain = newDomain
    else:
        db.session.query(Domain).filter(Domain.domain_name == domain).update({'email': email})
        db.session.commit()
    return dbDomain

def saveWhois(domain_id, whois):
    dbWhois = Whois.query.filter_by(domain_id=domain_id).first()

    if dbWhois is None:
        newWhois = Whois(domain_id=domain_id, whois_info=whois)
        db.session.add(newWhois)
        db.session.commit()
        dbWhois = newWhois
    # else update the whios info
    else:
        db.session.query(Whois).filter(Whois.domain_id == domain_id).update({'whois_info': whois})
        db.session.commit()
       
    return dbWhois

def saveSubdomain(domain_id, subdomain):
  
    dbSubdomain = Subdomain.query.filter_by(domain_id=domain_id, subdomain_name=subdomain).first()

    if dbSubdomain is None:
        newSubdomain = Subdomain(domain_id=domain_id, subdomain_name=subdomain)
        db.session.add(newSubdomain)
        db.session.commit()
        dbSubdomain = newSubdomain

    return dbSubdomain

def saveActiveSubs(domain_id, active_subdomain):

    dbActiveSubs = ActiveSubdomain.query.filter_by(domain_id=domain_id, active_subdomain_name=active_subdomain).first()

    if dbActiveSubs is None:
        newActiveSubs = ActiveSubdomain(domain_id=domain_id, active_subdomain_name=active_subdomain)
        db.session.add(newActiveSubs)
        db.session.commit()
        dbActiveSubs = newActiveSubs

    return dbActiveSubs

def saveSubdomainTakeover(domain_id, taken_over_subdomain):

    dbSubdomainTakeover = SubdomainTakeover.query.filter_by(domain_id=domain_id, subdomain_takeover_name=taken_over_subdomain).first()

    if dbSubdomainTakeover is None:
        newSubdomainTakeover = SubdomainTakeover(domain_id=domain_id, subdomain_takeover_name=taken_over_subdomain)
        db.session.add(newSubdomainTakeover)
        db.session.commit()
        dbSubdomainTakeover = newSubdomainTakeover

    return dbSubdomainTakeover

def saveZoneTransfer(domain_id, zone_transfer):

    dbZoneTransfer = ZoneTransfer.query.filter_by(domain_id=domain_id, zone_transfer_name=zone_transfer).first()

    if dbZoneTransfer is None:
        newZoneTransfer = ZoneTransfer(domain_id=domain_id, zone_transfer_name=zone_transfer)
        db.session.add(newZoneTransfer)
        db.session.commit()
        dbZoneTransfer = newZoneTransfer

    return dbZoneTransfer

def saveDNSRecords(domain_id, dns_record):

    dbDNSRecords = DNSRecords.query.filter_by(domain_id=domain_id, dns_record_name=dns_record).first()

    if dbDNSRecords is None:
        newDNSRecords = DNSRecords(domain_id=domain_id, dns_record_name=dns_record)
        db.session.add(newDNSRecords)
        db.session.commit()
        dbDNSRecords = newDNSRecords

    return dbDNSRecords

def saveTXTRecords(domain_id, txt_record):

    dbTXTRecords = TXTRecords.query.filter_by(domain_id=domain_id, txt_record_name=txt_record).first()

    if dbTXTRecords is None:
        newTXTRecords = TXTRecords(domain_id=domain_id, txt_record_name=txt_record)
        db.session.add(newTXTRecords)
        db.session.commit()
        dbTXTRecords = newTXTRecords

    return dbTXTRecords

def saveMailServer(domain_id, mail_server):

    dbMailServer = MailServers.query.filter_by(domain_id=domain_id, mail_server_name=mail_server).first()

    if dbMailServer is None:
        newMailServer = MailServers(domain_id=domain_id, mail_server_name=mail_server)
        db.session.add(newMailServer)
        db.session.commit()
        dbMailServer = newMailServer

    return dbMailServer

def saveEmailAuthentication(domain_id, email_authentication):

    dbEmailAuthentication = EmailAuthentication.query.filter_by(domain_id=domain_id, email_authentication_name=email_authentication).first()

    if dbEmailAuthentication is None:
        newEmailAuthentication = EmailAuthentication(domain_id=domain_id, email_authentication_name=email_authentication)
        db.session.add(newEmailAuthentication)
        db.session.commit()
        dbEmailAuthentication = newEmailAuthentication

    return dbEmailAuthentication

def saveWAF(domain_id, waf):

    dbWAF = WAF.query.filter_by(domain_id=domain_id, waf_name=waf).first()

    if dbWAF is None:
        newWAF = WAF(domain_id=domain_id, waf_name=waf)
        db.session.add(newWAF)
        db.session.commit()
        dbWAF = newWAF

    return dbWAF

def saveIPv4(domain_id, ipv4):

    dbIPv4 = IPv4.query.filter_by(domain_id=domain_id, ipv4_name=ipv4).first()

    if dbIPv4 is None:
        newIPv4 = IPv4(domain_id=domain_id, ipv4_name=ipv4)
        db.session.add(newIPv4)
        db.session.commit()
        dbIPv4 = newIPv4

    return dbIPv4

def saveIPv6(domain_id, ipv6):

    dbIPv6 = IPv6.query.filter_by(domain_id=domain_id, ipv6_name=ipv6).first()

    if dbIPv6 is None:
        newIPv6 = IPv6(domain_id=domain_id, ipv6_name=ipv6)
        db.session.add(newIPv6)
        db.session.commit()
        dbIPv6 = newIPv6

    return dbIPv6

# def savePortScan(domain_id, ipv4_address, port, protocol, state, service, version):

#     dbPortScan = PortScan.query.filter_by(domain_id=domain_id, ipv4=ipv4_address, port_no=port, protocol_name=protocol, state_result=state, service_result=service, version_no=version, product_name=product, cve_id=cve).first()

#     if dbPortScan is None:
#         newPortScan = PortScan(omain_id, ipv4_address, port, protocol, state, service, version)
#         db.session.add(newPortScan)
#         db.session.commit()
#         dbPortScan = newPortScan

#     return dbPortScan

def saveCommonBackups(domain_id, common_backup):

    dbCommonBackups = CommonBackups.query.filter_by(domain_id=domain_id, common_backups_name=common_backup).first()

    if dbCommonBackups is None:
        newCommonBackups = CommonBackups(domain_id=domain_id, common_backups_name=common_backup)
        db.session.add(newCommonBackups)
        db.session.commit()
        dbCommonBackups = newCommonBackups

    return dbCommonBackups

def saveFindSecrets(domain_id, find_secrets):

    dbFindSecrets = FindSecrets.query.filter_by(domain_id=domain_id, find_secrets_name=find_secrets).first()

    if dbFindSecrets is None:
        newFindSecrets = FindSecrets(domain_id=domain_id, find_secrets_name=find_secrets)
        db.session.add(newFindSecrets)
        db.session.commit()
        dbFindSecrets = newFindSecrets

    return dbFindSecrets

def saveCloudgitEnumeration(domain_id, cloudgit_enumeration):

    dbCloudgitEnumeration = CloudgitEnumeration.query.filter_by(domain_id=domain_id, cloudgit_enumeration_name=cloudgit_enumeration).first()

    if dbCloudgitEnumeration is None:
        newCloudgitEnumeration = CloudgitEnumeration(domain_id=domain_id, cloudgit_enumeration_name=cloudgit_enumeration)
        db.session.add(newCloudgitEnumeration)
        db.session.commit()
        dbCloudgitEnumeration = newCloudgitEnumeration

    return dbCloudgitEnumeration

def saveWappalyzerVersion(domain_id, wappalyzer_technology,wappalyzer_version_no, wappalyzer_cve):

    dbWappalyzerVersion = WappalyzerVersion.query.filter_by(domain_id=domain_id, wappalyzer_technology=wappalyzer_technology, wappalyzer_version=wappalyzer_version_no, wappalyzer_cve=wappalyzer_cve).first()

    if dbWappalyzerVersion is None:
        newWappalyzerVersion = WappalyzerVersion(domain_id=domain_id, wappalyzer_technology=wappalyzer_technology, wappalyzer_version=wappalyzer_version_no, wappalyzer_cve=wappalyzer_cve)
        db.session.add(newWappalyzerVersion)
        db.session.commit()
        dbWappalyzerVersion = newWappalyzerVersion

    return dbWappalyzerVersion

def saveEndpointsEnumeration(domain_id, endpoints_enumeration):

    dbEndpointsEnumeration = EndpointsEnumeration.query.filter_by(domain_id=domain_id, endpoints_enumeration_name=endpoints_enumeration).first()

    if dbEndpointsEnumeration is None:
        newEndpointsEnumeration = EndpointsEnumeration(domain_id=domain_id, endpoints_enumeration_name=endpoints_enumeration)
        db.session.add(newEndpointsEnumeration)
        db.session.commit()
        dbEndpointsEnumeration = newEndpointsEnumeration

    return dbEndpointsEnumeration



   