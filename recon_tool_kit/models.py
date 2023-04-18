from recon_tool_kit import app,db

class Domain(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    domain_name = db.Column(db.String(255), unique=True, nullable=False)
    email = db.Column(db.String(255), unique=False, nullable=True)
    whois = db.relationship('Whois', back_populates='domain')
    subdomains = db.relationship('Subdomain', back_populates='domain')
    active_subs = db.relationship('ActiveSubdomain', back_populates='domain')
    subdomain_takeover = db.relationship('SubdomainTakeover', back_populates='domain')
    zone_transfer = db.relationship('ZoneTransfer', back_populates='domain')
    dns_records = db.relationship('DNSRecords', back_populates='domain')
    txt_records = db.relationship('TXTRecords', back_populates='domain')
    # cname_info = db.relationship('CNAME Info', back_populates='domain')
    mail_servers = db.relationship('MailServers', back_populates='domain')
    email_auth = db.relationship('EmailAuthentication', back_populates='domain')
    waf = db.relationship('WAF', back_populates='domain')
    ipv4 = db.relationship('IPv4', back_populates='domain')
    ipv6 = db.relationship('IPv6', back_populates='domain')
    # port_scan = db.relationship('PortScan', back_populates='domain')
    common_backups = db.relationship('CommonBackups', back_populates='domain')
    find_secrets = db.relationship('FindSecrets', back_populates='domain')
    cloudgit_enumeration = db.relationship('CloudgitEnumeration', back_populates='domain')
    wappalyzer_version = db.relationship('WappalyzerVersion', back_populates='domain')
    endpoints_enumeration = db.relationship('EndpointsEnumeration', back_populates='domain')

def __init__(self, domain_name):
    self.domain_name = domain_name

class Whois(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    domain_id = db.Column(db.Integer, db.ForeignKey('domain.id'))
    whois_info = db.Column(db.String(255))
    domain = db.relationship('Domain', back_populates='whois')

def __init__(self, whois_info):
    self.whois_info = whois_info

class Subdomain(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    domain_id = db.Column(db.Integer, db.ForeignKey('domain.id'))
    subdomain_name = db.Column(db.String(255))
    domain = db.relationship('Domain', back_populates='subdomains')
    
def __init__(self, subdomain_name):
    self.subdomain_name = subdomain_name

class ActiveSubdomain(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    domain_id = db.Column(db.Integer, db.ForeignKey('domain.id'))
    active_subdomain_name = db.Column(db.String(255))
    domain = db.relationship('Domain', back_populates='active_subs')

def __init__(self, active_subdomain_name):
    self.active_subdomain_name = active_subdomain_name

class SubdomainTakeover(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    domain_id = db.Column(db.Integer, db.ForeignKey('domain.id'))
    subdomain_takeover_name = db.Column(db.String(255))
    domain = db.relationship('Domain', back_populates='subdomain_takeover')

def __init__(self, subdomain_takeover_name):
    self.subdomain_takeover_name = subdomain_takeover_name

class ZoneTransfer(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    domain_id = db.Column(db.Integer, db.ForeignKey('domain.id'))
    zone_transfer_name = db.Column(db.String(255))
    domain = db.relationship('Domain', back_populates='zone_transfer')

def __init__(self, zone_transfer_name):
    self.zone_transfer_name = zone_transfer_name

class DNSRecords(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    domain_id = db.Column(db.Integer, db.ForeignKey('domain.id'))
    dns_record_name = db.Column(db.String(255))
    domain = db.relationship('Domain', back_populates='dns_records')

def __init__(self, dns_record_name):
    self.dns_record_name = dns_record_name

class TXTRecords(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    domain_id = db.Column(db.Integer, db.ForeignKey('domain.id'))
    txt_record_name = db.Column(db.String(255))
    domain = db.relationship('Domain', back_populates='txt_records')

def __init__(self, txt_record_name):
    self.txt_record_name = txt_record_name

class MailServers(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    domain_id = db.Column(db.Integer, db.ForeignKey('domain.id'))
    mail_server_name = db.Column(db.String(255))
    domain = db.relationship('Domain', back_populates='mail_servers')

def __init__(self, mail_server_name):
    self.mail_server_name = mail_server_name

class EmailAuthentication(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    domain_id = db.Column(db.Integer, db.ForeignKey('domain.id'))
    email_authentication_name = db.Column(db.String(255))
    domain = db.relationship('Domain', back_populates='email_auth')

def __init__(self, email_authentication_name):
    self.email_authentication_name = email_authentication_name

class WAF(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    domain_id = db.Column(db.Integer, db.ForeignKey('domain.id'))
    waf_name = db.Column(db.String(255))
    domain = db.relationship('Domain', back_populates='waf')

def __init__(self, waf_name):
    self.waf_name = waf_name

class IPv4(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    domain_id = db.Column(db.Integer, db.ForeignKey('domain.id'))
    ipv4_name = db.Column(db.String(255))
    domain = db.relationship('Domain', back_populates='ipv4')

def __init__(self, ipv4_name):
    self.ipv4_name = ipv4_name

class IPv6(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    domain_id = db.Column(db.Integer, db.ForeignKey('domain.id'))
    ipv6_name = db.Column(db.String(255))
    domain = db.relationship('Domain', back_populates='ipv6')

def __init__(self, ipv6_name):
    self.ipv6_name = ipv6_name

# class PortScan(db.Model):
#     id = db.Column(db.Integer, primary_key=True, autoincrement=True)
#     domain_id = db.Column(db.Integer, db.ForeignKey('domain.id'))
#     ipv4_address = db.Column(db.String(255))
#     port = db.Column(db.String(255))
#     state = db.Column(db.String(255))
#     service = db.Column(db.String(255))
#     version = db.Column(db.String(255))
#     product = db.Column(db.String(255))
#     cve = db.Column(db.String(255))
#     domain = db.relationship('Domain', back_populates='port_scan')

# def __init__(self, ipv4_address, port, state, service, version, product, cve):
#     self.ipv4_address = ipv4_address
#     self.port = port
#     self.state = state
#     self.service = service
#     self.version = version
#     self.product = product
#     self.cve = cve


class CommonBackups(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    domain_id = db.Column(db.Integer, db.ForeignKey('domain.id'))
    common_backups_name = db.Column(db.String(255))
    domain = db.relationship('Domain', back_populates='common_backups')

def __init__(self, common_backups_name):
    self.common_backups_name = common_backups_name

class FindSecrets(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    domain_id = db.Column(db.Integer, db.ForeignKey('domain.id'))
    find_secrets_name = db.Column(db.String(255))
    domain = db.relationship('Domain', back_populates='find_secrets')

def __init__(self, find_secrets_name):
    self.find_secrets_name = find_secrets_name

class CloudgitEnumeration(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    domain_id = db.Column(db.Integer, db.ForeignKey('domain.id'))
    cloudgit_enumeration_name = db.Column(db.String(255))
    domain = db.relationship('Domain', back_populates='cloudgit_enumeration')

def __init__(self, cloudgit_enumeration_name):
    self.cloudgit_enumeration_name = cloudgit_enumeration_name

class WappalyzerVersion(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    domain_id = db.Column(db.Integer, db.ForeignKey('domain.id'))
    wappalyzer_technology = db.Column(db.String(255))
    wappalyzer_version = db.Column(db.String(255))
    wappalyzer_cve = db.Column(db.String(255))
    domain = db.relationship('Domain', back_populates='wappalyzer_version')

def __init__(self, wappalyzer_technology, wappalyzer_version, wappalyzer_cve):
    self.wappalyzer_technology = wappalyzer_technology
    self.wappalyzer_version = wappalyzer_version
    self.wappalyzer_cve = wappalyzer_cve

class EndpointsEnumeration(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    domain_id = db.Column(db.Integer, db.ForeignKey('domain.id'))
    endpoints_enumeration_name = db.Column(db.String(255))
    domain = db.relationship('Domain', back_populates='endpoints_enumeration')

def __init__(self, endpoints_enumeration_name):
    self.endpoints_enumeration_name = endpoints_enumeration_name

with app.app_context():
    db.create_all()

