import dns.resolver
import dns.zone
import dns.name
import dns.reversename
import sys

class MyDNS():
    @staticmethod
    def getRecord(search_term, rec_type):
        try:
            result = dns.resolver.query(search_term, rec_type)
            return result
        except Exception as e:
	    return []

    @staticmethod
    def getAllRecords(domain):
        rec_types = [
            'A', 'A6', 'AAAA', 'AFSDB', 'ANY', 'APL', 'AXFR', 'CAA', 'CDNSKEY', 'CDS', 'CERT', 'CNAME', 'CSYNC', 'DHCID', 'DLV', 'DNAME', 'DNSKEY', 'DS', 'EUI48', 'EUI64', 'GPOS', 'HINFO', 'HIP', 'IPSECKEY', 'ISDN', 'IXFR', 'KEY', 'KX', 'LOC', 'MAILA', 'MAILB', 'MB', 'MD', 'MF', 'MG', 'MINFO', 'MR', 'MX', 'NAPTR', 'NONE', 'NS', 'NSAP', 'NSAP-PTR', 'NSEC', 'NSEC3', 'NSEC3PARAM', 'NULL', 'NXT', 'OPT', 'PTR', 'PX', 'RP', 'RRSIG', 'RT', 'SIG', 'SOA', 'SPF', 'SRV', 'SSHFP', 'TA', 'TKEY', 'TLSA', 'TSIG', 'TXT', 'UNSPEC', 'URI', 'WKS', 'X25',
        ]

        dns_records = dict()
        for rec_type in rec_types:
            try:
                answers = MyDNS.getRecord(domain, rec_type)
                data = []
                for rdata in answers:
                    data.append(rdata.to_text())
                if data:
                    dns_records[rec_type] = data
            except Exception as e:
                pass

        return dns_records

    @staticmethod
    def getZoneXfr(srv, domain):
        return dns.zone.from_xfr(dns.query.xfr(srv, domain))

    @staticmethod
    def isSubDomain(a, b):
        a = dns.name.from_text(a)
        b = dns.name.from_text(b)
        return a.is_subdomain(b)

    @staticmethod
    def isSuperDomain(a, b):
        a = dns.name.from_text(a)
        b = dns.name.from_text(b)
        return a.is_superdomain(b)

    @staticmethod
    def getHostname(ip):
        print ip
        return dns.reversename.from_address(ip)

if __name__ == '__main__':
    domain = sys.argv[1]
    #recs = MyDNS.getAllRecords(domain)
    #for k in recs:
    #    print "-----------------------------"
    #    print k
    #    print recs[k]

    #if "NS" in recs:
    #    print "ZXFR"
    #    xfr = MyDNS.getZoneXfr(recs["NS"][0], domain)
    #    for k in xfr:
    #        print xfr[k].to_text(k)

    ns = MyDNS.getRecord(domain, "NS")
    for n in ns:
        print n
    #print "is Sub"
    #isSubDomain(a, b)
    #print "is Super"
    #isSuperDomain(a, b)
    #if "A" in recs:
    #    print "Hostname"
    #    print MyDNS.getHostname(recs["A"][0])
