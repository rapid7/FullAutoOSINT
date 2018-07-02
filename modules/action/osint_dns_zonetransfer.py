from core.osintModule import osintModule
from core.keystore import KeyStore as kb
from core.utils import Utils
from core.mydns import MyDNS
import re

class osint_dns_zonetransfer(osintModule):
    def __init__(self, config, display, lock):
        super(osint_dns_zonetransfer, self).__init__(config, display, lock)
        self.title = "DNS Zone Transfer"
        self.shortName = "DNSXfer"
        self.description = "Checking for DNS zone transfers on DNS domains"

        self.requirements = []
        self.triggers = ["newDNSDomain"]
        self.types = ["OSINT", "DNS"]

    def getTargets(self):
        self.targets = kb.get('osint/dnsdomain/')

    def fixStr(self, text):
        if isinstance(text, str):
            text = text.lower()
        elif isinstance(text, unicode):
            text = text.encode('utf-8')
            text = text.lower()
        return text

    def processZoneLine(self, text, domain):
        lines = text.splitlines()
        for line in lines:
            line = self.fixStr(line)
            result = re.match("(\S+?)\s+?(\d+?)\s+?(in)\s+?(\S+?)\s+(.*)", line.strip())
            if result:
                host = self.fixStr(result.group(1))
                ttl = self.fixStr(result.group(2))
                record_class = self.fixStr(result.group(3))
                record_type = self.fixStr(result.group(4))
                record_data = self.fixStr(result.group(5))
    
                if host == "@":
                    host = domain
    
                if record_type == "a":
                    host = host[:host.find(domain) + len(domain)]
                    kb.add('osint/dnsdomain/' + domain + '/A/' + host + "/" + record_data) 
                    self.fire("newDNSARecord")
                elif record_type == "ns":
                    temp = record_data[:-1]
                    temp = temp[:host.find(domain) + len(domain)]
                    kb.add('osint/dnsdomain/' + domain + '/NS/' + temp) 
                    self.fire("newDNSNSRecord")
                #elif record_type == "txt":
                #    print line
                #elif record_type == "mx":
                #    print line
                elif record_type == "cname":
                    host = host[:host.find(domain) + len(domain)]
                    kb.add('osint/dnsdomain/' + domain + '/CNAME/' + host + "/" + record_data[:-1]) 
                    self.fire("newDNSCNAMERecord")
                elif record_type == "ptr":
                    if "in-addr.arpa" in host:
                        record_data = record_data[:host.find(domain) + len(domain)]
                        kb.add('osint/dnsdomain/' + domain + '/PTR/' + host + "/" + record_data) 
                        self.fire("newDNSPTRRecord")

                        host = host.replace("in-addr.arpa", "")
                        parts = host.split('.')
                        host = parts[3] + "." + parts[2] + "." + parts[1] + "." + parts[0]
                        kb.add('osint/dnsdomain/' + domain + '/A/' + host + "/" + record_data) 
                        self.fire("newDNSARecord")
                #else:
                #    print record_type
                    #print line.strip()

    def process(self):
        # load any targets we are interested in
        self.getTargets()

        # loop over each target
        for t in self.targets:
            # verify we have not tested this host before
            if not self.seentarget(t):
                # add the new target to the already seen list
                self.addseentarget(t)

                self.display.verbose(self.shortName + " - Targetting " + t)

                # Find NS records
                ns_list = kb.get('osint/dnsdomain/' + t + '/NS/')
                ns_list2 = MyDNS.getRecord(t, "NS")
                for n in ns_list2:
                    n = str(n)[:-1]
                    ns_list.append(n)

                for ns in ns_list:
                    try:
                        xfr = MyDNS.getZoneXfr(ns, t)
                        text = ""
		        for k in xfr:
                            text += xfr[k].to_text(k) + "\n"
                            self.processZoneLine(xfr[k].to_text(k), t)

                        if text:
                            # make outfile
                            outfile = self.config["proofsDir"] + self.shortName + "_" + t + "_" + ns + "_" + Utils.getRandStr(10)
		    
                            # output to file
                            Utils.writeFile(text, outfile)
                            self.fire("newDNSZoneXfr")
                    except Exception as e:
                        print e


        return
