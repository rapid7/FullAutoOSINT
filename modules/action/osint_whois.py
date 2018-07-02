from core.osintModule import osintModule
from core.keystore import KeyStore as kb
from core.utils import Utils
import re
import whois
import json

class osint_whois(osintModule):
    def __init__(self, config, display, lock):
        super(osint_whois, self).__init__(config, display, lock)
        self.title = "Domain Whois Lookup"
        self.shortName = "Whois"
        self.description = "Lookup the Whois records for a domain"

        self.requirements = []
        self.triggers = ["newDNSDomain"]
        self.types = ["OSINT", "DNS"]

    def getTargets(self):
        self.targets = kb.get('osint/dnsdomain/')

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

                # call whois on the target domain
                w = whois.whois(t)
                data = dict(w)

                # standardize on dateformat
                for k in ('creation_date', 'expiration_date', 'updated_date'):
                    if k in data:
                        date = data[k][0] if isinstance(data[k], list) else data[k]
                        if data[k]:
                            data[k] = date.strftime('%m/%d/%Y')

                # identify useful items within the whois results and store them in in the KB
                for k in data:
                    if data[k]:
                        if "_email" in k:
                            print k
                            print data[k]
                            kb.add('osint/email/' + datum)
                            self.fire("newEmailAddress")
#                        elif "_name" in k:
#                            kb.add('osint/name/' + datum)
#                            self.fire("newName")


                # make outfile
                outfile = self.config["proofsDir"] + self.shortName + "_" + t + "_" + Utils.getRandStr(10)
		    
                # output to file
                Utils.writeFile(json.dumps(data, indent=4), outfile)
#                    self.fire("newDNSZoneXfr")

        return
