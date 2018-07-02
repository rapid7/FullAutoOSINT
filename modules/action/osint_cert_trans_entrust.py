from core.actionModule import actionModule
from core.keystore import KeyStore as kb
from core.utils import Utils
import re
import requests


class osint_cert_trans_entrust(actionModule):
    def __init__(self, config, display, lock):
        super(osint_cert_trans_entrust, self).__init__(config, display, lock)
        self.title = "Certificate Tansparency - Entrust"
        self.shortName = "CertTransEntrust"
        self.description = ""

        self.requirements = []
        self.triggers = ["newDNSDomain"]
        self.types = ["OSINT", "SUBDOMAIN"]

    def getTargets(self):
        self.targets = kb.get('osint/dnsdomain/')


    def search(self, domain):
        base_url = "https://ctsearch.entrust.com/api/v1/certificates?domain={}&fields=subjectDN"
        url = base_url.format(domain)

        ua = 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1'
        req = requests.get(url, headers={'User-Agent': ua})

        if req.ok:
            try:
                content = req.content.decode('utf-8')
                pattern = r'cn\\u003d([^,]+),'
                regex = re.compile(pattern, re.IGNORECASE)
                data = []
                for match in regex.finditer(content):
                    x = Utils.cleanString(match.group(1), '"} ')
                    data.append(x)
                return list(set(data))
            except Exception as err:
                print("Error retrieving information.")
                print err
        return []

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

                # make outfile
                temp_file = self.config["proofsDir"] + self.shortName + "_" + t + "_" + Utils.getRandStr(10)

                # perform web stie request and parsing
                result = self.search(t)
                for line in result:
                    kb.add("osint/dnsdomain/host/t")
                    self.fire("newHost")

                text = ', '.join(result)
                Utils.writeFile(text, temp_file)


        return
