import socket

from core.osintModule import osintModule
from core.keystore import KeyStore as kb


class osint_getipaddress(osintModule):
    def __init__(self, config, display, lock):
        super(osint_getipaddress, self).__init__(config, display, lock)
        self.title = "Determine the IP for each hostname"
        self.shortName = "GetIP"
        self.description = "execute [gethostbyname(hostname)] on each target"

        self.requirements = []
        self.triggers = ["newhostname"]

    def getTargets(self):
        #get all hosts
        self.targets = kb.get('osint/dnsdomain/subdomain/')

    def process(self):
        # load any targets we are interested in
        self.getTargets()

        # loop over each target
        for t in self.targets:
            # verify we have not tested this host before
            if not self.seentarget(t):
                # add the new IP to the already seen list
                self.addseentarget(t)
                self.display.verbose(self.shortName + " - Connecting to " + t)
                try:
                    results = socket.gethostbyname(t)
                    self.fire("newHostname")
                    kb.add('host/' + t + '/hostname/' + results[0])
                except:
                    pass

        return
