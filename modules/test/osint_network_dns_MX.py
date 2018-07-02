from core.actionModule import actionModule
from core.keystore import KeyStore as kb
from core.utils import Utils
import dns.resolver

class scan_network_dns(actionModule):
    def __init__(self, config, display, lock):
        super(scan_network_dns, self).__init__(config, display, lock)
        self.title = ""
        self.shortName = "DNSDomainLookup"
        self.description = ""

        self.requirements = [""]
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

                # make outfile
                temp_file = self.config["proofsDir"] + self.shortName + "_" + t + "_" + user + "_" + Utils.getRandStr(10)

                # run external command
                command = self.config[""]
                result = Utils.execWait(command, None)

                # if process outputs to screen
                for line in result:
                    kb.add("osint/")
                    self.fire("")

                # if process outputs to file
                if Utils.isReadable(temp_file):
                    with open (temp_file, "r") as myfile:
                        result=myfile.readlines()

                    for line in result:
                        kb.add("osint/")
                        self.fire("")

        return
