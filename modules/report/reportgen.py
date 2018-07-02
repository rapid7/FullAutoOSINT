try:
    from yattag import Doc
except ImportError:
    raise ImportError('Missing Yattag, if you would like to enable report generation do: pip install yattag')
import datetime
from core.reportModule import reportModule
from core.keystore import KeyStore as kb
from core.utils import Utils

#  Overview of KB structure for reporting
#  1. host
#     1. IP
#         1. files (Files from tools run against this IP, not necessarily finding a vuln)
#             1. filepath 
#         2. tcpport
#             1. port number
#         3. udpport
#             1. port number
#         4. vuln
#             1. name
#                 1. message (Specific line in output confirming vuln)
#                 2. module (What module found this vuln)
#                 3. output (Files relating to this specific vuln)
#                    1. file path
#                 4. port (Port running the vulnerable service)
#                 5. vector (Path from nmap to module)
#                 6. etc... 
#                    1. (try not to go deeper than this so I don't need recursive searching)
#  2. service
#     1. service name
#         1. hosts
#  3. domain
#     1. domain name


class reportgen(reportModule):
    def __init__(self, config, display, lock):
        super(reportgen, self).__init__(config, display, lock)
        self.title = "Generate HTML Report"
        self.shortName = "reportGenHTML"
        self.description = "Gather information and generate HTML report"

        self.requirements = []

    def getTargets(self):
        # we are interested in all hosts
        self.targets = kb.get('host')

    def processTarget(self, t, port):
        # do nothing
        return

    def process(self):
        self.display.verbose(self.shortName + " - Writing report")
        doc, tag, text = Doc().tagtext()
        self.getTargets()
        # TODO: Put report in folder, copy CSS and maybe JS files (if we want to make the report fancy)
        outfile = self.config["reportDir"] + self.shortName + "_" + Utils.getRandStr(10) + ".html"
        Utils.writeFile(doc.getvalue(), outfile)
        self.display.alert("Report file located at %s" % outfile)

        return
