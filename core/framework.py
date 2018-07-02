import argparse
import imp
import os
import re
import sys
import pkg_resources

from threading import RLock, Thread
from keyeventthread import KeyEventThread
from os.path import expanduser

# import our libs
from utils import Utils, Display
from keystore import KeyStore as kb
from events import EventHandler

class Framework():
    def __init__(self):
        self.display = Display()
        self.modulelock = RLock()

        self.inputModules = {}
        self.actionModules = {}
        self.reportModules = {}

        self.progName = "FullAutoOSINT"
        self.version = "None"

        if Utils.isReadable('VERSION'):
            version_pattern = "'(\d+\.\d+\.\d+[^']*)'"
            self.version = re.search(version_pattern, open('VERSION').read()).group(1)

        self.isRunning = True  # Conditional to check if user wants to quit

        self.inputs = {}

        self.config = {}

        self.config["homeDir"] = expanduser("~")
        self.config["outDir"] = self.config["homeDir"] + "/.FullAutoOSINT/"
        self.config["reportDir"] = ""
        self.config["logDir"] = ""
        self.config["proofsDir"] = ""
        self.config["tmpDir"] = ""
        self.config["pkgDir"] = os.path.dirname(os.path.dirname(os.path.abspath(__file__))) + "/"
        self.config["miscDir"] = ""
        self.config['lhost'] = Utils.getIP()

        self.setupDirs()

        # initialize some config options
        self.config["config_filename"] = ""

        # default all bool values to False
        self.config["verbose"] = False
        self.config["always_yes"] = False
        self.config["list_modules"] = False

        self.config["scan_depth"] = 5
        self.config["exclude_types"] = ""

        # make temp file for the KB save file
        self.kbSaveFile = self.config["proofsDir"] + "KB-" + Utils.getRandStr(10) + ".save"

        self.threadcount_thread = None
        self.keyevent_thread = None

        self.allFinished = False

    # ==================================================
    # SUPPORT METHODS
    # ==================================================

    # ----------------------------
    # Setup Directories
    # ----------------------------
    def setupDirs(self):
        # make directories
        if not os.path.isdir(self.config["outDir"]):
            os.makedirs(self.config["outDir"])

        if not os.path.isdir(self.config["outDir"] + "reports/"):
            os.makedirs(self.config["outDir"] + "reports/")
        self.config["reportDir"] = self.config["outDir"] + "reports/"

        if not os.path.isdir(self.config["outDir"] + "logs/"):
            os.makedirs(self.config["outDir"] + "logs/")
        self.config["logDir"] = self.config["outDir"] + "logs/"
        self.display.setLogPath(self.config["logDir"])

        if not os.path.isdir(self.config["outDir"] + "proofs/"):
            os.makedirs(self.config["outDir"] + "proofs/")
        self.config["proofsDir"] = self.config["outDir"] + "proofs/"

        if not os.path.isdir(self.config["outDir"] + "tmp/"):
            os.makedirs(self.config["outDir"] + "tmp/")
        self.config["tmpDir"] = self.config["outDir"] + "tmp/"

        if not os.path.isdir(self.config["pkgDir"] + "misc/"):
            os.makedirs(self.config["pkgDir"] + "misc/")
        self.config["miscDir"] = self.config["pkgDir"] + "misc/"

    # ----------------------------
    # CTRL-C display and exit
    # ----------------------------
    def ctrlc(self):
        self.display.alert("Ctrl-C caught!!!")

        self.cleanup()

    # ----------------------------
    # Close everything down nicely
    # ----------------------------
    def cleanup(self):
        #kill key press thread if it has been set up
        if self.keyevent_thread:
            self.keyevent_thread.stop()

        # kill thread count thread
        EventHandler.kill_thread_count_thread()

        # fix prompt
        os.system("stty echo")

        # exit
        sys.exit(0)

    # ----------------------------
    # Display the Banner
    # ----------------------------
    def displayBanner(self):
        self.display.output()
        self.display.output("FullAutoOSINT")
        self.display.output()

        self.display.output("An Automated OSINT Tool")
        self.display.output("Written by: Adam Compton")
        self.display.output("Verion: %s" % self.version)

    # ----------------------------
    # Parse CommandLine Parms
    # ----------------------------
    def parseParameters(self, argv):
        parser = argparse.ArgumentParser()

        # ==================================================
        # Input Files
        # ==================================================
        filesgroup = parser.add_argument_group('inputs')
        filesgroup.add_argument("-C",
                                metavar="<config.txt>",
                                dest="config_file",
                                action='store',
                                help="config file")
        filesgroup.add_argument("-f",
                                metavar="<input file>",
                                dest="inputs",
                                default=[],
                                action='store',
                                help="one of more input files seperated by spaces",
                                nargs='*')

        # ==================================================
        # Advanced Flags
        # ==================================================
        advgroup = parser.add_argument_group('advanced')
        advgroup.add_argument("--ip",
                              metavar="<local IP>",
                              dest="lhost",
                              default=Utils.getIP(),
                              action='store',
                              help="defaults to %s" % Utils.getIP())

        # ==================================================
        # Optional Args
        # ==================================================
        parser.add_argument("-v", "--verbosity",
                            dest="verbose",
                            action='count',
                            help="increase output verbosity")
        parser.add_argument("-s", "--scandepth",
                            dest="scan_depth",
                            action='store',
                            default=5,
                            help="set imax number of iterations of OSINT to perform. Default is 5.  Anything beyond 10 may result in issues.")
        parser.add_argument("-x", "--exclude",
                            dest="exclude_types",
                            action="store",
                            default="",
                            help="specify a comma seperatec list of module types to exclude from running")
        # ==================================================
        # Misc Flags
        # ==================================================
        miscgroup = parser.add_argument_group('misc')
        miscgroup.add_argument("--listmodules",
                               dest="list_modules",
                               action='store_true',
                               help="list out all current modules and exit")

        # parse args
        args = parser.parse_args()

        # convert parameters to values in the config dict
        self.config["config_filename"] = args.config_file
        self.config["verbose"] = args.verbose
        self.config["list_modules"] = args.list_modules
        self.config["scan_depth"] = int(args.scan_depth)
        self.config["exclude_types"] = args.exclude_types
        self.config['lhost'] = args.lhost
        for f in args.inputs:
            if (Utils.isReadable(f)):
                type = self.idFileType(f)
                if (type):
                    if type in self.inputs:
                        self.inputs[type].append(f)
                    else:
                        self.inputs[type] = [f]
            else:
                print "Can not access [" + f + "]"

    # ----------------------------
    # Load config setting from the config file
    # ----------------------------
    def loadConfig(self):
        # does config file exist?
        if (("config_filename" in self.config) and (self.config["config_filename"] is not None)):
            temp1 = self.config
            temp2 = Utils.loadConfig(self.config["config_filename"])
            self.config = dict(temp2.items() + temp1.items())
        else:
            # guess not..   so try to load the default one
            if Utils.isReadable(self.config["miscDir"] + "default.cfg"):
                self.display.verbose("a CONFIG FILE was not specified...  defaulting to [default.cfg]")
                temp1 = self.config
                temp2 = Utils.loadConfig(self.config["miscDir"] + "default.cfg")
                self.config = dict(temp2.items() + temp1.items())
            else:
                # someone must have removed it!
                self.display.error("a CONFIG FILE was not specified...")
                self.cleanup()

        # set verbosity/debug level
        if ("verbose" in self.config):
            if (self.config['verbose'] >= 1):
                self.display.enableVerbose()
            if (self.config['verbose'] > 1):
                self.display.enableDebug()

        if ((self.config["lhost"] == None) or (self.config["lhost"] == "")):
            self.display.error("No IP was able to be determined and one was not provided.")
            self.display.error("Please specify one via the [--ip <ip>] argument.")
            self.cleanup()

    # ----------------------------
    # Load Initial Events
    # ----------------------------
    def populateInitEvents(self):
        EventHandler.fire("always:initial")

    # ----------------------------
    # look for and load and modules (input/action)
    # ----------------------------
    def loadModules(self):
        module_dict = {}
        # crawl the module directory and build the module tree
        # process inputs
        path = os.path.join(self.config["pkgDir"], 'modules/input')
        for dirpath, dirnames, filenames in os.walk(path):
            # remove hidden files and directories
            filenames = [f for f in filenames if not f[0] == '.']
            dirnames[:] = [d for d in dirnames if not d[0] == '.']
            if len(filenames) > 0:
                for filename in [f for f in filenames if (f.endswith('.py') and not f == "__init__.py")]:
                    module = self.loadModule("input", dirpath, filename)
                    if module is not None:
                        module_dict[module['name'].rstrip(" ")] = module
        # process actions
        path = os.path.join(self.config["pkgDir"], 'modules/action')
        for dirpath, dirnames, filenames in os.walk(path):
            # remove hidden files and directories
            filenames = [f for f in filenames if not f[0] == '.']
            dirnames[:] = [d for d in dirnames if not d[0] == '.']
            if len(filenames) > 0:
                for filename in [f for f in filenames if (f.endswith('.py') and not f == "__init__.py")]:
                    module = self.loadModule("action", dirpath, filename)
                    if module is not None:
                        module_dict[module['name'].rstrip(" ")] = module

        # process reports
        path = os.path.join(self.config["pkgDir"], 'modules/report')
        for dirpath, dirnames, filenames in os.walk(path):
            # remove hidden files and directories
            filenames = [f for f in filenames if not f[0] == '.']
            dirnames[:] = [d for d in dirnames if not d[0] == '.']
            if len(filenames) > 0:
                for filename in [f for f in filenames if (f.endswith('.py') and not f == "__init__.py")]:
                    module = self.loadModule("report", dirpath, filename)
                    if module is not None:
                        module_dict[module['name'].rstrip(" ")] = module

        return module_dict

    # ----------------------------
    # check to see if the module is of an exclude module type
    # ----------------------------
    def checkExcludeTypes(self, types):
        for t in types:
            for T in self.config["exclude_types"].split(','):
                if t == T:
                    return True
        return False

    # ----------------------------
    # load each module
    # ----------------------------
    def loadModule(self, type, dirpath, filename):
        module_dict = {}

        # remove the beginning string of the dirpath
        basepath = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        dirpath_orig = dirpath
        dirpath = dirpath[len(basepath)+1:]

        mod_name = filename.split('.')[0]
        mod_dispname = '/'.join(re.split('/modules/' + type + "/", dirpath)[-1].split('/') + [mod_name])
        mod_loadname = mod_dispname.replace('/', '_')
        mod_loadpath = os.path.join(dirpath_orig, filename)
        mod_file = open(mod_loadpath)
        try:
            # import the module into memory
            imp.load_source(mod_loadname, mod_loadpath, mod_file)
            # find the module and make an instace of it
            _module = __import__(mod_loadname)
            _class = getattr(_module, mod_name)
            _instance = _class(self.config, self.display, self.modulelock)

            reasons = []

            valid = True
            for r in _instance.getRequirements():
                if r == 'disable':
                    reasons.append("Module Manually Disabled !!!")
                elif r == 'APIKEY':
                    key_name = mod_name + "_apikey"
                    if not key_name in self.config:
                        reasons.append("API key is missing")
                        valid = False
                elif not r in self.config:
                    path = Utils.validateExecutable(r)
                    if path:
                        self.config[r] = path
                    else:
                        reasons.append("Requirement not met: %s" % r)
                        valid = False
            if valid:
                module_dict = {'name': mod_name.ljust(25),
                               'description': _instance.getTitle().ljust(40),
                               'type': type.ljust(6),
                               'valid': True}
            else:
                module_dict = {'name': mod_name.ljust(25),
                               'description': _instance.getTitle().ljust(40),
                               'type': type.ljust(6),
                               'valid': False}

            # add the module to the framework's loaded modules
            if valid:
                if type == "action":
                    if self.checkExcludeTypes(_instance.getTypes()) == True:
                        True
                    else:
                        self.actionModules[mod_dispname] = _instance
                        for t in _instance.getTriggers():
                            EventHandler.add(_instance, t)
                elif type == "input":
                    self.inputModules[mod_dispname] = _instance
                elif type == "report":
                    self.reportModules[mod_dispname] = _instance

            if reasons:
                self.display.error('Module \'%s\' disabled:' % mod_name)
            for r in reasons:
                self.display.error('     ' + r)

        except ImportError as e:
            # notify the user of missing dependencies
            self.display.error('Module \'%s\' disabled. Dependency required: \'%s\'' % (mod_name, e))
            return None
        except Exception as e:
            # notify the user of errors
            print e
            self.display.error('Module \'%s\' disabled.' % (mod_name))
            return None
        return module_dict

    # ----------------------------
    # Attempt to identify the type of input file
    # ----------------------------
    def idFileType(self, filename):
        # load and read first 4096 bytes of file
        file = open(filename, 'rb')
        data = file.read(4086)

        # get first line of of the 4096 bytes
        firstline = data.split('\n', 1)[0]

        # check firstline
        if (firstline.find("<NeXposeSimpleXML") != -1):
            return "nexpose_simple"
        elif (firstline.find("<NexposeReport") != -1):
            return "nexpose"
        elif (firstline.find("<NessusClientData>") != -1):
            return "nessus"
        elif (firstline.find("<?xml") != -1):
            # it's xml, check for root tags we can handle
            for line in data.split('\n'):
                parts = re.findall("<([a-zA-Z0-9\-\_]+)[ >]", line)
                for part in parts:
                    if part == "nmaprun":
                        return "nmap"
        else:
            return "dict"

    def modulesLoaded(self):
        """Print Loaded Module Stats"""
        self.display.output("Input Modules Loaded:\t%i" % len(self.inputModules))
        self.display.output("Action Modules Loaded:\t%i" % len(self.actionModules))
        self.display.output("Report Modules Loaded:\t%i" % len(self.reportModules))

    def additionalInfo(self):
        """Print Additional Information such as knowledge base path and current IP address"""
        self.display.output()
        self.display.alert("The KnowledgeBase will be auto saved to : %s" % self.kbSaveFile)
        self.display.alert("Local IP is set to : %s" % self.config['lhost'])
        self.display.alert(
            "      If you would rather use a different IP, then specify it via the [--ip <ip>] argument.")


    # ----------------------------
    # Begin a Scan
    # ----------------------------
    def runScan(self):
        # begin main loop
        self.keyevent_thread = KeyEventThread(self.display)
        self.keyevent_thread.start()

        while not EventHandler.finished() or not self.allFinished:
            if (EventHandler.finished() and not self.allFinished):
                EventHandler.fire("allFinished")
                self.allFinished = True
            if not self.keyevent_thread.isPaused():
                EventHandler.processNext(self.display, int(self.config['max_modulethreads']))
        #scan is done, stop checking for keypresses in case we go back to the menu
        self.keyevent_thread.stop()

    # ==========================================================================================
    # ==========================================================================================
    # ==========================================================================================

    # ----------------------------
    # Primary METHOD
    # ----------------------------

    def run(self, argv):
        self.parseParameters(argv)
        self.displayBanner() #Print banner first and all messages after
        self.loadConfig() # load config
        modules_dict = self.loadModules() # load input/action modules
        self.modulesLoaded()

        if self.config["list_modules"]:
            self.display.printModuleList(modules_dict)
            sys.exit()

        self.additionalInfo()

        # parse inputs
        for input in self.inputs.keys():
            for inputmodule in self.inputModules.keys():
                _instance = self.inputModules[inputmodule]
                if _instance.getType() == input:
                    for file in self.inputs[input]:
                        self.display.verbose("Loading [%s] with [%s]" % (file, inputmodule))
                        _instance.go(file)

        # populate any initial events
        self.populateInitEvents()

        # begin menu loop
        self.threadcount_thread = Thread(target=EventHandler.print_thread_count, args=(self.display,))
        self.threadcount_thread.start()
        self.runScan()  # Skip first trip through menu and go straight into a scan using whatever arguments were passed

        if (kb):
            kb.save(self.kbSaveFile)

        # generate reports
        self.display.output("Generating Reports")
        for reportmodule in self.reportModules.keys():
            _instance = self.reportModules[reportmodule]
            _instance.process()

        self.display.output()
        self.display.output("Good Bye!")
        self.cleanup()
