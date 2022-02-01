# from functools import cache
# from importlib.metadata import distribution
import logging.handlers
import os
import json
import urllib3
import xml.etree.ElementTree as ET
from autopkglib import Processor, ProcessorError, URLGetter

APPNAME = "APM"
LOGLEVEL = logging.DEBUG

__all__ = [APPNAME]


class PST:
    pstID = ""
    distMethod = ""
    delay = 0
    jamfUrl = ""
    postHeader = ""
    getHeader = ""

    def __init__(self, EnvObject):
        print("in pst init")
        self.EnvObject = EnvObject
        self.jamfUrl = self.EnvObject.env.get("JSS_URL")
        self.apiUsername = self.EnvObject.env.get("API_USERNAME")
        self.apiPassword = self.EnvObject.env.get("API_PASSWORD")
        self.getJsonHeader = urllib3.make_headers(basic_auth=f"{self.apiUsername}:{self.apiPassword}")
        self.getJsonHeader["Accept"] = "application/json"
        self.getXmlHeader = urllib3.make_headers(basic_auth=f"{self.apiUsername}:{self.apiPassword}")
        self.postHeader = urllib3.make_headers(basic_auth=f"{self.apiUsername}:{self.apiPassword}")
        self.postHeader["Content-Type"] = "application/xml"
        self.pstName = self.EnvObject.env.get("patchSoftwareTitle")
        self.pstID = self.getPstID(self.pstName)
        self.generalPolicyName = self.EnvObject.env.get("generalPolicyName")
        self.generalPkg = self.getGeneralPolicyPkg()
        pass

    def updatePST(self):
        print("starting update pst")
        pstURL = f"{self.jamfUrl}/JSSResource/patchsoftwaretitles/id/{self.pstID}"
        response = self.EnvObject.download(url=pstURL, headers=self.getXmlHeader)
        if not response:
            print("get pst failed")
        pst = response.decode('utf-8')
        root = ET.fromstring(pst)
        done = False
        for definition in root.findall("versions/version"):
            if self.generalPkg["version"] in definition.findtext("software_version"):
                if definition.findtext("package/name"):
                    print(f"definition already has a package {definition.findtext('package/name')}")
                    print("leaving update Pst")
                    return None
                updatePkg = definition.find("package")
                add = ET.SubElement(updatePkg, "id")
                add.text = str(self.generalPkg["id"])
                add = ET.SubElement(updatePkg, "name")
                add.text = self.generalPkg["name"]
                print("pkg was added to definitions")
                done = True
                break
        data = ET.tostring(root)
        # header = self.postHeader
        curl_cmd = (
            self.EnvObject.curl_binary(),
            "--url",
            pstURL,
            "--location",
            "-H",
            self.postHeader,
            "-H",
            "Content-Type: application/xml",
            "-X",
            "PUT",
            "-d",
            data
        )
        # print(curl_cmd)
        response = self.EnvObject.download_with_curl(curl_cmd)
        if not response:
            print("update to jamf failed")
        else:
            print("update to jamf succeeded")
        ## Return getHeader to is prior state
        print("leaving update Pst")
        return

    def createPolicy(self, appName, policyName, definitionVersion, distributionMethod="SelfService", gracePeriod="60"):
        print("Creating Policy...")
        # Create a Patch Policy asociated to the patch ID
        if distributionMethod == "prompt":
            tree = ET.parse("ppPromptTemplate.xml")
            root = tree.getroot()
        else:
            tree = ET.parse("ppSelfServiceTemplate.xml")
            root = tree.getroot()
            ### Edit XML Here
            root.find("user_interaction/self_service_description").text = f"Uptdate {appName}"
            root.find("user_interaction/notifications/notification_subject").text = "Update Available"
            root.find("user_interaction/notifications/notification_message").text = f"{appName} Update Installing"
        ### Edit XML Here
        root.find("general/name").text = str(policyName)
        root.find("software_title_configuration_id").text = self.pstID
        root.find("general/target_version").text = definitionVersion
        root.find("user_interaction/grace_period/grace_period_duration").text = gracePeriod

        ###
        xmlstr = ET.tostring(root, encoding='unicode', method='xml')
        # print(xmlstr)
        xmlstr = xmlstr.replace("\n", "")
        # xmlstr = xmlstr.replace(" ","")
        print(xmlstr)
        postURL = f"{self.jamfUrl}/JSSResource/patchpolicies/softwaretitleconfig/id/{self.pstID}"
        header = f"authorization: {self.postHeader['authorization']}"
        curl_cmd = (
            self.EnvObject.curl_binary(),
            "--url",
            postURL,
            "--location",
            "-H",
            header,
            "-H",
            "Content-Type: application/xml",
            "-X",
            "POST",
            "-d",
            xmlstr
        )
        response = self.EnvObject.download_with_curl(curl_cmd)
        if not response:
            print("update to jamf failed")
        else:
            print(response)

    def getGeneralPolicyPkg(self):
        print("starting getGeneralPolicypkg")
        generalPolicyURL = f"{self.jamfUrl}/JSSResource/policies/name/{self.generalPolicyName}"
        response = self.EnvObject.download(url=generalPolicyURL, headers=self.getJsonHeader)
        if not response:
            print("unable to get response from get general policy")
        decodedResponse = response.decode('utf-8')
        generalPolicy = json.loads(decodedResponse)
        pkgCount = len(generalPolicy["policy"]["package_configuration"]["packages"])
        if pkgCount != 1:
            print(f"the amount of packages in {self.generalPolicyName} needs to only be 1 pkg")
            return
        pkg = {}
        pkg['name'] = generalPolicy["policy"]["package_configuration"]["packages"][0]["name"]
        pkg['id'] = generalPolicy["policy"]["package_configuration"]["packages"][0]["id"]
        pkg["appName"] = pkg["name"].split("-", -1)[0]
        pkg["version"], pkg["type"] = (pkg["name"].rsplit("-", 1)[1]).rsplit(".", 1)
        print(f"returning {pkg['appName']} with type {pkg['type']} and version {pkg['version']}")
        print("leaving get General Policy pkg")
        return pkg

    def policyExist(self, policyName):
        ##Check if Gamma Policy
        print("in policyExist")
        print(f"Checking if PST Policy {policyName} Exists..")
        # looking for policy named gamma sorted by pst ID
        allPolicesURL = f"{self.jamfUrl}/JSSResource/patchpolicies/softwaretitleconfig/id/{self.pstID}"
        response = self.EnvObject.download(url=allPolicesURL, headers=self.getJsonHeader)
        decodedResponse = response.decode('utf-8')
        allPolicies = json.loads(decodedResponse)
        # print(allPolicies)
        for policy in allPolicies["patch policies"]:
            if policyName.lower() == policy["name"].lower():
                policyID = str(policy["id"])
                print(f"Found gamma policy with ID of {policyID}")
                print("Leaving policy Exist")
                return True
        print(f"Cound not find policy {policyName} in PST {self.pstName}")
        print("Leaving policy Exist")
        return False

    def getPstID(self, pstTitle):
        print("starting getPstId")
        allPatchesURL = f"{self.jamfUrl}/JSSResource/patchsoftwaretitles"
        # print(self.getJsonHeader)
        response = self.EnvObject.download(url=allPatchesURL, headers=self.getJsonHeader)
        # print(response)
        if not response:
            print("we were unable to get the response from the getPstID")
            return 0
        decodedResponse = response.decode('utf-8')
        softwareTitles = json.loads(decodedResponse)
        foundPst = False
        for pst in softwareTitles["patch_software_titles"]:
            if pstTitle == pst["name"]:
                pstID = str(pst["id"])
                print(f"Found pst with ID of {pstID}")
                foundPst = True
                break
        if not foundPst:
            print(f"Cound not find patch with name: {pstTitle}\n"
                  f"Please create the patch or confirm it's correct name before retrying script")
            return False
        print("leaving getPstId")
        return pstID


class Cache:
    cacheAPMPath = ""

    def __init__(self, processor):
        # Create cache for version control ii it doesn't exist
        print("starting cache init")
        self.cacheAPMPath = processor.env.get("RECIPE_CACHE_DIR") + "/APM.json"
        if not os.path.exists(self.cacheAPMPath):
            with open(self.cacheAPMPath, 'w', encoding='utf-8') as newFile:
                json.dumps("\{\}", newFile, ensure_ascii=False, indent=4)
        print("leaving cache init")

    def getCache(self):
        print("starting getCache")
        ##Returns Version, Date of Last Patch Update using the policyID

        # version, date, packageName, name, gammaPolicyID, prodPolicyID = "new"
        # when i run the script whith the above I get the following error fsfollow.vlc.apm
        # Error in local.APM.VLC.FSFollow: Processor: APM: Error: not enough values to unpack (expected 6, got 3)
        if not os.stat(self.cacheAPMPath).st_size:
            print("Cache is Empty! Returning keys with no value.")
            return False, {"version": "", "date": "", "packageName": "", "name": "", "gammaPolicyID": "",
                           "prodPolicyID": ""}
        else:
            with open(self.cacheAPMPath, 'r') as inFile:
                data = json.load(inFile)
            print("Cache opened.")
            version = data["version"]
            date = data["date"]
            packageName = data["packageName"]
            name = data["name"]
            gammaPolicyID = data["gammaPolicyID"]
            prodPolicyID = data["prodPolicyID"]
            return True, {"version": version, "date": date, "packageName": packageName,
                          "name": name, "gammaPolicyID": gammaPolicyID, "prodPolicyID": prodPolicyID}
        print("leaving getCache")

    def setCache(self, version, date, packageName, name, gammaPolicyID, prodPolicyID):
        ##updates cache version, policyID, and Date of Last Patch Update
        with open(self.cacheAPMPath, 'r') as inFile:
            data = json.load(inFile)
        data["version"] = version
        data["date"] = date
        data["packageName"] = packageName
        data["name"] = name
        data["gammaPolicyID"] = gammaPolicyID
        data["prodPolicyID"] = prodPolicyID
        with open(self.cacheAPMPath, 'w', encoding='utf-8') as newFile:
            json.dump(data, newFile, ensure_ascii=False, indent=4)
        return


class Gamma:
    pkgName = ""
    generalPolicyName = ""
    jamfUrl = ""
    getHeader = {}
    postHeader = {}
    apiUsername = ""
    apiPassword = ""
    distributionMethod = ""

    def __init__(self, EnvObject, PSTObject):
        print("in gamma init")
        ##Constructor(initializer) that activates when an object is created
        self.EnvObject = EnvObject
        self.pst = PSTObject
        self.pkgName = self.EnvObject.env.get("applicationTitle")
        self.distributionMethod = self.EnvObject.env.get("gammaDistributionMethod")
        print("leaving gamma init")

        
    def compGammaPtch(self):
        print("in compGammaPtch")
        cacheObject = Cache(self.EnvObject)
        self.pst.updatePST()
        if not self.pst.policyExist("Gamma"):
            print("did not find PST Policy Gamma, creating policy now.")
            self.pst.createPolicy("Gamma")
        # need to update policy
        # need to update cache
        # not to test Set cache?
        print("leaving compGammaPtch")
        return

    def __checkPolicyVersion():
        ##Checks to see if Gamma has latest version and that definition has a pkg
        return

    def __updatePolicyVersion():
        ##Updates the policy version in cache
        return

    def __updateGammaPtch(self, patchID, distributionMethod):
        ## Public function
        ## Contains logic to update Gamma Patch

        return


class Prod:
    delta = 0
    distributionMethod = ""
    prodPolicyID = ""

    def __init__(self, EnvObject):
        self.EnvObject = EnvObject
        ##Constructor(initializer) that activates when an object is created
        self.delta = 7

    def moveProduction(self):
        ##Function that holds the logic to move policy to production
        return

    def __checkPSTPolicy(self):
        ##check if the PST Production Policy Exists
        return

    def checkDelta(self, delta, date):
        ##Compares the Delta Variable with the (current time) - (timw when patch was created)
        ##returns True if result of diff is <= 0 else returns False
        return False


class Application:
    """A class to carry the details of the application through the processor"""

    applicationTitle = ""  # The name of the application
    generalPolicyName = ""  # The name of the policy that we pull the filename from
    generalPolicyID = ""  # The ID of the policy that we pull the filename from
    productionDelay = ""  # The length in days to wait to go from test to prod
    gammaDistributionMethod = ""  # The method for distribution (Selfservice/automatic(prompt))
    prodDistributionMethod = ""  # The method for distribution (Selfservice (prompt)/automatic)


class APM(URLGetter):
    """This processor takes a general policy that is made by some other recipe and then moves that package to JAMFs Patch management
    Definitions and policies. In policies it creates and sets up a testing policy, the user is required to set the scope, 
    it also creates a production policy that does the same thing, and again the user has to setup scope."""

    description = __doc__

    input_variables = {
        "applicationTitle": {"required": True, "description": "The name of the application"},
        "generalPolicyName": {"required": True, "description": "The name of the policy that we pull the filename from"},
        "patchSoftwareTitle": {"required": True,
                               "description": "The name of the patch software title we need to use to check PST policies"},
        "productionDelay": {"required": False, "description": "The length in days to wait to go from test to prod"},
        "gammaDistributionMethod": {"required": False,
                                    "description": "The method for distribution (Selfservice/automatic(prompt))"},
        "prodDistributionMethod": {"required": False,
                                   "description": "The method for distribution (Selfservice (prompt)/automatic)"},
    }
    output_variables = {
        "patch_manager_summary_result": {"description": "Summary of action"}
    }

    app = Application()

    def setup_logging(self):
        """Defines a nicely formatted logger"""
        LOGFILE = "/usr/local/var/log/%s.log" % APPNAME

        self.logger = logging.getLogger(APPNAME)
        # we may be the second and subsequent iterations of JPCImporter
        # and already have a handler.
        if len(self.logger.handlers):
            return
        ch = logging.handlers.TimedRotatingFileHandler(
            LOGFILE, when="D", interval=1, backupCount=7
        )
        ch.setFormatter(
            logging.Formatter(
                "%(asctime)s %(levelname)s %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )
        )
        self.logger.addHandler(ch)
        self.logger.setLevel(LOGLEVEL)

    def main(self):
        print("My custom processor!") ### testing Git
        pstCahce = Cache(self)
        pst = PST(self)
        cacheLoadStatus, cache = pstCahce.getCache()
        if cacheLoadStatus:
            print("cache load status succeeded proceeding to prodution")
            print(cache["date"])
            prod = Prod(self)
            print(prod.checkDelta(self.EnvObject.env.get("productionDelay"), cache["date"]))
        else:
            print("cache load status is false so Production was skipped")
        if not pst.policyExist("gamma"):
            pst.createPolicy(appName=self.pkgName, policyName="Gamma", definitionVersion=generalPkg["version"],
                             distributionMethod=self.distributionMethod)

        gamma = Gamma(self, pst)
        gamma.compGammaPtch()


if __name__ == "__main__":
    PROCESSOR = APM()
    PROCESSOR.execute_shell()