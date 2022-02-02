# from functools import cache
# from importlib.metadata import distribution
import logging.handlers
import os
import json
import urllib3
import xml.etree.ElementTree as ET
import time
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
        print("starting pst init")
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
        print("leaving pst init")
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
        auth = f"authorization: {self.postHeader['authorization']}"
        type = f"Content-type: {self.postHeader['Content-Type']}"
        curl_cmd = (
            self.EnvObject.curl_binary(),
            "--url",
            pstURL,
            "--location",
            "-H",
            auth,
            "-H",
            type,
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
        print("starting createPolicy")
        # Create a Patch Policy asociated to the patch ID
        data = """
        <patch_policy><general><id></id><name>Edit</name><target_version></target_version>
        <distribution_method>self service</distribution_method><patch_unknown>true</patch_unknown>
        </general><user_interaction><grace_period><grace_period_duration>15</grace_period_duration>
        </grace_period></user_interaction><software_title_configuration_id>Edit
        </software_title_configuration_id></patch_policy>
        """
        tree = ET.ElementTree(ET.fromstring(data))
        root = tree.getroot()
        if distributionMethod == "prompt":
            root.find("general/distribution_method").text = "prompt"
        else:
            root.find("general/distribution_method").text = "selfservice"
            user_interaction = root.find("user_interaction")
            self_service_description = ET.fromstring(f"<self_service_description>Update {appName}"
                                                     f"</self_service_description>")
            user_interaction.append(self_service_description)
            notifications = ET.fromstring(f"<notifications><notification_subject>Update Available"
                                          f"</notification_subject><notification_message>"
                                          f"{appName} Update Installing</notification_message></notifications>")
            user_interaction.append(notifications)
        ### Edit XML Here
        root.find("general/name").text = str(policyName)
        root.find("software_title_configuration_id").text = self.pstID
        root.find("general/target_version").text = definitionVersion
        root.find("user_interaction/grace_period/grace_period_duration").text = gracePeriod

        ###
        xmlString = ET.tostring(root, encoding='unicode', method='xml')
        xmlString = xmlString.replace("\n", "")
        # leaving this out since it makes the notifications look bad and xml doesnt care
        # xmlString = xmlString.replace(" ","")
        # print(xmlString)
        postURL = f"{self.jamfUrl}/JSSResource/patchpolicies/softwaretitleconfig/id/{self.pstID}"
        auth = f"authorization: {self.postHeader['authorization']}"
        type = f"Content-type: {self.postHeader['Content-Type']}"
        curl_cmd = (
            self.EnvObject.curl_binary(),
            "--url",
            postURL,
            "--location",
            "-H",
            auth,
            "-H",
            type,
            "-X",
            "POST",
            "-d",
            xmlString
        )
        response = self.EnvObject.download_with_curl(curl_cmd)
        if not response:
            print("update to jamf failed")
            return 1
        else:
            print("Policy successfully created in JAMF")
            return 0

    def checkPolicyVersion(self, policyName, definitionVersion):
        print("starting checkPolicyVersion")
        check = {}
        # checking to see if this policy has the right version
        allPolicesURL = f"{self.jamfUrl}/JSSResource/patchpolicies/softwaretitleconfig/id/{self.pstID}"
        response = self.EnvObject.download(url=allPolicesURL, headers=self.getJsonHeader)
        decodedResponse = response.decode('utf-8')
        allPolicies = json.loads(decodedResponse)
        for policy in allPolicies["patch policies"]:
            if policyName.lower() == policy["name"].lower():
                policyID = str(policy["id"])
                gammaURL = f"{self.jamfUrl}/JSSResource/patchpolicies/id/{policyID}"
                response = self.EnvObject.download(url=gammaURL, headers=self.getJsonHeader)
                decodedResponse = response.decode('utf-8')
                gammaPolicy = json.loads(decodedResponse)
                # print(gammaPolicy)
                # print(f"Found gamma policy with ID of {policyID}")
                if definitionVersion == str(gammaPolicy["patch_policy"]["general"]["target_version"]):
                    print("policy has the correct version")
                    print("Leaving checkPolicyVersion")
                    check["status"] = True
                    check["version"] = definitionVersion
                    check["policyID"] = policyID
                    return check
                else:
                    print("policy has old version")
                    print("Leaving checkPolicyVersion")
                    check["status"] = False
                    check["policyID"] = policyID
                    check["version"] = definitionVersion
                    return check
        print(f"Could not find policy {policyName} in PST {self.pstName}")
        print("Leaving checkPolicyVersion")
        return 1

    def updatePolicyVersion(self, policyID, definitionVersion):
        print("starting updatePolicyVersion")
        xmlString = f"<patch_policy><general><target_version>{definitionVersion}" \
                    f"</target_version></general></patch_policy>"
        # tree = ET.ElementTree(ET.fromstring(data))
        # root = tree.getroot()
        # ### Edit XML Here
        # root.find("general/name").text = str(policyName)
        # xmlString = ET.tostring(root, encoding='unicode', method='xml')
        postURL = f"{self.jamfUrl}/JSSResource/patchpolicies/id/{policyID}"
        auth = f"authorization: {self.postHeader['authorization']}"
        contentType = f"Content-type: {self.postHeader['Content-Type']}"
        curl_cmd = (
            self.EnvObject.curl_binary(),
            "--url",
            postURL,
            "--location",
            "-H",
            auth,
            "-H",
            contentType,
            "-X",
            "PUT",
            "-d",
            xmlString
        )
        response = self.EnvObject.download_with_curl(curl_cmd)
        if not response:
            print("update to jamf failed")
            print("Leaving updatePolicyVersion")
            return 1
        else:
            # print(response)
            print(f"updated policy to version {definitionVersion}")
            print("Leaving updatePolicyVersion")
            return 0

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

    def checkPolicyExist(self, policyName):
        ##Check if Gamma Policy
        print("starting checkPolicyExist")
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
            data = {"version": "", "date": time.time(), "packageName": "", "name": "", "gammaPolicyID": "",
                    "prodPolicyID": ""}
            # jsonString = json.dumps(data)
            # print(data)
            with open(self.cacheAPMPath, 'w') as outfile:
                json.dump(data, outfile)
        print("leaving cache init")

    def get(self):
        print("starting Cache set")
        ##Returns Version, Date of Last Patch Update using the policyID

        # version, date, packageName, name, gammaPolicyID, prodPolicyID = "new"
        # when i run the script whith the above I get the following error fsfollow.vlc.apm
        # Error in local.APM.VLC.FSFollow: Processor: APM: Error: not enough values to unpack (expected 6, got 3)
        with open(self.cacheAPMPath, 'r') as inFile:
            data = json.load(inFile)
        print("Cache opened.")
        version = data["version"]
        date = data["date"]
        packageName = data["packageName"]
        name = data["name"]
        gammaPolicyID = data["gammaPolicyID"]
        prodPolicyID = data["prodPolicyID"]
        print("leaving Cache get")
        return {"version": version, "date": date, "packageName": packageName,
                "name": name, "gammaPolicyID": gammaPolicyID, "prodPolicyID": prodPolicyID}


    def set(self, version, packageName, name, gammaPolicyID=0, prodPolicyID=0):
        print("starting cache set")
        ##updates cache version, policyID, and Date of Last Patch Update
        with open(self.cacheAPMPath, 'r') as inFile:
            data = json.load(inFile)
        data["version"] = version
        data["date"] = time.time()
        data["packageName"] = packageName
        data["name"] = name
        if not gammaPolicyID == 0:
            data["gammaPolicyID"] = gammaPolicyID
        if not prodPolicyID == 0:
            data["prodPolicyID"] = prodPolicyID
        with open(self.cacheAPMPath, 'w', encoding='utf-8') as newFile:
            json.dump(data, newFile, ensure_ascii=False, indent=4)
        print("leaving cache set")
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
        print("starting gamma init")
        ##Constructor(initializer) that activates when an object is created
        self.EnvObject = EnvObject
        self.pst = PSTObject
        self.pkgName = self.EnvObject.env.get("applicationTitle")
        self.distributionMethod = self.EnvObject.env.get("gammaDistributionMethod")
        self.definitionVersion = self.EnvObject.env.get("")
        print("leaving gamma init")

    def gammaPatch(self):
        print("starting gammaPatch")
        appName = self.pkgName
        policyName = "Gamma"
        gammaCache = Cache(self.EnvObject)
        cache = gammaCache.get()
        self.pst.updatePST()
        if not self.pst.checkPolicyExist("Gamma"):
            print("did not find PST Policy Gamma, creating policy now.")
            policyCreated = self.pst.createPolicy(appName=appName, policyName=policyName,
                                                  definitionVersion=self.pst.generalPkg["version"],
                                                  distributionMethod=self.distributionMethod)
            if policyCreated != 0:
                print("Gamma policy was not created")
                return 1
            else:
                print("gamma policy created and update check can be skipped")
                gammaCache.set(version=self.pst.generalPkg["version"],
                               packageName=self.pst.generalPkg["name"],
                               name=self.pst.pstName)
                return 0
        check = self.pst.checkPolicyVersion(policyName=policyName, definitionVersion=self.pst.generalPkg["version"])
        if not check["status"]:
            updateComplete = self.pst.updatePolicyVersion(policyID=check["policyID"],
                                                          definitionVersion=self.pst.generalPkg["version"])
            if updateComplete != 0:
                print("policy update failed")
                return 1
        if cache["version"] != self.pst.generalPkg["version"]:
            gammaCache.set(version=self.pst.generalPkg["version"],
                      packageName=self.pst.generalPkg["name"],
                      name=self.pst.pstName,
                      gammaPolicyID=check["policyID"])
        # not to test Set cache?
        print("leaving gammaPatch")
        return 0


class Prod:
    delta = 0
    distributionMethod = ""
    prodPolicyID = ""

    def __init__(self, EnvObject, PSTObject, cache):
        print("starting prod init")
        ##Constructor(initializer) that activates when an object is created
        self.EnvObject = EnvObject
        self.pst = PSTObject
        self.distributionMethod = self.EnvObject.env.get("prodDistributionMethod")
        self.cacheVersion = cache["version"]
        self.packageName = cache["packageName"]
        self.prodPolicyID = cache["prodPolicyID"]
        self.appName = cache["name"]
        print("leaving prod init")

    def prodPatch(self):
        print("starting prodPatch")
        ##Function that holds the logic to move policy to production
        policyName = "Production"
        if not self.pst.checkPolicyExist("Production"):
            print("did not find PST Policy Production, creating policy now.")
            policyCreated = self.pst.createPolicy(appName=self.appName, policyName=policyName,
                                                  definitionVersion=self.cacheVersion,
                                                  distributionMethod=self.distributionMethod)
            if policyCreated != 0:
                print("Gamma policy was not created")
                return 1
            else:
                print("gamma policy created and update check can be skipped")
                return 0
        check = self.pst.checkPolicyVersion(policyName=policyName, definitionVersion=self.cacheVersion)
        if not check["status"]:
            updateComplete = self.pst.updatePolicyVersion(policyID=check["policyID"],
                                                          definitionVersion=self.cacheVersion)
            if updateComplete != 0:
                print("policy update failed")
                return 1
        print("leaving prodPatch")
        return 0


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
        print("My custom processor!")  ### testing Git
        mainCache = Cache(self)
        pst = PST(self)
        cache = mainCache.get()
        if cache["version"] != "":
            print("cache load version successful, checking delta")
            deltaInSeconds = 60 * 60 * 24 * int(self.env.get("productionDelay"))
            if time.time() + deltaInSeconds < cache["date"]:
                print("delta time has elapsed running prod")
                prod = Prod(self, pst, cache)
                prod.prodPatch()
            else:
                print("production Delay time has not been met, skipping production")
        else:
            print("cached version is empty so Production was skipped")
        gamma = Gamma(self, pst)
        gamma.gammaPatch()


if __name__ == "__main__":
    PROCESSOR = APM()
    PROCESSOR.execute_shell()
