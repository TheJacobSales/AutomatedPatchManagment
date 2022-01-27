# from functools import cache
import logging.handlers
from pickle import FALSE
from ssl import VerifyMode
from turtle import pos
from urllib import response


from urllib3 import get_host
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

    def __init__(self, baseUrl, postHeader, getHeader, pstID):
        self.jamfUrl = baseUrl
        self.postHeader = postHeader
        self.getHeader = getHeader
        self.pstID = pstID
        pass
    
    def createPolicy(self, policyName, appName, definitionVersion, distributionMethod, gracePeriod):
        print("Creating Policy...")
        # payload = f"""
        # <patch_policy><general><name>Gamma</name><enabled>false</enabled><distribution_method>{distributionMethod}</distribution_method>
        # <allow_downgrade>false</allow_downgrade><patch_unknown>true</patch_unknown></general><user_interaction>
        # <grace_period><grace_period_duration>60</grace_period_duration></grace_period></user_interaction>
        # <software_title_configuration_id></software_title_configuration_id></patch_policy>
        # """
        #Create a Patch Policy asociated to the patch ID
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
        xmlstr = xmlstr.replace("\n","")
        # xmlstr = xmlstr.replace(" ","")
        # print(xmlstr)
        postURL = f"{self.jamfUrl}/JSSResource/patchpolicies/softwaretitleconfig/id/{self.pstID}"
        response = self.EnvObject.download(url=postURL, headers=self.postHeader, data=xmlstr)
        decodedResponse = response.decode('utf-8')
        softwareTitles = json.loads(decodedResponse)
        if response.status_code == 201:
            print(f"{policyName} policy was created successfully. This Policy was created with no "
                f"scope and disabled. When ready go and set a scope and then enable policy.")
        else:
            print(f"{policyName} policy failed to create with error code: {response.status_code}")
        return

    def getPolicy():
        return

class Cache:
    cacheAPMPath = ""
    def __init__(self, processor):
        #Create cache for version control ii it doesn't exist
        print("in cache init")
        self.cacheAPMPath = processor.env.get("RECIPE_CACHE_DIR") + "/APM.json"
        if not os.path.exists(self.cacheAPMPath):
            with open(self.cacheAPMPath, 'w', encoding='utf-8') as newFile:
                json.dumps("\{\}",newFile, ensure_ascii=False, indent=4)

    def getCache(self):
        ##Returns Version, Date of Last Patch Update using the policyID

        # version, date, packageName, name, gammaPolicyID, prodPolicyID = "new"
        # when i run the script whith the above I get the following error fsfollow.vlc.apm
        # Error in local.APM.VLC.FSFollow: Processor: APM: Error: not enough values to unpack (expected 6, got 3)
        if not os.stat(self.cacheAPMPath).st_size: 
            print("Cache is Empty! Returning keys with no value.")
            return False, {"version":"", "date":"", "packageName":"", "name":"", "gammaPolicyID":"", "prodPolicyID":""}
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
            return True, {"version":version, "date":date, "packageName":packageName, 
        "name":name, "gammaPolicyID":gammaPolicyID, "prodPolicyID":prodPolicyID}
    
    def setCache(self,version, date, packageName, name, gammaPolicyID, prodPolicyID):
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
            json.dump(data,newFile, ensure_ascii=False, indent=4)
        return

class Gamma:
    pkgName = ""
    generalPolicyID = ""
    jamfUrl = ""
    getHeader = {}
    postHeader = {}
    def __init__(self, EnvObject):
        ##Constructor(initializer) that activates when an object is created
        self.EnvObject = EnvObject
        self.pkgName = self.EnvObject.env.get("applicationTitle")
        self.jamfUrl = self.EnvObject.env.get("JSS_URL")
        generalPolicyName = self.EnvObject.env.get("generalPolicyName")
        apiUsername = self.EnvObject.env.get("API_USERNAME")
        apiPassword = self.EnvObject.env.get("API_PASSWORD")
        patchPoliciesURL = f"{self.jamfUrl}/JSSResource/policies/name/{generalPolicyName}"
        print(patchPoliciesURL)
        self.getHeader= urllib3.make_headers(basic_auth=f"{apiUsername}:{apiPassword}")
        self.postHeader = self.getHeader
        self.getHeader["Accept"] = "application/json"
        response = self.EnvObject.download(patchPoliciesURL, headers=self.getHeader)
        decodedResponse = response.decode('utf-8')
        patchPolicies = json.loads(decodedResponse)
        self.generalPolicyID = patchPolicies["policy"]["general"]["category"]["id"]
    
    def compGammaPtch(self):
        ## Public function
        ## Contains logic to complete Gamma Patch
        print(self.__gammaPolicyExist())
        return
    
    def __checkDef():
        ##Check if patch definition exists
        #return true if exists else create def
        return False
    
    def __updateDef():
        ##Update patch definition or create definition
        return
    
    def __gammaPolicyExist(self):
        ##Check if Gamma Policy
        #return True if exists else create new gamma policy
        #Get software title ID if it exists
        print("Checking if Gamma Exists..")
        patchName = self.EnvObject.env.get("patchSoftwareTitle")
        allPatchesURL = f"{self.jamfUrl}/JSSResource/patchsoftwaretitles"
        response = self.EnvObject.download(url=allPatchesURL, headers=self.getHeader)
        decodedResponse = response.decode('utf-8')
        softwareTitles = json.loads(decodedResponse)
        foundPatch = False
        for patch in softwareTitles["patch_software_titles"]:
            if patchName == patch["name"]:
                patchID = str(patch["id"])
                print(f"Found patch with ID of {patchID}")
                foundPatch = True
                break
        if foundPatch == False:
            print(f"Cound not find patch with name: {patchName}\nPlease create the patch or confirm it's correct name before retrying script")
            return False

        #looking for policy named gamma sorted by pst ID
        allPolicesURL = f"{self.jamfUrl}/JSSResource/patchpolicies/softwaretitleconfig/id/{patchID}"
        response = self.EnvObject.download(url=allPolicesURL, headers=self.getHeader)
        decodedResponse = response.decode('utf-8')
        allPolicies = json.loads(decodedResponse)
        foundPolicy = False
        # print(allPolicies)
        for policy in allPolicies["patch policies"]:
            if "gamma" == policy["name"].lower():
                policyID = str(policy["id"])
                print(f"Found gamma policy with ID of {policyID}")
                foundPolicy = True
                break
        if foundPolicy == False:
            print(f"Cound not find policy with name: Gamma in {patchName}\nAPM will now create that policy")
            # self.__createGammaPolicy(patchID)
            
        raise SystemExit

        # patchPoliciesURL = f"{self.jamfUrl}/JSSResource/patchpolicies/softwaretitleconfig/id/{patchID}"
        # print(patchPoliciesURL)
        # response = self.get(url=patchPoliciesURL, headers=getHeader)
        # patchPolicies = response.json()
        # print(patchPolicies)
        return False

    def __checkPolicyVersion():
        ##Checks to see if Gamma has latest version and that definition has a pkg
        return

    def __updatePolicyVersion():
        ##Updates the policy version in cache
        return

class Prod:
    delta = 0
    dispoMethod = ""
    testPolicyID = ""

    def __init__(self):
        ##Constructor(initializer) that activates when an object is created
        self.delta = 7
    
    def moveProduction():
        ##Function that holds the logic to move policy to production
        return

    def __checkPSTPolicy():
        ##check if the PST Production Policy Exists
        return

    def __compDelta():
        ##Compares the Delta Variable with the (current time) - (timw when patch was created)
        ##returns True if result of diff is <= 0 else returns False
        return False

class Application:
    """A class to carry the details of the application through the processor"""

    applicationTitle = "" # The name of the application
    generalPolicyName = "" # The name of the policy that we pull the filename from
    generalPolicyID = "" # The ID of the policy that we pull the filename from
    productionDelay = "" # The length in days to wait to go from test to prod
    gammaDistributionMethod = "" # The method for distribution (Selfservice/automatic(prompt))
    prodDistributionMethod = "" # The method for distribution (Selfservice (prompt)/automatic)
    

class APM(URLGetter):
    """This processor takes a general policy that is made by some other recipe and then moves that package to JAMFs Patch management
    Definitions and policies. In policies it creates and sets up a testing policy, the user is required to set the scope, 
    it also creates a production policy that does the same thing, and again the user has to setup scope."""

    description = __doc__

    input_variables = {
        "applicationTitle": {"required": True, "description": "The name of the application"},
        "generalPolicyName": {"required": True, "description": "The name of the policy that we pull the filename from"},
        "patchSoftwareTitle": {"required": True, "description": "The name of the patch software title we need to use to check PST policies"},
        "productionDelay": {"required": False, "description": "The length in days to wait to go from test to prod"},
        "gammaDistributionMethod": {"required": False, "description": "The method for distribution (Selfservice/automatic(prompt))"},
        "prodDistributionMethod": {"required": False, "description": "The method for distribution (Selfservice (prompt)/automatic)"},
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

    def getPstID():
        # maybe the get pstid should be here, it should only needs to be done once, so probably just call in 
        # main before calling gamma?
        return

    def main(self):
        cache = Cache(self)
        print("My custom processor!")
        gamma = Gamma(self)
        gamma.compGammaPtch()
        # get Cache seems to work
        # not to test Set cache?

if __name__ == "__main__":
    PROCESSOR = APM()
    PROCESSOR.execute_shell()