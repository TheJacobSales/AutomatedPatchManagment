import logging.handlers
import os
import json
import urllib3
import xml.etree.ElementTree as ET
import time
import sys
from autopkglib import Processor, ProcessorError, URLGetter

APPNAME = "APM"
LOGLEVEL = logging.DEBUG

__all__ = [APPNAME]


class PST:
    def __init__(self, EnvObject):
        EnvObject.logger.info("Starting PST init..")
        self.EnvObject = EnvObject
        self.jamfUrl = EnvObject.env.get("JSS_URL")
        self.generalPolicyName = EnvObject.env.get("generalPolicyName")
        self.pstName = EnvObject.env.get("patchSoftwareTitle")
        apiUsername = EnvObject.env.get("API_USERNAME")
        apiPassword = EnvObject.env.get("API_PASSWORD")
        self.getJsonHeader = urllib3.make_headers(
            basic_auth=f"{apiUsername}:{apiPassword}"
        )
        self.getJsonHeader["Accept"] = "application/json"
        self.getXmlHeader = urllib3.make_headers(
            basic_auth=f"{apiUsername}:{apiPassword}"
        )
        self.postHeader = urllib3.make_headers(
            basic_auth=f"{apiUsername}:{apiPassword}"
        )
        self.postHeader["Content-Type"] = "application/xml"
        self.pstID = self.getPstID(self.pstName)
        self.generalPkg = self.getGeneralPolicyPkg()
        EnvObject.logger.info("Leaving PST init.")
        pass

    def updatePST(self):
        self.EnvObject.logger.info("Starting update PST...")
        pstURL = f"{self.jamfUrl}/JSSResource/patchsoftwaretitles/id/{self.pstID}"
        response = self.EnvObject.download(url=pstURL, headers=self.getXmlHeader)
        if not response:
            self.EnvObject.logger.error("GET PST FAILED!")
        pst = response.decode("utf-8")
        root = ET.fromstring(pst)
        self.EnvObject.logger.info(self.generalPkg["version"])
        for definition in root.findall("versions/version"):
            pstVersion = (
                definition.findtext("software_version").split("(", -1)[0].strip()
            )
            self.EnvObject.logger.info(pstVersion)
            if pstVersion in self.generalPkg["version"]:
                self.EnvObject.logger.info(
                    f"found general package version {self.generalPkg['version']}"
                )
                # this checks to see if the definitions are exactly the same, if not at this point we will
                # use the definition from JAMF
                if self.generalPkg["version"] != definition.findtext(
                    "software_version"
                ):
                    self.generalPkg["version"] = definition.findtext("software_version")
                    self.EnvObject.logger.info(
                        f"self.generalpkg version was updated to {self.generalPkg['version']}"
                    )
                if definition.findtext("package/name"):
                    self.EnvObject.logger.info(
                        f"Definition already has a package {definition.findtext('package/name')}."
                    )
                    self.EnvObject.logger.info("Leaving update PST.")
                    return None
                updatePkg = definition.find("package")
                add = ET.SubElement(updatePkg, "id")
                add.text = str(self.generalPkg["id"])
                add = ET.SubElement(updatePkg, "name")
                add.text = self.generalPkg["name"]
                self.EnvObject.logger.info("Pkg was added to definitions.")
                break
        if updatePkg is None:
            self.EnvObject.logger.info("Pkg was not found in definition Error.")
            sys.exit()

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
            data,
        )
        # print(curl_cmd)
        response = self.EnvObject.download_with_curl(curl_cmd)
        if not response:
            self.EnvObject.logger.error("UPDATE TO PST FAILED!")
        else:
            self.EnvObject.logger.info("Update to jamf succeeded.")
            self.EnvObject.logger.info("Leaving update PST.")
        return

    def createPolicy(
        self,
        appName,
        policyName,
        definitionVersion,
        distributionMethod="SelfService",
        gracePeriod="60",
    ):
        self.EnvObject.logger.info("Starting createPolicy...")
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
            self_service_description = ET.fromstring(
                f"<self_service_description>Update {appName}"
                f"</self_service_description>"
            )
            user_interaction.append(self_service_description)
            notifications = ET.fromstring(
                f"<notifications><notification_subject>Update Available"
                f"</notification_subject><notification_message>"
                f"{appName} Update Installing</notification_message></notifications>"
            )
            user_interaction.append(notifications)
        root.find("general/name").text = str(policyName)
        root.find("software_title_configuration_id").text = self.pstID
        root.find("general/target_version").text = definitionVersion
        root.find(
            "user_interaction/grace_period/grace_period_duration"
        ).text = gracePeriod
        xmlString = ET.tostring(root, encoding="unicode", method="xml")
        xmlString = xmlString.replace("\n", "")
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
            xmlString,
        )
        response = self.EnvObject.download_with_curl(curl_cmd)
        if not response:
            self.EnvObject.logger.error("UPDATE TO JAMF FAILED!")
            return 1
        else:
            self.EnvObject.logger.info("Policy successfully created in JAMF.")
            return 0

    def checkPolicyVersion(self, policyName, definitionVersion):
        self.EnvObject.logger.info("Starting checkPolicyVersion...")
        check = {}
        # checking to see if this policy has the right version
        allPolicesURL = f"{self.jamfUrl}/JSSResource/patchpolicies/softwaretitleconfig/id/{self.pstID}"
        response = self.EnvObject.download(
            url=allPolicesURL, headers=self.getJsonHeader
        )
        decodedResponse = response.decode("utf-8")
        allPolicies = json.loads(decodedResponse)
        for policy in allPolicies["patch policies"]:
            if policyName.lower() == policy["name"].lower():
                policyID = str(policy["id"])
                gammaURL = f"{self.jamfUrl}/JSSResource/patchpolicies/id/{policyID}"
                response = self.EnvObject.download(
                    url=gammaURL, headers=self.getJsonHeader
                )
                decodedResponse = response.decode("utf-8")
                gammaPolicy = json.loads(decodedResponse)
                # print(gammaPolicy)
                # print(f"Found gamma policy with ID of {policyID}")
                if definitionVersion == str(
                    gammaPolicy["patch_policy"]["general"]["target_version"]
                ):
                    self.EnvObject.logger.info("Policy has the correct version.")
                    check["status"] = True
                else:
                    self.EnvObject.logger.info("Policy has old version.")
                    check["status"] = False
                check["version"] = definitionVersion
                check["policyID"] = policyID
                self.EnvObject.logger.info("Leaving checkPolicyVersion.")
                return check
        self.EnvObject.logger.info(
            f"Could not find policy {policyName} in PST {self.pstName}."
        )
        self.EnvObject.logger.info("Leaving checkPolicyVersion.")
        return 1

    def updatePolicyVersion(self, policyID, definitionVersion):
        self.EnvObject.logger.info("Starting updatePolicyVersion...")
        xmlString = (
            f"<patch_policy><general><target_version>{definitionVersion}"
            f"</target_version></general></patch_policy>"
        )
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
            xmlString,
        )
        response = self.EnvObject.download_with_curl(curl_cmd)
        if not response:
            self.EnvObject.logger.ERROR("UPDATE TO JAMF FAILED!")
            self.EnvObject.logger.info("Leaving updatePolicyVersion.")
            return 1
        else:
            # print(response)
            self.EnvObject.logger.info(
                f"Updated policy to version {definitionVersion}."
            )
            self.EnvObject.logger.info("Leaving updatePolicyVersion.")
            return 0

    def getGeneralPolicyPkg(self):
        self.EnvObject.logger.info("Starting getGeneralPolicypkg...")
        generalPolicyURL = (
            f"{self.jamfUrl}/JSSResource/policies/name/{self.generalPolicyName}"
        )
        response = self.EnvObject.download(
            url=generalPolicyURL, headers=self.getJsonHeader
        )
        if not response:
            self.EnvObject.logger.ERROR("UNABLE TO GET RESPONSE FROM GENERAL POLICY!")
        try:
            decodedResponse = response.decode("utf-8")
            generalPolicy = json.loads(decodedResponse)
        except ValueError:
            self.EnvObject.logger.info(
                f"FAILED TO PARSE RESPONSE FROM GENERAL POLICY! {self.generalPolicyName}"
            )
            self.EnvObject.logger.info("Leaving updatePolicyVersion.")
            sys.exit()
        # Trying to make it so that multiple packages can exist in the policy
        # if pkgCount != 1:
        #     self.EnvObject.logger.info(
        #         f"The amount of packages in {self.generalPolicyName} needs to only be 1 pkg."
        #     )
        #     return
        pkgCount = len(generalPolicy["policy"]["package_configuration"]["packages"])
        if pkgCount != 1:
            for package in generalPolicy["policy"]["package_configuration"]["packages"]:
                if self.EnvObject.env.get("applicationTitle") in package["name"]:
                    foundPackage = package
                    self.EnvObject.logger.info(
                        f"package {package['name']} found and using for version info"
                    )
                    break
                else:
                    self.EnvObject.logger.ERROR(
                        f"UNABLE TO FIND {self.EnvObject.env.get('applicationTitle')} "
                        f"IN GENERAL POLICY PACKAGES"
                    )
        else:
            foundPackage = generalPolicy["policy"]["package_configuration"]["packages"][
                0
            ]
        if "_" in foundPackage["name"]:
            delineator = "_"
        elif "-" in foundPackage["name"]:
            delineator = "-"
        pkg = {}
        pkg["name"] = foundPackage["name"]
        pkg["id"] = foundPackage["id"]
        pkg["appName"] = pkg["name"].split(delineator, -1)[0]
        pkg["version"], pkg["type"] = (pkg["name"].rsplit(delineator, 1)[1]).rsplit(
            ".", 1
        )
        self.EnvObject.logger.info(
            f"Returning {pkg['appName']} with type {pkg['type']} and version {pkg['version']}."
        )
        self.EnvObject.logger.info("Leaving get General Policy pkg.")
        return pkg

    def checkPolicyExist(self, policyName):
        ##Check if Gamma Policy
        self.EnvObject.logger.info("Starting checkPolicyExist...")
        self.EnvObject.logger.info(f"Checking if PST Policy {policyName} Exists...")
        # looking for policy named gamma sorted by pst ID
        allPolicesURL = f"{self.jamfUrl}/JSSResource/patchpolicies/softwaretitleconfig/id/{self.pstID}"
        response = self.EnvObject.download(
            url=allPolicesURL, headers=self.getJsonHeader
        )
        decodedResponse = response.decode("utf-8")
        allPolicies = json.loads(decodedResponse)
        # print(allPolicies)
        for policy in allPolicies["patch policies"]:
            if policyName.lower() == policy["name"].lower():
                policyID = str(policy["id"])
                self.EnvObject.logger.info(f"Found gamma policy with ID of {policyID}.")
                self.EnvObject.logger.info("Leaving checkPolicyExists.")
                return True
        self.EnvObject.logger.info(
            f"Cound not find policy {policyName} in PST {self.pstName}."
        )
        self.EnvObject.logger.info("Leaving checkPolicyExists.")
        return False

    def getPstID(self, pstTitle):
        self.EnvObject.logger.info("Starting getPstId...")
        allPatchesURL = f"{self.jamfUrl}/JSSResource/patchsoftwaretitles"
        # self.EnvObject.logger.info(allPatchesURL)
        response = self.EnvObject.download(
            url=allPatchesURL, headers=self.getJsonHeader
        )
        # self.EnvObject.logger.info(response)
        if not response:
            self.EnvObject.logger.info("UNABLE TO GET RESPONSE FROM PSTID!")
            return 0
        decodedResponse = response.decode("utf-8")
        softwareTitles = json.loads(decodedResponse)
        for pst in softwareTitles["patch_software_titles"]:
            if pstTitle == pst["name"]:
                pstID = str(pst["id"])
                self.EnvObject.logger.info(f"Found pst with ID of {pstID}.")
                self.EnvObject.logger.info("Leaving getPstId.")
                return pstID
        self.EnvObject.logger.info(
            f"Cound not find patch with name: {pstTitle}.\n"
            f"Please create the patch or confirm it's correct name before retrying script."
        )
        return False


class Cache:
    def __init__(self, processor):
        # Create cache for version control if it doesn't exist
        self.EnvObject = processor
        processor.logger.info("starting cache init")
        self.cacheAPMPath = processor.env.get("RECIPE_CACHE_DIR") + "/APM.json"
        if not os.path.exists(self.cacheAPMPath) or not os.path.getsize(
            self.cacheAPMPath
        ):
            data = {
                "version": "",
                "date": time.time(),
                "packageName": "",
                "name": "",
                "gammaPolicyID": "",
                "prodPolicyID": "",
            }
            # jsonString = json.dumps(data)
            # print(data)
            with open(self.cacheAPMPath, "w") as outfile:
                json.dump(data, outfile)
        processor.logger.info("leaving cache init")

    def get(self):
        self.EnvObject.logger.info("starting Cache get")
        ##Returns Version, Date of Last Patch Update using the policyID
        with open(self.cacheAPMPath, "r") as inFile:
            data = json.load(inFile)
        self.EnvObject.logger.info("Cache opened.")
        self.EnvObject.logger.info("leaving Cache get")
        return {
            "version": data["version"],
            "date": data["date"],
            "packageName": data["packageName"],
            "name": data["name"],
            "gammaPolicyID": data["gammaPolicyID"],
            "prodPolicyID": data["prodPolicyID"],
        }

    def set(self, version, packageName, name, gammaPolicyID=0, prodPolicyID=0):
        self.EnvObject.logger.info("starting cache set")
        ##updates cache version, policyID, and Date of Last Patch Update
        with open(self.cacheAPMPath, "r") as inFile:
            data = json.load(inFile)
        data["version"] = version
        data["date"] = time.time()
        data["packageName"] = packageName
        data["name"] = name
        if not gammaPolicyID == 0:
            data["gammaPolicyID"] = gammaPolicyID
        if not prodPolicyID == 0:
            data["prodPolicyID"] = prodPolicyID
        with open(self.cacheAPMPath, "w", encoding="utf-8") as newFile:
            json.dump(data, newFile, ensure_ascii=False, indent=4)
        self.EnvObject.logger.info("leaving cache set")
        return


class Gamma:
    def __init__(self, EnvObject, PSTObject):
        EnvObject.logger.info("Starting Gamma init...")
        ##Constructor(initializer) that activates when an object is created
        self.EnvObject = EnvObject
        self.pst = PSTObject
        self.pkgName = EnvObject.env.get("applicationTitle")
        self.distributionMethod = EnvObject.env.get("gammaDistributionMethod")
        EnvObject.logger.info("Leaving Gamma init.")

    def gammaPatch(self):
        self.EnvObject.logger.info(
            "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
        )
        self.EnvObject.logger.info("Starting gammaPatch...")
        appName = self.pkgName
        policyName = "Gamma"
        gammaCache = Cache(self.EnvObject)
        cache = gammaCache.get()
        self.pst.updatePST()
        if not self.pst.checkPolicyExist("Gamma"):
            self.EnvObject.logger.info(
                "Did not find PST Policy Gamma, creating policy now..."
            )
            policyCreated = self.pst.createPolicy(
                appName=appName,
                policyName=policyName,
                definitionVersion=self.pst.generalPkg["version"],
                distributionMethod=self.distributionMethod,
            )
            if policyCreated != 0:
                self.EnvObject.logger.error("GAMMA POLICY WAS NOT CREATED!")
                return 1
            else:
                self.EnvObject.logger.info(
                    "Gamma policy created and update check can be skipped."
                )
                gammaCache.set(
                    version=self.pst.generalPkg["version"],
                    packageName=self.pst.generalPkg["name"],
                    name=self.pst.pstName,
                )
                self.EnvObject.env["gamma_policy_summary_result"] = {
                    "summary_text": "The following Gamma policy was created:",
                    "report_fields": ["app_name", "policy_name", "version"],
                    "data": {
                        "app_name": appName,
                        "policy_name": policyName,
                        "version": self.pst.generalPkg["version"],
                    },
                }
                self.EnvObject.env["cache_summary_result"] = {
                    "summary_text": "The cache was updated with the following values:",
                    "report_fields": ["name", "package_name", "version"],
                    "data": {
                        "name": self.pst.pstName,
                        "package_name": self.pst.generalPkg["name"],
                        "version": self.pst.generalPkg["version"],
                    },
                }
                return 0
        check = self.pst.checkPolicyVersion(
            policyName=policyName, definitionVersion=self.pst.generalPkg["version"]
        )
        if not check["status"]:
            updateComplete = self.pst.updatePolicyVersion(
                policyID=check["policyID"],
                definitionVersion=self.pst.generalPkg["version"],
            )
            self.EnvObject.env["gamma_policy_summary_result"] = {
                "summary_text": "The following Gamma policy was created:",
                "report_fields": ["app_name", "policy_name", "version"],
                "data": {
                    "app_name": appName,
                    "policy_name": policyName,
                    "version": self.pst.generalPkg["version"],
                },
            }
            if updateComplete != 0:
                self.EnvObject.logger.error("POLICY UPDATE FAILED!")
                return 1
        if cache["version"] != self.pst.generalPkg["version"]:
            gammaCache.set(
                version=self.pst.generalPkg["version"],
                packageName=self.pst.generalPkg["name"],
                name=self.pst.pstName,
                gammaPolicyID=check["policyID"],
            )
            self.EnvObject.env["cache_summary_result"] = {
                "summary_text": "The cache was updated with the following values:",
                "report_fields": ["name", "package_name", "version", "gamma_policy_id"],
                "data": {
                    "name": self.pst.pstName,
                    "package_name": self.pst.generalPkg["name"],
                    "version": self.pst.generalPkg["version"],
                    "gamma_policy_id": check["policyID"],
                },
            }
        # not to test Set cache?
        self.EnvObject.logger.info("Leaving gammaPatch.")
        self.EnvObject.logger.info(
            "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
        )
        return 0


class Prod:
    def __init__(self, EnvObject, PSTObject, cache):
        EnvObject.logger.info("Starting Prod init...")
        ##Constructor(initializer) that activates when an object is created
        self.EnvObject = EnvObject
        self.pst = PSTObject
        self.distributionMethod = self.EnvObject.env.get("prodDistributionMethod")
        self.cacheVersion = cache["version"]
        self.appName = cache["name"]
        EnvObject.logger.info("Leaving Prod init.")

    def prodPatch(self):
        self.EnvObject.logger.info(
            "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
        )
        self.EnvObject.logger.info("Starting prodPatch...")
        ##Function that holds the logic to move policy to production
        policyName = "Production"
        if not self.pst.checkPolicyExist("Production"):
            self.EnvObject.logger.info(
                "Did not find PST Policy Production, creating policy now..."
            )
            policyCreated = self.pst.createPolicy(
                appName=self.appName,
                policyName=policyName,
                definitionVersion=self.cacheVersion,
                distributionMethod=self.distributionMethod,
            )
            if policyCreated != 0:
                self.EnvObject.logger.error("PROD POLICY WAS NOT CREATED!")
                return 1
            else:
                self.EnvObject.logger.info(
                    "Prod policy created and update check can be skipped."
                )
                self.EnvObject.env["pstpolicy_summary_result"] = {
                    "summary_text": "Prod was created with the following values:",
                    "report_fields": ["app_name", "policy_name", "version"],
                    "data": {
                        "app_name": self.appName,
                        "policy_name": policyName,
                        "version": self.pst.generalPkg["version"],
                    },
                }
                return 0
        check = self.pst.checkPolicyVersion(
            policyName=policyName, definitionVersion=self.cacheVersion
        )
        if not check["status"]:
            updateComplete = self.pst.updatePolicyVersion(
                policyID=check["policyID"], definitionVersion=self.cacheVersion
            )
            if updateComplete != 0:
                self.EnvObject.logger.error("POLICY UPDATED FAILED!")
                return 1
            self.EnvObject.env["pstpolicy_summary_result"] = {
                "summary_text": "Prod was updated with the following values:",
                "report_fields": ["app_name", "policy_name", "version"],
                "data": {
                    "app_name": self.appName,
                    "policy_name": policyName,
                    "version": self.pst.generalPkg["version"],
                },
            }
        self.EnvObject.logger.info("Leaving prodPatch.")
        return 0


class APM(URLGetter):
    """This processor takes a general policy that is made by some other recipe and then moves that package to JAMFs Patch management
    Definitions and policies. In policies it creates and sets up a testing policy, the user is required to set the scope,
    it also creates a production policy that does the same thing, and again the user has to setup scope."""

    description = __doc__

    input_variables = {
        "applicationTitle": {
            "required": True,
            "description": "The name of the application",
        },
        "generalPolicyName": {
            "required": True,
            "description": "The name of the policy that we pull the filename from",
        },
        "patchSoftwareTitle": {
            "required": True,
            "description": "The name of the patch software title we need to use to check PST policies",
        },
        "productionDelay": {
            "required": False,
            "description": "The length in days to wait to go from test to prod",
        },
        "gammaDistributionMethod": {
            "required": False,
            "description": "The method for distribution (Selfservice/automatic(prompt))",
        },
        "prodDistributionMethod": {
            "required": False,
            "description": "The method for distribution (Selfservice (prompt)/automatic)",
        },
    }
    output_variables = {
        "patch_manager_summary_result": {"description": "Summary of action"},
        "cache_summary_result": {"description": "Summary of cache creation or update."},
        "gamma_policy_summary_result": {
            "description": "Summary of gamma policy creation or update."
        },
        "pstpolicy_summary_result": {
            "description": "Summary of gamma policy creation or update."
        },
    }

    def setup_logging(self):
        """Defines a nicely formatted logger"""
        cachePath = self.env.get("RECIPE_CACHE_DIR")
        application = self.env.get("applicationTitle")
        LOGFILE = f"{cachePath}/{application}.log"
        if not os.path.exists(LOGFILE):
            with open(LOGFILE, "w") as outfile:
                pass
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
        self.setup_logging()
        self.logger.info(
            "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
        )
        self.logger.info("Starting APM main...")
        if "gamma_summary_result" in self.env:
            del self.env["gamma_summary_result"]
        if "cache_summary_result" in self.env:
            del self.env["cache_summary_result"]
        if "pstpolicy_summary_result" in self.env:
            del self.env["pstpolicy_summary_result"]
        print("Setting up Cache ...")
        mainCache = Cache(self)
        print("Setting up PST ...")
        pst = PST(self)
        cache = mainCache.get()
        if cache["version"] != "":
            self.logger.info("Cache load version successful, checking delta...")
            deltaInSeconds = 60 * 60 * 24 * int(self.env.get("productionDelay"))
            if time.time() + deltaInSeconds < cache["date"]:
                self.logger.info("Delta time has elapsed running prod...")
                print("Delta time has elapsed running prod...")
                prod = Prod(self, pst, cache)
                prod.prodPatch()
            else:
                self.logger.info(
                    "Production Delay time has not been met, skipping production."
                )
                print("Production Delay time has not been met, skipping production.")
        else:
            self.logger.info("Cached version is empty so Production was skipped.")
            print("Cached version is empty so Production was skipped.")
        print("Setting up Gamma...")
        gamma = Gamma(self, pst)
        print("Running Gamma ...")
        gamma.gammaPatch()
        self.logger.info("Leaving APM main.")
        print("Leaving APM main.")
        self.logger.info(
            "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
        )


if __name__ == "__main__":
    PROCESSOR = APM()
    PROCESSOR.execute_shell()
