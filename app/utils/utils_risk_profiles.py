from app.models import *
# from app.utils import  *
from sqlalchemy import exists
import json
import os

# region Threat Estimation calls  @@@@@@@@@@@@@
# 1 RiskML, 2 Reputation, 3 DB, 4 DSS forecasting
# region 1 RiskML
from app.utils.utils_communication import get_ml_flow_info


def get_RiskML_value(asset_type, threat, estimation_type, port, experiment):
    # action = {Hacking, Social, Malware, Physical, Error}
    # action.variety = {M.Ransomware, H.DoS, H.SQL, H Brute force, H.Use of backdoor or C2}
    # asset.variety = {Server, User Device, Person, Media}
    # asset.asset.variety = {S.Database, S.Web.application, U.Desctop or laptop}
    # attribute = {Confidenciality,availability,integrity}
    print("To start", flush=True)
    # Get root directory to save json input in correct path
    current_dict = os.getcwd()
    root_dir = os.path.join(current_dict, "mlflow_info")

    # Get from server current json input still containing junk data
    # get_ml_flow_info(experiment, root_dir)

    # URL to get actual values for this experiment (selected experiment depends on port)
    url = "http://mlflow_code:" + port + "/invocations"
    print( current_dict, "mlflow_info", experiment, "model", "input_example.json", flush = True)
    dict_to_load_path = os.path.join(current_dict, "mlflow_info", experiment, "model", "input_example.json")
    # Remove junk info from input json
    file_json = open(dict_to_load_path)
    json_to_send = json.load(file_json)

    print(json_to_send, flush=True)
    to_clean_data = json_to_send["data"][0]
    print(to_clean_data, flush=True)
    for it,entry in enumerate(to_clean_data):
        if entry == True:
            to_clean_data[it] = False

    print(json_to_send, flush=True)


    if (estimation_type == 'action'):
        for asset_name in asset_type:
            paramlist = json_to_send["columns"]
            valuelist = json_to_send["data"][0]
            findindex = paramlist.index(asset_name)
            valuelist[findindex] = True
            print(json_to_send, flush=True)

            # str = {"columns": paramlist, "data": [valuelist]}
            # print(json.dumps(str))
            # return json.dumps(str)
    elif (estimation_type == 'action.x.variety'):
        paramlist = ["asset.variety.Embedded", "asset.variety.Kiosk/Term", "asset.variety.Media",
                     "asset.variety.Network", "asset.variety.Person", "asset.variety.Server", "asset.variety.User Dev",
                     "asset.assets.variety.E - Other", "asset.assets.variety.E - Telematics",
                     "asset.assets.variety.E - Telemetry", "asset.assets.variety.M - Disk drive",
                     "asset.assets.variety.M - Disk media", "asset.assets.variety.M - Documents",
                     "asset.assets.variety.M - Fax", "asset.assets.variety.M - Flash drive",
                     "asset.assets.variety.M - Other", "asset.assets.variety.M - Payment card",
                     "asset.assets.variety.M - Smart card", "asset.assets.variety.M - Tapes",
                     "asset.assets.variety.N - Access reader", "asset.assets.variety.N - Broadband",
                     "asset.assets.variety.N - Camera", "asset.assets.variety.N - Firewall",
                     "asset.assets.variety.N - HSM", "asset.assets.variety.N - IDS", "asset.assets.variety.N - LAN",
                     "asset.assets.variety.N - NAS", "asset.assets.variety.N - Other", "asset.assets.variety.N - PBX",
                     "asset.assets.variety.N - PLC", "asset.assets.variety.N - Private WAN",
                     "asset.assets.variety.N - Public WAN", "asset.assets.variety.N - RTU",
                     "asset.assets.variety.N - Router or switch", "asset.assets.variety.N - SAN",
                     "asset.assets.variety.N - Telephone", "asset.assets.variety.N - VoIP adapter",
                     "asset.assets.variety.N - WLAN", "asset.assets.variety.Other", "asset.assets.variety.P - Auditor",
                     "asset.assets.variety.P - Call center", "asset.assets.variety.P - Cashier",
                     "asset.assets.variety.P - Customer", "asset.assets.variety.P - Developer",
                     "asset.assets.variety.P - End-user", "asset.assets.variety.P - End-user or employee",
                     "asset.assets.variety.P - Executive", "asset.assets.variety.P - Finance",
                     "asset.assets.variety.P - Former employee", "asset.assets.variety.P - Guard",
                     "asset.assets.variety.P - Helpdesk", "asset.assets.variety.P - Human resources",
                     "asset.assets.variety.P - Maintenance", "asset.assets.variety.P - Manager",
                     "asset.assets.variety.P - Other", "asset.assets.variety.P - Other employee",
                     "asset.assets.variety.P - Partner", "asset.assets.variety.P - System admin",
                     "asset.assets.variety.S - Authentication", "asset.assets.variety.S - Backup",
                     "asset.assets.variety.S - Code repository",
                     "asset.assets.variety.S - Configuration or patch management", "asset.assets.variety.S - DCS",
                     "asset.assets.variety.S - DHCP", "asset.assets.variety.S - DNS",
                     "asset.assets.variety.S - Database", "asset.assets.variety.S - Directory",
                     "asset.assets.variety.S - File", "asset.assets.variety.S - ICS", "asset.assets.variety.S - Log",
                     "asset.assets.variety.S - Mail", "asset.assets.variety.S - Mainframe",
                     "asset.assets.variety.S - Other", "asset.assets.variety.S - POS controller",
                     "asset.assets.variety.S - Payment switch", "asset.assets.variety.S - Print",
                     "asset.assets.variety.S - Proxy", "asset.assets.variety.S - Remote access",
                     "asset.assets.variety.S - VM host", "asset.assets.variety.S - Web application",
                     "asset.assets.variety.T - ATM", "asset.assets.variety.T - Gas terminal",
                     "asset.assets.variety.T - Kiosk", "asset.assets.variety.T - Other",
                     "asset.assets.variety.T - PED pad", "asset.assets.variety.U - Auth token",
                     "asset.assets.variety.U - Desktop", "asset.assets.variety.U - Desktop or laptop",
                     "asset.assets.variety.U - Laptop", "asset.assets.variety.U - Media",
                     "asset.assets.variety.U - Mobile phone", "asset.assets.variety.U - Other",
                     "asset.assets.variety.U - POS terminal", "asset.assets.variety.U - Peripheral",
                     "asset.assets.variety.U - Tablet", "asset.assets.variety.U - Telephone",
                     "asset.assets.variety.U - VoIP phone", "action.Error", "action.Hacking", "action.Malware",
                     "action.Misuse", "action.Physical", "action.Social", "victim.orgsize.Large",
                     "victim.industry.name"]
        valuelist = [False, False, False, False, False, False, False, False, False, False, False, False, False, False,
                     False, False, False, False, False, False, False, False, False, False, False, False, False, False,
                     False, False, False, False, False, False, False, False, False, False, False, False, False, False,
                     False, False, False, False, False, False, False, False, False, False, False, False, False, False,
                     False, False, False, False, False, False, False, False, False, False, False, False, False, False,
                     False, False, False, False, False, False, False, False, False, False, False, False, False, False,
                     False, False, False, False, False, False, False, False, False, False, False, False, False, False,
                     False, False, False, False, False, False, "Healthcare"]
        return -1
    elif (estimation_type == 'asset.variety'):
        paramlist = ["action.Error", "action.Hacking", "action.Malware", "action.Misuse", "action.Physical",
                     "action.Social", "action.error.variety.Capacity shortage",
                     "action.error.variety.Classification error", "action.error.variety.Data entry error",
                     "action.error.variety.Disposal error", "action.error.variety.Gaffe", "action.error.variety.Loss",
                     "action.error.variety.Maintenance error", "action.error.variety.Malfunction",
                     "action.error.variety.Misconfiguration", "action.error.variety.Misdelivery",
                     "action.error.variety.Misinformation", "action.error.variety.Omission",
                     "action.error.variety.Other", "action.error.variety.Physical accidents",
                     "action.error.variety.Programming error", "action.error.variety.Publishing error",
                     "action.hacking.variety.Abuse of functionality", "action.hacking.variety.Brute force",
                     "action.hacking.variety.Buffer overflow", "action.hacking.variety.CSRF",
                     "action.hacking.variety.Cache poisoning", "action.hacking.variety.Cryptanalysis",
                     "action.hacking.variety.DoS", "action.hacking.variety.Exploit misconfig",
                     "action.hacking.variety.Exploit vuln", "action.hacking.variety.Footprinting",
                     "action.hacking.variety.Forced browsing", "action.hacking.variety.Format string attack",
                     "action.hacking.variety.Fuzz testing", "action.hacking.variety.HTTP Response Splitting",
                     "action.hacking.variety.HTTP request smuggling", "action.hacking.variety.HTTP request splitting",
                     "action.hacking.variety.HTTP response smuggling",
                     "action.hacking.variety.Insecure deserialization", "action.hacking.variety.Integer overflows",
                     "action.hacking.variety.LDAP injection", "action.hacking.variety.Mail command injection",
                     "action.hacking.variety.MitM", "action.hacking.variety.Null byte injection",
                     "action.hacking.variety.OS commanding", "action.hacking.variety.Offline cracking",
                     "action.hacking.variety.Other", "action.hacking.variety.Pass-the-hash",
                     "action.hacking.variety.Path traversal", "action.hacking.variety.RFI",
                     "action.hacking.variety.Reverse engineering", "action.hacking.variety.Routing detour",
                     "action.hacking.variety.SQLi", "action.hacking.variety.SSI injection",
                     "action.hacking.variety.Session fixation", "action.hacking.variety.Session prediction",
                     "action.hacking.variety.Session replay", "action.hacking.variety.Soap array abuse",
                     "action.hacking.variety.Special element injection", "action.hacking.variety.URL redirector abuse",
                     "action.hacking.variety.Use of backdoor or C2", "action.hacking.variety.Use of stolen creds",
                     "action.hacking.variety.User breakout", "action.hacking.variety.Virtual machine escape",
                     "action.hacking.variety.XML attribute blowup", "action.hacking.variety.XML entity expansion",
                     "action.hacking.variety.XML external entities", "action.hacking.variety.XML injection",
                     "action.hacking.variety.XPath injection", "action.hacking.variety.XQuery injection",
                     "action.hacking.variety.XSS", "action.malware.variety.Adminware", "action.malware.variety.Adware",
                     "action.malware.variety.Capture app data", "action.malware.variety.Capture stored data",
                     "action.malware.variety.Click fraud",
                     "action.malware.variety.Click fraud and cryptocurrency mining",
                     "action.malware.variety.Client-side attack", "action.malware.variety.Cryptocurrency mining",
                     "action.malware.variety.Destroy data", "action.malware.variety.Disable controls",
                     "action.malware.variety.Downloader", "action.malware.variety.Exploit misconfig",
                     "action.malware.variety.Exploit vuln", "action.malware.variety.Export data",
                     "action.malware.variety.In-memory", "action.malware.variety.Modify data",
                     "action.malware.variety.Other", "action.malware.variety.Packet sniffer",
                     "action.malware.variety.Password dumper", "action.malware.variety.RAM scraper",
                     "action.malware.variety.RAT", "action.malware.variety.Ransomware",
                     "action.malware.variety.Rootkit", "action.malware.variety.Scan network",
                     "action.malware.variety.Spam", "action.malware.variety.Spyware/Keylogger",
                     "action.malware.variety.Trojan", "action.malware.variety.Worm",
                     "action.misuse.variety.Data mishandling", "action.misuse.variety.Email misuse",
                     "action.misuse.variety.Illicit content", "action.misuse.variety.Knowledge abuse",
                     "action.misuse.variety.Net misuse", "action.misuse.variety.Other",
                     "action.misuse.variety.Possession abuse", "action.misuse.variety.Privilege abuse",
                     "action.misuse.variety.Snap picture", "action.misuse.variety.Unapproved hardware",
                     "action.misuse.variety.Unapproved software", "action.misuse.variety.Unapproved workaround",
                     "action.physical.variety.Assault", "action.physical.variety.Bypassed controls",
                     "action.physical.variety.Connection", "action.physical.variety.Destruction",
                     "action.physical.variety.Disabled controls", "action.physical.variety.Other",
                     "action.physical.variety.Skimmer", "action.physical.variety.Snooping",
                     "action.physical.variety.Surveillance", "action.physical.variety.Tampering",
                     "action.physical.variety.Theft", "action.physical.variety.Wiretapping",
                     "action.social.variety.Baiting", "action.social.variety.Bribery",
                     "action.social.variety.Elicitation", "action.social.variety.Extortion",
                     "action.social.variety.Forgery", "action.social.variety.Influence", "action.social.variety.Other",
                     "action.social.variety.Phishing", "action.social.variety.Pretexting",
                     "action.social.variety.Propaganda", "action.social.variety.Scam", "action.social.variety.Spam",
                     "victim.orgsize.Large", "victim.industry.name"]
        valuelist = [False, False, False, False, False, False, False, False, False, False, False, False, False, False,
                     False, False, False, False, False, False, False, False, False, False, False, False, False, False,
                     False, False, False, False, False, False, False, False, False, False, False, False, False, False,
                     False, False, False, False, False, False, False, False, False, False, False, False, False, False,
                     False, False, False, False, False, False, False, False, False, False, False, False, False, False,
                     False, False, False, False, False, False, False, False, False, False, False, False, False, False,
                     False, False, False, False, False, False, False, False, False, False, False, False, False, False,
                     False, False, False, False, False, False, False, False, False, False, False, False, False, False,
                     False, False, False, False, False, False, False, False, False, False, False, False, False, False,
                     False, False, False, False, False, False, False, False, False, False, False, "Healthcare"]
        return -1
    elif (estimation_type == 'asset.assets.variety'):
        paramlist = ["asset.variety.Embedded", "asset.variety.Kiosk/Term", "asset.variety.Media",
                     "asset.variety.Network", "asset.variety.Person", "asset.variety.Server", "asset.variety.User Dev",
                     "action.Error", "action.Hacking", "action.Malware", "action.Misuse", "action.Physical",
                     "action.Social", "action.error.variety.Capacity shortage",
                     "action.error.variety.Classification error", "action.error.variety.Data entry error",
                     "action.error.variety.Disposal error", "action.error.variety.Gaffe", "action.error.variety.Loss",
                     "action.error.variety.Maintenance error", "action.error.variety.Malfunction",
                     "action.error.variety.Misconfiguration", "action.error.variety.Misdelivery",
                     "action.error.variety.Misinformation", "action.error.variety.Omission",
                     "action.error.variety.Other", "action.error.variety.Physical accidents",
                     "action.error.variety.Programming error", "action.error.variety.Publishing error",
                     "action.hacking.variety.Abuse of functionality", "action.hacking.variety.Brute force",
                     "action.hacking.variety.Buffer overflow", "action.hacking.variety.CSRF",
                     "action.hacking.variety.Cache poisoning", "action.hacking.variety.Cryptanalysis",
                     "action.hacking.variety.DoS", "action.hacking.variety.Exploit misconfig",
                     "action.hacking.variety.Exploit vuln", "action.hacking.variety.Footprinting",
                     "action.hacking.variety.Forced browsing", "action.hacking.variety.Format string attack",
                     "action.hacking.variety.Fuzz testing", "action.hacking.variety.HTTP Response Splitting",
                     "action.hacking.variety.HTTP request smuggling", "action.hacking.variety.HTTP request splitting",
                     "action.hacking.variety.HTTP response smuggling",
                     "action.hacking.variety.Insecure deserialization", "action.hacking.variety.Integer overflows",
                     "action.hacking.variety.LDAP injection", "action.hacking.variety.Mail command injection",
                     "action.hacking.variety.MitM", "action.hacking.variety.Null byte injection",
                     "action.hacking.variety.OS commanding", "action.hacking.variety.Offline cracking",
                     "action.hacking.variety.Other", "action.hacking.variety.Pass-the-hash",
                     "action.hacking.variety.Path traversal", "action.hacking.variety.RFI",
                     "action.hacking.variety.Reverse engineering", "action.hacking.variety.Routing detour",
                     "action.hacking.variety.SQLi", "action.hacking.variety.SSI injection",
                     "action.hacking.variety.Session fixation", "action.hacking.variety.Session prediction",
                     "action.hacking.variety.Session replay", "action.hacking.variety.Soap array abuse",
                     "action.hacking.variety.Special element injection", "action.hacking.variety.URL redirector abuse",
                     "action.hacking.variety.Use of backdoor or C2", "action.hacking.variety.Use of stolen creds",
                     "action.hacking.variety.User breakout", "action.hacking.variety.Virtual machine escape",
                     "action.hacking.variety.XML attribute blowup", "action.hacking.variety.XML entity expansion",
                     "action.hacking.variety.XML external entities", "action.hacking.variety.XML injection",
                     "action.hacking.variety.XPath injection", "action.hacking.variety.XQuery injection",
                     "action.hacking.variety.XSS", "action.malware.variety.Adminware", "action.malware.variety.Adware",
                     "action.malware.variety.Capture app data", "action.malware.variety.Capture stored data",
                     "action.malware.variety.Click fraud",
                     "action.malware.variety.Click fraud and cryptocurrency mining",
                     "action.malware.variety.Client-side attack", "action.malware.variety.Cryptocurrency mining",
                     "action.malware.variety.Destroy data", "action.malware.variety.Disable controls",
                     "action.malware.variety.Downloader", "action.malware.variety.Exploit misconfig",
                     "action.malware.variety.Exploit vuln", "action.malware.variety.Export data",
                     "action.malware.variety.In-memory", "action.malware.variety.Modify data",
                     "action.malware.variety.Other", "action.malware.variety.Packet sniffer",
                     "action.malware.variety.Password dumper", "action.malware.variety.RAM scraper",
                     "action.malware.variety.RAT", "action.malware.variety.Ransomware",
                     "action.malware.variety.Rootkit", "action.malware.variety.Scan network",
                     "action.malware.variety.Spam", "action.malware.variety.Spyware/Keylogger",
                     "action.malware.variety.Trojan", "action.malware.variety.Worm",
                     "action.misuse.variety.Data mishandling", "action.misuse.variety.Email misuse",
                     "action.misuse.variety.Illicit content", "action.misuse.variety.Knowledge abuse",
                     "action.misuse.variety.Net misuse", "action.misuse.variety.Other",
                     "action.misuse.variety.Possession abuse", "action.misuse.variety.Privilege abuse",
                     "action.misuse.variety.Snap picture", "action.misuse.variety.Unapproved hardware",
                     "action.misuse.variety.Unapproved software", "action.misuse.variety.Unapproved workaround",
                     "action.physical.variety.Assault", "action.physical.variety.Bypassed controls",
                     "action.physical.variety.Connection", "action.physical.variety.Destruction",
                     "action.physical.variety.Disabled controls", "action.physical.variety.Other",
                     "action.physical.variety.Skimmer", "action.physical.variety.Snooping",
                     "action.physical.variety.Surveillance", "action.physical.variety.Tampering",
                     "action.physical.variety.Theft", "action.physical.variety.Wiretapping",
                     "action.social.variety.Baiting", "action.social.variety.Bribery",
                     "action.social.variety.Elicitation", "action.social.variety.Extortion",
                     "action.social.variety.Forgery", "action.social.variety.Influence", "action.social.variety.Other",
                     "action.social.variety.Phishing", "action.social.variety.Pretexting",
                     "action.social.variety.Propaganda", "action.social.variety.Scam", "action.social.variety.Spam",
                     "victim.orgsize.Large", "victim.industry.name"]
        valuelist = [False, False, False, False, False, False, False, False, False, False, False, False, False, False,
                     False, False, False, False, False, False, False, False, False, False, False, False, False, False,
                     False, False, False, False, False, False, False, False, False, False, False, False, False, False,
                     False, False, False, False, False, False, False, False, False, False, False, False, False, False,
                     False, False, False, False, False, False, False, False, False, False, False, False, False, False,
                     False, False, False, False, False, False, False, False, False, False, False, False, False, False,
                     False, False, False, False, False, False, False, False, False, False, False, False, False, False,
                     False, False, False, False, False, False, False, False, False, False, False, False, False, False,
                     False, False, False, False, False, False, False, False, False, False, False, False, False, False,
                     False, False, False, False, False, False, False, False, False, False, False, False, False, False,
                     False, False, False, False, "Healthcare"]
        return -1
    elif (estimation_type == 'attribute'):
        paramlist = ["asset.variety.Embedded", "asset.variety.Kiosk/Term", "asset.variety.Media",
                     "asset.variety.Network", "asset.variety.Person", "asset.variety.Server", "asset.variety.User Dev",
                     "asset.assets.variety.E - Other", "asset.assets.variety.E - Telematics",
                     "asset.assets.variety.E - Telemetry", "asset.assets.variety.M - Disk drive",
                     "asset.assets.variety.M - Disk media", "asset.assets.variety.M - Documents",
                     "asset.assets.variety.M - Fax", "asset.assets.variety.M - Flash drive",
                     "asset.assets.variety.M - Other", "asset.assets.variety.M - Payment card",
                     "asset.assets.variety.M - Smart card", "asset.assets.variety.M - Tapes",
                     "asset.assets.variety.N - Access reader", "asset.assets.variety.N - Broadband",
                     "asset.assets.variety.N - Camera", "asset.assets.variety.N - Firewall",
                     "asset.assets.variety.N - HSM", "asset.assets.variety.N - IDS", "asset.assets.variety.N - LAN",
                     "asset.assets.variety.N - NAS", "asset.assets.variety.N - Other", "asset.assets.variety.N - PBX",
                     "asset.assets.variety.N - PLC", "asset.assets.variety.N - Private WAN",
                     "asset.assets.variety.N - Public WAN", "asset.assets.variety.N - RTU",
                     "asset.assets.variety.N - Router or switch", "asset.assets.variety.N - SAN",
                     "asset.assets.variety.N - Telephone", "asset.assets.variety.N - VoIP adapter",
                     "asset.assets.variety.N - WLAN", "asset.assets.variety.Other", "asset.assets.variety.P - Auditor",
                     "asset.assets.variety.P - Call center", "asset.assets.variety.P - Cashier",
                     "asset.assets.variety.P - Customer", "asset.assets.variety.P - Developer",
                     "asset.assets.variety.P - End-user", "asset.assets.variety.P - End-user or employee",
                     "asset.assets.variety.P - Executive", "asset.assets.variety.P - Finance",
                     "asset.assets.variety.P - Former employee", "asset.assets.variety.P - Guard",
                     "asset.assets.variety.P - Helpdesk", "asset.assets.variety.P - Human resources",
                     "asset.assets.variety.P - Maintenance", "asset.assets.variety.P - Manager",
                     "asset.assets.variety.P - Other", "asset.assets.variety.P - Other employee",
                     "asset.assets.variety.P - Partner", "asset.assets.variety.P - System admin",
                     "asset.assets.variety.S - Authentication", "asset.assets.variety.S - Backup",
                     "asset.assets.variety.S - Code repository",
                     "asset.assets.variety.S - Configuration or patch management", "asset.assets.variety.S - DCS",
                     "asset.assets.variety.S - DHCP", "asset.assets.variety.S - DNS",
                     "asset.assets.variety.S - Database", "asset.assets.variety.S - Directory",
                     "asset.assets.variety.S - File", "asset.assets.variety.S - ICS", "asset.assets.variety.S - Log",
                     "asset.assets.variety.S - Mail", "asset.assets.variety.S - Mainframe",
                     "asset.assets.variety.S - Other", "asset.assets.variety.S - POS controller",
                     "asset.assets.variety.S - Payment switch", "asset.assets.variety.S - Print",
                     "asset.assets.variety.S - Proxy", "asset.assets.variety.S - Remote access",
                     "asset.assets.variety.S - VM host", "asset.assets.variety.S - Web application",
                     "asset.assets.variety.T - ATM", "asset.assets.variety.T - Gas terminal",
                     "asset.assets.variety.T - Kiosk", "asset.assets.variety.T - Other",
                     "asset.assets.variety.T - PED pad", "asset.assets.variety.U - Auth token",
                     "asset.assets.variety.U - Desktop", "asset.assets.variety.U - Desktop or laptop",
                     "asset.assets.variety.U - Laptop", "asset.assets.variety.U - Media",
                     "asset.assets.variety.U - Mobile phone", "asset.assets.variety.U - Other",
                     "asset.assets.variety.U - POS terminal", "asset.assets.variety.U - Peripheral",
                     "asset.assets.variety.U - Tablet", "asset.assets.variety.U - Telephone",
                     "asset.assets.variety.U - VoIP phone", "action.Error", "action.Hacking", "action.Malware",
                     "action.Misuse", "action.Physical", "action.Social", "action.error.variety.Capacity shortage",
                     "action.error.variety.Classification error", "action.error.variety.Data entry error",
                     "action.error.variety.Disposal error", "action.error.variety.Gaffe", "action.error.variety.Loss",
                     "action.error.variety.Maintenance error", "action.error.variety.Malfunction",
                     "action.error.variety.Misconfiguration", "action.error.variety.Misdelivery",
                     "action.error.variety.Misinformation", "action.error.variety.Omission",
                     "action.error.variety.Other", "action.error.variety.Physical accidents",
                     "action.error.variety.Programming error", "action.error.variety.Publishing error",
                     "action.hacking.variety.Abuse of functionality", "action.hacking.variety.Brute force",
                     "action.hacking.variety.Buffer overflow", "action.hacking.variety.CSRF",
                     "action.hacking.variety.Cache poisoning", "action.hacking.variety.Cryptanalysis",
                     "action.hacking.variety.DoS", "action.hacking.variety.Exploit misconfig",
                     "action.hacking.variety.Exploit vuln", "action.hacking.variety.Footprinting",
                     "action.hacking.variety.Forced browsing", "action.hacking.variety.Format string attack",
                     "action.hacking.variety.Fuzz testing", "action.hacking.variety.HTTP Response Splitting",
                     "action.hacking.variety.HTTP request smuggling", "action.hacking.variety.HTTP request splitting",
                     "action.hacking.variety.HTTP response smuggling",
                     "action.hacking.variety.Insecure deserialization", "action.hacking.variety.Integer overflows",
                     "action.hacking.variety.LDAP injection", "action.hacking.variety.Mail command injection",
                     "action.hacking.variety.MitM", "action.hacking.variety.Null byte injection",
                     "action.hacking.variety.OS commanding", "action.hacking.variety.Offline cracking",
                     "action.hacking.variety.Other", "action.hacking.variety.Pass-the-hash",
                     "action.hacking.variety.Path traversal", "action.hacking.variety.RFI",
                     "action.hacking.variety.Reverse engineering", "action.hacking.variety.Routing detour",
                     "action.hacking.variety.SQLi", "action.hacking.variety.SSI injection",
                     "action.hacking.variety.Session fixation", "action.hacking.variety.Session prediction",
                     "action.hacking.variety.Session replay", "action.hacking.variety.Soap array abuse",
                     "action.hacking.variety.Special element injection", "action.hacking.variety.URL redirector abuse",
                     "action.hacking.variety.Use of backdoor or C2", "action.hacking.variety.Use of stolen creds",
                     "action.hacking.variety.User breakout", "action.hacking.variety.Virtual machine escape",
                     "action.hacking.variety.XML attribute blowup", "action.hacking.variety.XML entity expansion",
                     "action.hacking.variety.XML external entities", "action.hacking.variety.XML injection",
                     "action.hacking.variety.XPath injection", "action.hacking.variety.XQuery injection",
                     "action.hacking.variety.XSS", "action.malware.variety.Adminware", "action.malware.variety.Adware",
                     "action.malware.variety.Capture app data", "action.malware.variety.Capture stored data",
                     "action.malware.variety.Click fraud",
                     "action.malware.variety.Click fraud and cryptocurrency mining",
                     "action.malware.variety.Client-side attack", "action.malware.variety.Cryptocurrency mining",
                     "action.malware.variety.Destroy data", "action.malware.variety.Disable controls",
                     "action.malware.variety.Downloader", "action.malware.variety.Exploit misconfig",
                     "action.malware.variety.Exploit vuln", "action.malware.variety.Export data",
                     "action.malware.variety.In-memory", "action.malware.variety.Modify data",
                     "action.malware.variety.Other", "action.malware.variety.Packet sniffer",
                     "action.malware.variety.Password dumper", "action.malware.variety.RAM scraper",
                     "action.malware.variety.RAT", "action.malware.variety.Ransomware",
                     "action.malware.variety.Rootkit", "action.malware.variety.Scan network",
                     "action.malware.variety.Spam", "action.malware.variety.Spyware/Keylogger",
                     "action.malware.variety.Trojan", "action.malware.variety.Worm",
                     "action.misuse.variety.Data mishandling", "action.misuse.variety.Email misuse",
                     "action.misuse.variety.Illicit content", "action.misuse.variety.Knowledge abuse",
                     "action.misuse.variety.Net misuse", "action.misuse.variety.Other",
                     "action.misuse.variety.Possession abuse", "action.misuse.variety.Privilege abuse",
                     "action.misuse.variety.Snap picture", "action.misuse.variety.Unapproved hardware",
                     "action.misuse.variety.Unapproved software", "action.misuse.variety.Unapproved workaround",
                     "action.physical.variety.Assault", "action.physical.variety.Bypassed controls",
                     "action.physical.variety.Connection", "action.physical.variety.Destruction",
                     "action.physical.variety.Disabled controls", "action.physical.variety.Other",
                     "action.physical.variety.Skimmer", "action.physical.variety.Snooping",
                     "action.physical.variety.Surveillance", "action.physical.variety.Tampering",
                     "action.physical.variety.Theft", "action.physical.variety.Wiretapping",
                     "action.social.variety.Baiting", "action.social.variety.Bribery",
                     "action.social.variety.Elicitation", "action.social.variety.Extortion",
                     "action.social.variety.Forgery", "action.social.variety.Influence", "action.social.variety.Other",
                     "action.social.variety.Phishing", "action.social.variety.Pretexting",
                     "action.social.variety.Propaganda", "action.social.variety.Scam", "action.social.variety.Spam",
                     "victim.orgsize.Large", "victim.industry.name"]
        valuelist = [False, False, False, False, False, False, False, False, False, False, False, False, False, False,
                     False, False, False, False, False, False, False, False, False, False, False, False, False, False,
                     False, False, False, False, False, False, False, False, False, False, False, False, False, False,
                     False, False, False, False, False, False, False, False, False, False, False, False, False, False,
                     False, False, False, False, False, False, False, False, False, False, False, False, False, False,
                     False, False, False, False, False, False, False, False, False, False, False, False, False, False,
                     False, False, False, False, False, False, False, False, False, False, False, False, False, False,
                     False, False, False, False, False, False, False, False, False, False, False, False, False, False,
                     False, False, False, False, False, False, False, False, False, False, False, False, False, False,
                     False, False, False, False, False, False, False, False, False, False, False, False, False, False,
                     False, False, False, False, False, False, False, False, False, False, False, False, False, False,
                     False, False, False, False, False, False, False, False, False, False, False, False, False, False,
                     False, False, False, False, False, False, False, False, False, False, False, False, False, False,
                     False, False, False, False, False, False, False, False, False, False, False, False, False, False,
                     False, False, False, False, False, False, False, False, False, False, False, False, False, False,
                     False, False, False, False, False, False, False, False, False, False, False, False, False, False,
                     False, False, False, False, False, False, False, False, False, False, "Healthcare"]
        return -1
    else:
        return -1

    # TODO remove return when wanting to call the
    return
    headers = {
        'Content-Type': 'application/json'
    }
    payload = json.dumps()
    response = requests.request("POST", url, headers=headers, data=payload)
# endregion 1 RiskML
# region 2 Reputation
#     TODO: "provide API to get the estimation"
def get_Threat_Estimation_BBTR():
    return -1


# endregion 2 Reputation
# region 3 DB
def get_ThreatFactorsvaluesfromDB(assetID, threatID):
    if db.session.query(exists().where((RepoAssetRepoThreatRelationship.repo_asset_id == assetID) and (
            RepoAssetRepoThreatRelationship.repo_threat_id == threatID))).scalar():
        my_asset_threat = db.session.query(RepoAssetRepoThreatRelationship).filter(
            RepoAssetRepoThreatRelationship.repo_asset_id == assetID,
            RepoAssetRepoThreatRelationship.repo_threat_id == threatID).first()
        if isinstance(my_asset_threat.risk_skill_level, (int, float)) and isinstance(my_asset_threat.risk_motive,
                                                                                     (int, float)) and isinstance(
                my_asset_threat.risk_source, (int, float)) and isinstance(my_asset_threat.risk_actor,
                                                                          (int, float)) and isinstance(
                my_asset_threat.risk_opportunity, (int, float)):
            result = (
                                 my_asset_threat.risk_skill_level + my_asset_threat.risk_motive + my_asset_threat.risk_source + my_asset_threat.risk_actor + my_asset_threat.risk_opportunity) / 500
        return result
    else:
        return -1


# endregion 3 DB

# region 4 DSS forecasting
#     TODO: "call API to get the estimation from DSS. Do we have this?"
# endregion 4 DSS forecasting
# region return final estimation
#     TODO: "call functions"

def get_Threat_exposure_value(assetID, threatID):
    i = 0
    # TODO: The SIEM_threat_ID must be converted into RCRA_threat_ID
    # This call needs RCRA_Threat_ID
    value_DB = get_ThreatFactorsvaluesfromDB(assetID, threatID)
    if not value_DB == -1:
        i += 1
    else:
        value_DB = 0
    # This call needs SIEM_Threat_ID
    value_BBTR = get_Threat_Estimation_BBTR()
    if not value_BBTR == -1:
        i += 1
    else:
        value_BBTR = 0

    # This call needs RCRA_Threat_ID
    if (threatID == 1):
        # Malware
        url = "http://127.0.0.1:5020/invocations"
    elif (threatID == 2):
        # Malware - Ransomware
        url = "http://127.0.0.1:5020/invocations"
        url = "http://127.0.0.1:5022/invocations"
    elif (threatID == 3):
        # hacking - DoS
        url = "http://127.0.0.1:5021/invocations"
        url = "http://127.0.0.1:5023/invocations"
    elif (threatID == 4):
        # hacking - SQLi
        url = "http://127.0.0.1:5021/invocations"
        url = "http://127.0.0.1:5024/invocations"
    elif (threatID == 5):
        # hacking - MitM
        url = "http://127.0.0.1:5021/invocations"
        url = "http://127.0.0.1:5024/invocations"


    value_ML = get_RiskML_value()
    if not value_ML == -1:
        i += 1
    else:
        value_ML = 0

    if i>0:
        return (value_DB + value_BBTR + value_ML) / i
    else:
        return -1

    # url = "http://sphinx-kubernetes.intracom-telecom.com:8080/SMPlatform/manager/rst/Authentication"
    url = "http://127.0.0.1:5030/invocations"
    payload = {
        'username': 'testR1',
        'password': 'testR1123!@'
    }
    headers = {
        'Content-Type': 'application/json'
    }
    response = requests.request("POST", url, headers=headers, data=payload)


#
# endregion return final estimation

# endregion Threat Estimation calls

# region Test area

x = get_ThreatFactorsvaluesfromDB(1, 1)
# x = get_RiskML_value(["asset.variety.Server"],"Malware",'action')
print(x)
# endregion
