from flask import jsonify
from sqlalchemy.exc import SQLAlchemyError
from app import db
from app.models import *
# from app.csv_to_json_converter_util import *
from sqlalchemy import exists
from datetime import date, datetime
import openpyxl
import json
import os
import requests
import stix2
import stix2validator
import app.stix2_custom as stix2_custom
# region Insert information from Excel files
# region Insert all CAPEC records from Excel
from app.producer import SendKafkaReport


def CAPEC_excel_insertData(capecexcelpath):
    theFile = openpyxl.load_workbook(capecexcelpath)
    currentSheet = theFile.active
    for row in currentSheet.iter_rows(min_row=2, values_only=True):
        if row[0] is not None:  # We need to check that the cell is not empty.
            if not db.session.query(
                    exists().where(CommonAttackPatternEnumerationClassification.capecId == row[0])).scalar():
                my_row = CommonAttackPatternEnumerationClassification(capecId=row[0], name=row[1], abstraction=row[2],
                                                                      status=row[3], description=row[4],
                                                                      alternateTerms=row[5], likelihoodOfAttack=row[6],
                                                                      typicalSeverity=row[7],
                                                                      relatedAttackpatterns=row[8],
                                                                      executionFlow=row[9], prerequisites=row[10],
                                                                      skillsRequired=row[11], resourcesRequired=row[12],
                                                                      indicators=row[13], consequences=row[14],
                                                                      mitigations=row[15], exampleInstances=row[16],
                                                                      relatedWeaknesses=row[17],
                                                                      taxonomyMappings=row[18], notes=row[19])
                db.session.add(my_row)
    db.session.commit()
    return 1


# endregion

# region Insert all CWE records from Excel
def CWE_excel_insertData(cweexcelpath):
    theFile = openpyxl.load_workbook(cweexcelpath)
    currentSheet = theFile.active
    for row in currentSheet.iter_rows(min_row=2, values_only=True):
        if row[0] is not None:
            row_cweID = str(row[0])
            if db.session.query(exists().where(CommonWeaknessEnumeration.CWEId == row_cweID)).scalar():
                my_row = db.session.query(CommonWeaknessEnumeration).filter_by(CWEId=row_cweID)[0]
            else:
                my_row = CommonWeaknessEnumeration(CWEId=row[0])
            my_row.name = row[1]
            my_row.weakness = row[2]
            my_row.abstraction = row[3]
            my_row.status = row[4]
            my_row.description = row[5]
            my_row.extendedDescription = row[6]
            my_row.relatedWeaknesses = row[7]
            my_row.weaknessOrdinalities = row[8]
            my_row.applicablePlatforms = row[9]
            my_row.backgroundDetails = row[10]
            my_row.alternateTerms = row[11]
            my_row.modesOfIntroduction = row[12]
            my_row.exploitationFactors = row[13]
            my_row.likelihoodOfExploit = row[14]
            my_row.commonConsequences = row[15]
            my_row.detectionMethods = row[16]
            my_row.potentialMitigations = row[17]
            my_row.observedExamples = row[18]
            my_row.functionalAreas = row[19]
            my_row.affectedResources = row[20]
            my_row.taxonomyMappings = row[21]
            my_row.relatedAttackPatterns = row[22]
            my_row.notes = row[23]
            db.session.add(my_row)
    db.session.commit()
    return 1


# endregion

# region Insert all CVE records from Excel
def CVE_excel_insertData(cveexcelpath):
    theFile = openpyxl.load_workbook(cveexcelpath)
    currentSheet = theFile.active
    for row in currentSheet.iter_rows(min_row=2, values_only=True):
        # print(row[0])
        if row[0] is not None:
            if not db.session.query(
                    exists().where(CommonVulnerabilitiesAndExposures.CVEId == row[0])).scalar():
                my_row = CommonVulnerabilitiesAndExposures(CVEId=row[0], status=row[1])
                db.session.add(my_row)
    db.session.commit()
    return 1


# endregion

# region Insert information from VAaaS Report
def v_report(fpath):
    with open(fpath, "r") as fp:
        obj = json.load(fp)
        # todo: check what must be changed if a report has more than one devices
        # print("Test")
        if obj["report"]["@id"] is not None:
            reprow_reportId = obj["report"]["@id"]
            if db.session.query(exists().where(VulnerabilityReport.reportId == reprow_reportId)).scalar():
                my_json_report = db.session.query(VulnerabilityReport).filter_by(reportId=reprow_reportId).one()
            else:
                my_json_report = VulnerabilityReport(reportId=reprow_reportId)
            my_json_report.creation_time = obj["report"]["creation_time"] if obj["report"][
                                                                                 "creation_time"] is not None else ""
            my_json_report.name = obj["report"]["name"] if obj["report"]["name"] is not None else ""
            db.session.add(my_json_report)
            try:
                db.session.commit()
            except SQLAlchemyError as e:
                db.session.rollback()
                return -1
            # Get CVE from the result nodes of the report
            for item in obj['report']['report']['results']['result']:
                print("Test1")
                if item["nvt"]["cve"] == "NOCVE":
                    print("Continue")
                    continue
                else:
                    print("CVE Exists")
                    reprow_cveId = item["nvt"]["cve"]
                    # NEEDS FIXING CVE IS IMPORTED WITH AN EXTRA " IN THE START ----------------------------------------
                    reprow_cveId = '"' + reprow_cveId
                    if not db.session.query(
                            exists().where(CommonVulnerabilitiesAndExposures.CVEId == reprow_cveId)).scalar():
                        print("Continue2")
                        print(reprow_cveId)
                        continue
                    # my_report = db.session.query(VReport).filter_by(reportId=reprow_reportId).one()
                    my_cve = db.session.query(CommonVulnerabilitiesAndExposures).filter_by(CVEId=reprow_cveId).one()
                    if VulnerabilityReport.query.join(VulnerabilityReportVulnerabilitiesLink).join(
                            CommonVulnerabilitiesAndExposures).filter(
                        (VulnerabilityReportVulnerabilitiesLink.vreport_id == my_json_report.id) & (
                                VulnerabilityReportVulnerabilitiesLink.cve_id == my_cve.id)).first() is None:
                        my_link = VulnerabilityReportVulnerabilitiesLink(vreport_id=my_json_report.id, cve_id=my_cve.id)
                    else:
                        my_link = VulnerabilityReport.query.join(VulnerabilityReportVulnerabilitiesLink).join(
                            CommonVulnerabilitiesAndExposures).filter(
                            (VulnerabilityReportVulnerabilitiesLink.vreport_id == my_json_report.id) & (
                                    VulnerabilityReportVulnerabilitiesLink.cve_id == my_cve.id)).first()
                    my_link.VReport_assetID = item["host"]["asset"]["@asset_id"] if item["host"]["asset"][
                                                                                        "@asset_id"] is not None else ""
                    my_link.VReport_assetIp = obj["ip"] if obj["ip"] is not None else ""
                    my_link.VReport_port = item["port"] if item["port"] is not None else ""
                    my_link.comments = item["nvt"]["@oid"] if item["nvt"]["@oid"] is not None else ""
                    db.session.add(my_link)
                    print("Link Added")
                    print("my_link")
                    try:
                        db.session.commit()
                    except SQLAlchemyError as e:
                        db.session.rollback()
                        continue
                    # call API for CVE and CWE information
                    response = requests.get("https://services.nvd.nist.gov/rest/json/cve/1.0/" + item["nvt"]["cve"])
                    if response is not None and response.status_code == 200:
                        NVDreport = response.json()
                        # update CVE table with API values
                        impact = NVDreport['result']['CVE_Items'][0]['impact']
                        my_cve = db.session.query(CommonVulnerabilitiesAndExposures).filter_by(CVEId=reprow_cveId).one()
                        my_cve.severity = impact["baseMetricV2"]["severity"] if impact["baseMetricV2"][
                                                                                    "severity"] is not None else ""
                        my_cve.exploitabilityScore = impact["baseMetricV2"]['exploitabilityScore'] if \
                            impact["baseMetricV2"][
                                'exploitabilityScore'] is not None else ""
                        my_cve.impactScore = impact["baseMetricV2"]['impactScore'] if impact["baseMetricV2"][
                                                                                          'impactScore'] is not None else ""
                        my_cve.obtainAllPrivilege = impact["baseMetricV2"]['obtainAllPrivilege'] if \
                            impact["baseMetricV2"][
                                'obtainAllPrivilege'] is not None else ""
                        my_cve.obtainUserPrivilege = impact["baseMetricV2"]['obtainUserPrivilege'] if \
                            impact["baseMetricV2"][
                                'obtainUserPrivilege'] is not None else ""
                        my_cve.obtainOtherPrivilege = impact["baseMetricV2"]['obtainOtherPrivilege'] if \
                            impact["baseMetricV2"][
                                'obtainOtherPrivilege'] is not None else ""
                        my_cve.userInteractionRequired = impact["baseMetricV2"]['userInteractionRequired'] if \
                            impact["baseMetricV2"][
                                'userInteractionRequired'] is not None else ""
                        my_cve.accessVector = impact['baseMetricV2']['cvssV2']['accessVector'] if impact[
                                                                                                      'baseMetricV2'][
                                                                                                      'cvssV2'][
                                                                                                      'accessVector'] is not None else ""
                        my_cve.accessComplexity = impact['baseMetricV2']['cvssV2']['accessComplexity'] if impact[
                                                                                                              'baseMetricV2'][
                                                                                                              'cvssV2'][
                                                                                                              'accessComplexity'] is not None else ""
                        my_cve.authentication = impact['baseMetricV2']['cvssV2']['authentication'] if impact[
                                                                                                          'baseMetricV2'][
                                                                                                          'cvssV2'][
                                                                                                          'authentication'] is not None else ""
                        my_cve.confidentialityImpact = impact['baseMetricV2']['cvssV2']['confidentialityImpact'] if \
                            impact[
                                'baseMetricV2']['cvssV2']['confidentialityImpact'] is not None else ""
                        my_cve.integrityImpact = impact['baseMetricV2']['cvssV2']['integrityImpact'] if impact[
                                                                                                            'baseMetricV2'][
                                                                                                            'cvssV2'][
                                                                                                            'integrityImpact'] is not None else ""
                        my_cve.availabilityImpact = impact['baseMetricV2']['cvssV2']['availabilityImpact'] if impact[
                                                                                                                  'baseMetricV2'][
                                                                                                                  'cvssV2'][
                                                                                                                  'availabilityImpact'] is not None else ""
                        my_cve.baseScore = impact['baseMetricV2']['cvssV2']['baseScore'] if \
                            impact['baseMetricV2']['cvssV2']['baseScore'] is not None else ""
                        db.session.add(my_cve)
                        # Get CWEs and link them with CVE
                        for api_cve_desc, api_cveId, api_cweId in get_cwe_codes_from_API_report(NVDreport):
                            my_cve.description = api_cve_desc
                            cwe_number = api_cweId.split("CWE-", 1)[1].strip()
                            if cwe_number.isnumeric():
                                if db.session.query(
                                        exists().where(CommonWeaknessEnumeration.CWEId == cwe_number)).scalar():
                                    my_CWE_row = \
                                        db.session.query(CommonWeaknessEnumeration).filter_by(CWEId=cwe_number)[0]
                                else:
                                    my_CWE_row = CommonWeaknessEnumeration(CWEId=cwe_number)
                                    db.session.add(my_CWE_row)
                                if db.session.query(CommonVulnerabilitiesAndExposures).filter(
                                        VulnerabilitiesWeaknessLink.cwe_id == my_CWE_row.id,
                                        VulnerabilitiesWeaknessLink.cve_id == my_cve.id).first() is None:
                                    my_cVecWe = VulnerabilitiesWeaknessLink(cve_id=my_cve.id, cwe_id=my_CWE_row.id,
                                                                            date=datetime.utcnow())
                                else:
                                    my_cVecWe = db.session.query(CommonVulnerabilitiesAndExposures).filter(
                                        VulnerabilitiesWeaknessLink.cwe_id == my_CWE_row.id,
                                        VulnerabilitiesWeaknessLink.cve_id == my_cve.id).first()
                                    my_cVecWe.date = datetime.utcnow()
                                db.session.add(my_cVecWe)
                        db.session.commit()
            return 1


# endregion
# endregion

# region NVD API get_cwe_codes
def get_cwe_codes_from_API_report(APIreport):
    for item in APIreport['result']['CVE_Items']:
        itemdescr = item["cve"]["description"]["description_data"][0]["value"]
        for problem in item["cve"]['problemtype']['problemtype_data']:
            for descr in problem['description']:
                yield itemdescr, item["cve"]["CVE_data_meta"]["ID"], descr["value"]


# endregion

# region get_assets
# temporarily from VaasReport table
def get_assets():
    if db.session.query(VulnerabilityReportVulnerabilitiesLink).distinct(
            VulnerabilityReportVulnerabilitiesLink.VReport_assetID).count() > 0:
        list_of_assets = db.session.query(VulnerabilityReportVulnerabilitiesLink).distinct(
            VulnerabilityReportVulnerabilitiesLink.VReport_assetID)
        return list_of_assets
    else:
        return []
    # db.session.query(your_table.column1.distinct()).filter_by(column2 = 'some_column2_value').all()


#
# def get_assetsfromrepository():
#     if db.session.query().distinct(HardwareAsset.id).count() > 0:
#         list_of_assets = db.session.query(HardwareAsset).distinct(HardwareAsset.id)
#         return list_of_assets
#     else:
#         return -1


# region get Recommended CVEs for an asset
def get_cve_recommendations(asset_id):
    if db.session.query(VulnerabilityReportVulnerabilitiesLink).distinct(
            VulnerabilityReportVulnerabilitiesLink.cve_id).filter(
        VulnerabilityReportVulnerabilitiesLink.VReport_assetID == asset_id).count() > 0:
        list_of_cve = db.session.query(VulnerabilityReportVulnerabilitiesLink.cve_id).distinct(
            VulnerabilityReportVulnerabilitiesLink.cve_id).filter(
            VulnerabilityReportVulnerabilitiesLink.VReport_assetID == asset_id)
        result = db.session.query(CommonVulnerabilitiesAndExposures).filter(
            CommonVulnerabilitiesAndExposures.id.in_(list_of_cve))
        return result.all()
    else:
        return -1


# endregion

# region get Recommended CWEs for a selected CVE
def get_cwe_recommendations(selected_cve_id):
    if db.session.query(VulnerabilitiesWeaknessLink).distinct(VulnerabilitiesWeaknessLink.cwe_id).filter(
            VulnerabilitiesWeaknessLink.cve_id == selected_cve_id).count() > 0:
        list_of_cwe = db.session.query(VulnerabilitiesWeaknessLink.cwe_id).distinct(
            VulnerabilitiesWeaknessLink.cwe_id).filter(VulnerabilitiesWeaknessLink.cve_id == selected_cve_id)
        result = db.session.query(CommonWeaknessEnumeration).filter(CommonWeaknessEnumeration.id.in_(list_of_cwe))
        return result.all()
    else:
        return -1


# endregion

# region get Recommended CAPECs for a selected CVE
def get_capec_recommendations(selected_cve_id):
    for cwe_item in get_cwe_recommendations(selected_cve_id):
        capecList = []
        for capec_item in CommonAttackPatternEnumerationClassification.query.filter(
                CommonAttackPatternEnumerationClassification.relatedWeaknesses.like("%" + cwe_item.CWEId + "%")):
            capecList.append(capec_item.id)
    if capecList:
        result = db.session.query(CommonAttackPatternEnumerationClassification).distinct(
            CommonAttackPatternEnumerationClassification.capecId).filter(
            CommonAttackPatternEnumerationClassification.id.in_(capecList)) if db.session.query(
            CommonAttackPatternEnumerationClassification).filter(
            CommonAttackPatternEnumerationClassification.id.in_(capecList)) is not None else -1
        return result.all()
    else:
        return -1


# endregion

# region get Recommended CAPECs for a selected CVE

# One impact at a time saved
# scopes is an array
# NEEDS TO BE REACTIVATED, IT WORKS
# def save_capec_consequence(scopes, impact, notes):
#     scope_instances = []
#     for scope in scopes:
#         stored_scope = db.session.query(GiraScope).filter_by(name=scope).first()
#         if stored_scope is None:
#             new_scope = GiraScope(name=scope)
#             scope_instances.append(new_scope)
#             db.session.add(new_scope)
#         else:
#             scope_instances.append(stored_scope)
#
#     db.session.commit()
#     impact = impact[:-1]  # To be removed if bug that leaves ':' in the end of the asset is fixed
#     if db.session.query(GiraImpact).filter_by(name=impact).first() is None:
#         new_impact = GiraImpact(name=impact, note=notes)
#         for scope_instance in scope_instances:
#             new_impact.scopes.append(scope_instance)
#
#     db.session.commit()


# def get_capec_consequences():
#     capec_list = CommonAttackPatternEnumerationClassification.query.all()
#     for capec_entry in capec_list:
#         capec_consequence = capec_entry.consequences
#         if capec_consequence is None:
#             continue
#
#         temp_capec = capec_consequence[1:]
#         temp_capec = temp_capec[:-1]
#
#         temp_consequence_list = temp_capec.split(':SCOPE:')
#
#         # temp_scope contains scope that are linked to the next impact
#         temp_scope = []
#         for temp_it in temp_consequence_list:
#             if "TECHNICAL IMPACT:" in temp_it:
#                 temp_impact = temp_it
#                 temp_description = ""
#                 if "NOTE:" in temp_it:
#                     temp_impact_and_note = temp_it.split('NOTE:')
#                     temp_impact = temp_impact_and_note[0]
#                     temp_description = temp_impact_and_note[1]
#
#                 temp_scope_and_impact = temp_impact.split('TECHNICAL IMPACT:')
#                 temp_scope.append(temp_scope_and_impact[0])
#
#                 save_capec_consequence(temp_scope, temp_scope_and_impact[1], temp_description)
#                 print(temp_scope)
#                 print(temp_scope_and_impact[1])
#                 print(temp_description)
#                 print("-------------------")
#                 temp_scope = []
#
#             elif temp_it == "":
#                 continue
#             else:
#                 temp_scope.append(temp_it)


# def get_hardwareassets():
#     if db.session.query(HardwareAsset).distinct(
#             HardwareAsset.id).count() > 0:
#         list_of_hardwareassets = db.session.query(HardwareAsset).distinct(
#             HardwareAsset.id)
#         return list_of_hardwareassets
#     else:
#         return []


# endregion

# region Communication Functions
def sendDSSScore():
    asset = stix2.IPv4Address(
        # type="ipv4-addr",
        value="10.0.255.106"
    )
    attack = stix2.AttackPattern(
        # type="attack-pattern",
        name="Spear Phishing as Practiced by Adversary X",
        description="A particular form of spear phishing where the attacker claims that the target had won a contest, including personal details, to get them to click on a link.",
    )

    relationship = stix2.Relationship(
        # type="relationship",
        relationship_type="targets",
        source_ref=attack.id,
        target_ref=asset.id
    )

    scoring = {
        "score": "1",
        "impact": "high",
        "probability": "low"
    }
    rcra = stix2_custom.RCRAObjective(
        x_rcra_scoring=json.dumps(scoring)

    )

    bundle = stix2.Bundle(asset, attack, relationship, rcra)
    print(bundle, flush=True)
    stix2validator.validate_instance(bundle)
    SendKafkaReport(str(bundle), "rcra-report-topic")

    return 0


def sendDSSScoreTest():
    asset = stix2.IPv4Address(
        # type="ipv4-addr",
        value="10.0.255.106"
    )
    attack = stix2.AttackPattern(
        # type="attack-pattern",
        name="Spear Phishing as Practiced by Adversary X",
        description="A particular form of spear phishing where the attacker claims that the target had won a contest, including personal details, to get them to click on a link.",
    )

    relationship = stix2.Relationship(
        # type="relationship",
        relationship_type="targets",
        source_ref=attack.id,
        target_ref=asset.id
    )

    scoring = {
        "score": "20",
        "impact": "high",
        "probability": "low"
    }
    rcra = stix2_custom.RCRAObjective(
        x_rcra_scoring=json.dumps(scoring)

    )

    bundle = stix2.Bundle(asset, attack, relationship, rcra)
    print(bundle, flush=True)
    stix2validator.validate_instance(bundle)
    SendKafkaReport(str(bundle), "rcra-report-topic-test")

    return 0



def send_dss_alert():
    asset = stix2.IPv4Address(
        # type="ipv4-addr",
        value="10.0.255.106"
    )
    attack = stix2.AttackPattern(
        # type="attack-pattern",
        name="Spear Phishing as Practiced by Adversary X",
        description="A particular form of spear phishing where the attacker claims that the target had won a contest, including personal details, to get them to click on a link.",
    )

    relationship = stix2.Relationship(
        # type="relationship",
        relationship_type="targets",
        source_ref=attack.id,
        target_ref=asset.id
    )

    # scoring = {
    #     "score": "1",
    #     "impact": "high",
    #     "probability": "low"
    # }
    # rcra = stix2_custom.RCRAObjective(
    #     x_rcra_scoring=json.dumps(scoring)
    #
    # )

    bundle = stix2.Bundle(asset, attack, relationship)
    print(bundle, flush=True)
    stix2validator.validate_instance(bundle)
    # SendKafkaReport(str(bundle))
    return str(bundle)


def make_visualisation():
    """ Constructs example visualisation for Current Threats by impact level"""
    score = {
        "low_impact": "1",
        "medium_impact": "2",
        "high_impact": "2",
        "critical_impact": "1",
    }

    vis_1 = stix2_custom.RCRACurrentThreatsVis(
        x_rcra_threats=score
    )
    bundle = stix2.Bundle(vis_1)
    stix2validator.validate_instance(bundle)

    # print(bundle, flush=True)
    return str(bundle)

def make_visualisation_current_assets(assets):
    """ Constructs Visualisation for ID new-unverified asset alert """
    vis_1 = stix2_custom.RCRACurrentAssets(
        x_rcra_assets=assets
    )
    bundle = stix2.Bundle(vis_1)
    stix2validator.validate_instance(bundle)

    return str(bundle)

def send_asset_id_alert():
    """' Function Recieves New Detected Assets and Send new visualisation data to ID (all or uknown-unverified only?)"""
    return 1


def convert_database_items_to_json_table(items):
    """ Converts sqlalchemy entries to json ,
    Needs to be in an array to work"""
    if items:
        # print(items)
        columns = items[0].__table__.columns._data.keys()
        json_ready = []
        temp_json = {}
        # print(columns, flush=True)
        for item in items:
            # print(item)
            for column in columns:
                temp_json[column] = getattr(item, column)
            json_ready.append(temp_json.copy())
            # print(json_ready)

        return json_ready
    else:
        return []

def import_fixture_from_file(file_name):
    '''Function to imports Json from app/fixtures'''
    with open(os.path.join(os.getcwd(),"app", "fixtures",file_name+".json"),encoding='utf-8') as json_file:
        return json.load(json_file)

def rcra_db_init():
    """Function is run in the _init_ file when server starts to initialise static table data"""
    print("Initiating Database", flush=True)
    if RepoService.query.count() is not 0:
        print(RepoService.query.count())
        return "Already exists"

    to_add_services = import_fixture_from_file("repo_service")

    for service_json in to_add_services:
        print(service_json)
        to_add_service = RepoService(**service_json)
        db.session.add(to_add_service)

    to_add_threats = import_fixture_from_file("repo_threat")

    for threat_json in to_add_threats:
        to_add_threat = RepoThreat(**threat_json)
        db.session.add(to_add_threat)

    db.session.commit()

# def repo_check_dtm_asset_exits_and_add(dtm_object, assets):
#     """This function uses a single object of the DTM and the retrieved database assets
#     as input and will check if the described asset exists in the database"""
#     if dtm_object in assets:


# url = "http://sphinx-kubernetes.intracom-telecom.com:8080/SMPlatform/manager/rst/Authentication"
# payload = {
#     'username': 'testR1',
#     'password': 'testR1123!@'
# }
# response = requests.request("POST", url, data=payload)
# selectedticket = response.json()
# requestedTicket = selectedticket["data"]
#
# print("---------------------------------------", flush=True)
# print("Login ticket is: ", requestedTicket, flush=True)
# print("---------------------------------------", flush=True)
#
# # Need endpoint of dss
# url = "http://sphinx-dss-service:5000/-"
# params = {
#     'requestedservice': 'DSS',
#     'requestedTicket': requestedTicket
# }
#
# data = jsonify({'alert-1': [
#     {"asset": "server 1", "threat-level": "high", "date-time": "-", "type": "--"}
# ],
# })
# response = requests.request("POST", url, params=params, data=data)
#
# if response.status_code != 200:
#     return 1
# else:
#     return 0

# endregion


# region Test area
# db.create_all()
# x= v_report("Json_texts/report1.json")# for x in v_report("Json_texts/report1.json"):
# print(x)

# for y in get_assetsfromrepository():
#     print(y.id)

# for y in get_cve_recommendations('f080c7b3-3038-4a52-8b14-4397136c9dad'):
#     print(y.CVEId, y.id)
#
# for y in get_cwe_recommendations('170528'):
#     print(y.CWEId, y.id)

# for xx in CAPEC.query.filter(CAPEC.relatedWeaknesses.like("%200%")):
#     print(xx.capecId, xx.relatedWeaknesses)
# i = 0
# for xx in get_capec_recommendations('170528'):
#     i = i + 1
#     print(i, xx.capecId, xx.relatedWeaknesses)

# for y in db.session.query(VReportCVELink).distinct(VReportCVELink.VReport_assetID):
#     print(y.VReport_assetID, y.VReport_port, y.VReport_assetIp)

#
# for y in cVecWe.query.all():
#     print(y.cwe_id, y.cve_id, y.date)
#
# x= db.session.query(CVE).filter_by(CVEId="CVE-1999-0524").one()
# print(x.id, x.CVEId, x.description)
# for y in CVE.query.all():
#     print(y.CVEId, y.description)

# db.create_all()
# x = CAPEC_excel_insertData('xlsx_texts/CAPEC-Domains of Attack-3000.xlsx')
# print('Return: {}'.format(x))
# for xx in CommonAttackPatternEnumerationClassification.query.all():
#     print(xx.id, xx.capecId, xx.name, xx.relatedWeaknesses)
#
# x = CWE_excel_insertData('xlsx_texts/CWE-Research Concepts-1000.xlsx')
# print('Return: {}'.format(x))
# for xx in CommonWeaknessEnumeration.query.all():
#     print(xx.id, xx.CWEId, xx.name)
#
# x = CVE_excel_insertData('xlsx_texts/CVE-allitems.xlsx')
# print('Return: {}'.format(x))
# for xx in CommonVulnerabilitiesAndExposures.query.all():
#     print(xx.id, xx.CVEId, xx.status)

# endregion
