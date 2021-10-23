from copy import deepcopy

from sqlalchemy.exc import SQLAlchemyError
from app.models import *
# from app.csv_to_json_converter_util import *
from sqlalchemy import exists
from datetime import datetime
import openpyxl
import json
import os
import requests
import stix2
import stix2validator
import app.utils.stix2_custom as stix2_custom

# region Insert all CAPEC records from Excel
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

# endregion CAPEC

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

# endregion CWE

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

# endregion CVE
# endregion Insert information from Excel files

# region Insert information from VAaaS Report
def v_report(fpath):
    # with open(fpath, "r") as fp:
    #     obj = json.load(fp)
    #     if obj["id"] is not None:
    #         reprow_reportId = obj["id"]
    #         if db.session.query(exists().where(VulnerabilityReport.reportId == reprow_reportId)).scalar():
    #             my_json_report = db.session.query(VulnerabilityReport).filter_by(reportId=reprow_reportId).one()
    #         else:
    #             my_json_report = VulnerabilityReport(reportId=reprow_reportId)
    #         my_json_report.scan_start_time = obj["scan_start_time"] if obj["scan_start_time"] is not None else ""
    #         my_json_report.scan_end_time = obj["scan_end_time"] if obj["scan_end_time"] is not None else ""
    #         my_json_report.target_name = obj["target_name"] if obj["target_name"] is not None else ""
    #         db.session.add(my_json_report)
    #         try:
    #             db.session.commit()
    #         except SQLAlchemyError as e:
    #             db.session.rollback()
    #             return -1
    #         print(reprow_reportId)
    #         # Get asset IP
    #         for item in obj['objects']:
    #             if item['type'] != "ipv4-addr":
    #                 continue
    #             else:
    #                 my_asset_IP = item["value"]
    #             print(my_asset_IP)
    #         # Get CVE from the result nodes of the report
    #         for item in obj['objects']:
    #             if item['type'] != "vulnerability":
    #                 continue
    #             else:
    #                 if item["cvss"] == "0.0":
    #                     continue
    #                 else:
    #                     for subitem in item['external_references']:
    #                         if subitem['source_name'] == "cve":
    #                             reprow_cveId = subitem['external_id']
    #                             if not db.session.query(exists().where(CommonVulnerabilitiesAndExposures.CVEId == reprow_cveId)).scalar():
    #                                 my_cve = CommonVulnerabilitiesAndExposures(CVEId=reprow_cveId)
    #                                 db.session.add(my_cve)
    #                             else:
    #                                 my_cve = db.session.query(CommonVulnerabilitiesAndExposures).filter_by(CVEId=reprow_cveId).one()
    #
    #                             if VulnerabilityReport.query.join(VulnerabilityReportVulnerabilitiesLink).join(CommonVulnerabilitiesAndExposures).filter((VulnerabilityReportVulnerabilitiesLink.vreport_id == my_json_report.id) & (VulnerabilityReportVulnerabilitiesLink.cve_id == my_cve.id)).first() is None:
    #                                 my_link = VulnerabilityReportVulnerabilitiesLink(vreport_id=my_json_report.id, cve_id=my_cve.id)
    #                                 db.session.add(my_link)
    #                             else:
    #                                 my_link = VulnerabilityReport.query.join(VulnerabilityReportVulnerabilitiesLink).join(CommonVulnerabilitiesAndExposures).filter((VulnerabilityReportVulnerabilitiesLink.vreport_id == my_json_report.id) & (VulnerabilityReportVulnerabilitiesLink.cve_id == my_cve.id)).first()
    #                             my_link.VReport_assetID = obj['target_id'] if obj['target_id'] is not None else ""
    #                             my_link.VReport_assetIp = my_asset_IP if my_asset_IP is not None else ""
    #                             my_link.VReport_port = item['vulnerable_port'] if item['vulnerable_port'] is not None else ""
    #                             my_link.VReport_CVSS_score = item['cvss'] if item['cvss'] is not None else ""
    #                             my_link.date = datetime.date()
    #                             my_link.comments = item['threat_level'] if item['threat_level'] is not None else ""
    #                             print(my_cve.CVEId, my_link.VReport_CVSS_score)
    #                             try:
    #                                 db.session.commit()
    #                             except SQLAlchemyError as e:
    #                                 db.session.rollback()
    #                                 continue
    #                             # update_cve_scores(reprow_cveId)
    #                             # TODO: It's not needed to call the update CVE and CWE functions
    #
            return 1

# region Call NVD API to update CVE scores and get CWEs
# region Call NVD API to update CVE scores
def update_cve_scores(cveId):
    response = requests.get("https://services.nvd.nist.gov/rest/json/cve/1.0/" + cveId)
    if response is not None and response.status_code == 200:
        NVDreport = response.json()
        # update CVE table with API values
        impact = NVDreport['result']['CVE_Items'][0]['impact']
        my_cve = db.session.query(CommonVulnerabilitiesAndExposures).filter_by(CVEId=cveId).one()
        if impact['baseMetricV3']  is not None:
            my_cve.exploitabilityScore = impact['baseMetricV3']['exploitabilityScore'] if impact['baseMetricV3']['exploitabilityScore'] is not None else ""
            my_cve.impactScore = impact['baseMetricV3']['impactScore'] if impact['baseMetricV3']['impactScore'] is not None else ""
            my_cve.accessVector = impact['baseMetricV3']['cvssV3']['attackVector'] if impact[
                                                                                          'baseMetricV3'][
                                                                                          'cvssV3'][
                                                                                          'attackVector'] is not None else ""
            my_cve.accessComplexity = impact['baseMetricV3']['cvssV3']['attackComplexity'] if impact[
                                                                                                  'baseMetricV3'][
                                                                                                  'cvssV3'][
                                                                                                  'attackComplexity'] is not None else ""
            my_cve.obtainAllPrivilege = impact['baseMetricV3']['cvssV3']['obtainAllPrivilege'] if impact['baseMetricV3']['cvssV3']['obtainAllPrivilege'] is not None else ""
            my_cve.userInteractionRequired = impact['baseMetricV3']['cvssV3']['userInteractionRequired'] if impact['baseMetricV3']['cvssV3']['userInteractionRequired'] is not None else ""
            my_cve.confidentialityImpact = impact['baseMetricV3']['cvssV3']['confidentialityImpact'] if impact['baseMetricV3']['cvssV3']['confidentialityImpact'] is not None else ""
            my_cve.integrityImpact = impact['baseMetricV3']['cvssV3']['integrityImpact'] if impact['baseMetricV3']['cvssV3']['integrityImpact'] is not None else ""
            my_cve.availabilityImpact = impact['baseMetricV3']['cvssV3']['availabilityImpact'] if impact['baseMetricV3']['cvssV3']['availabilityImpact'] is not None else ""
            my_cve.baseScore = impact['baseMetricV3']['cvssV3']['baseScore'] if impact['baseMetricV3']['cvssV3']['baseScore'] is not None else ""
            my_cve.severity = impact['baseMetricV3']['cvssV3']['baseSeverity'] if impact['baseMetricV3']['cvssV3'][
                                                                                      'baseSeverity'] is not None else ""
        else:
            my_cve.severity = impact['baseMetricV2']['severity'] if impact['baseMetricV2']['severity'] is not None else ""
            my_cve.exploitabilityScore = impact['baseMetricV2']['exploitabilityScore'] if \
                impact['baseMetricV2'][
                    'exploitabilityScore'] is not None else ""
            my_cve.impactScore = impact['baseMetricV2']['impactScore'] if impact["baseMetricV2"][
                                                                              'impactScore'] is not None else ""
            my_cve.obtainAllPrivilege = impact['baseMetricV2']['obtainAllPrivilege'] if \
                impact['baseMetricV2'][
                    'obtainAllPrivilege'] is not None else ""
            my_cve.obtainUserPrivilege = impact["baseMetricV2"]['obtainUserPrivilege'] if \
                impact['baseMetricV2'][
                    'obtainUserPrivilege'] is not None else ""
            my_cve.obtainOtherPrivilege = impact["baseMetricV2"]['obtainOtherPrivilege'] if \
                impact['baseMetricV2'][
                    'obtainOtherPrivilege'] is not None else ""
            my_cve.userInteractionRequired = impact["baseMetricV2"]['userInteractionRequired'] if \
                impact['baseMetricV2'][
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
            my_cve.baseScore = impact['baseMetricV2']['cvssV2']['baseScore'] if impact['baseMetricV2']['cvssV2']['baseScore'] is not None else ""
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
        try:
            db.session.commit()
        except SQLAlchemyError as e:
            db.session.rollback()
            return -1
        return 1
# endregion

# region NVD API get_cwe_codes
def get_cwe_codes_from_API_report(APIreport):
    for item in APIreport['result']['CVE_Items']:
        itemdescr = item["cve"]["description"]["description_data"][0]["value"]
        for problem in item["cve"]['problemtype']['problemtype_data']:
            for descr in problem['description']:
                yield itemdescr, item["cve"]["CVE_data_meta"]["ID"], descr["value"]

# endregion CWE
# endregion CVE & CWE
# endregion VAaaS report

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

# endregion

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


# region test Area
path_to_VAaaS_report = os.path.join(os.path.abspath(os.path.join(os.path.dirname(__file__), os.path.pardir)), 'Json_texts', 'report_example_stix.json')
x = v_report(path_to_VAaaS_report)

print(x)
# endregion test Area