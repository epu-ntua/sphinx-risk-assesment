from sqlalchemy.exc import SQLAlchemyError
from app import db
from app.models import CAPEC, CWE, CVE, VReport, VReportCVELink, cVecWe
from sqlalchemy import exists
from datetime import date, datetime
import openpyxl
import json
import requests


# <editor-fold desc="Insert information from Excel files">
# <editor-fold desc="Insert all CAPEC records from Excel">
def CAPEC_excel_insertData(capecexcelpath):
    theFile = openpyxl.load_workbook(capecexcelpath)
    currentSheet = theFile.active
    for row in currentSheet.iter_rows(min_row=2, values_only=True):
        if row[0] is not None:  # We need to check that the cell is not empty.
            if not db.session.query(exists().where(CAPEC.capecId == row[0])).scalar():
                my_row = CAPEC(capecId=row[0], name=row[1], abstraction=row[2], status=row[3], description=row[4],
                               alternateTerms=row[5], likelihoodOfAttack=row[6], typicalSeverity=row[7],
                               relatedAttackpatterns=row[8], executionFlow=row[9], prerequisites=row[10],
                               skillsRequired=row[11], resourcesRequired=row[12], indicators=row[13], consequences=row[14],
                               mitigations=row[15], exampleInstances=row[16], relatedWeaknesses=row[17],
                               taxonomyMappings=row[18], notes=row[19])
                db.session.add(my_row)
    db.session.commit()
    return 1
# </editor-fold>

# <editor-fold desc="Insert all CWE records from Excel">
def CWE_excel_insertData(cweexcelpath):
    theFile = openpyxl.load_workbook(cweexcelpath)
    currentSheet = theFile.active
    for row in currentSheet.iter_rows(min_row=2, values_only=True):
        if row[0] is not None:
            row_cweID = str(row[0])
            if db.session.query(exists().where(CWE.CWEId == row_cweID)).scalar():
                my_row = db.session.query(CWE).filter_by(CWEId=row_cweID)[0]
            else:
                my_row = CWE(CWEId=row[0])
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


# </editor-fold>

# <editor-fold desc="Insert all CVE records from Excel">
def CVE_excel_insertData(cveexcelpath):
    theFile = openpyxl.load_workbook(cveexcelpath)
    currentSheet = theFile.active
    for row in currentSheet.iter_rows(min_row=2, values_only=True):
        if row[0] is not None:
            if not CVE.query(exists().where(CVE.CVEId == row[0])).scalar():
                my_row = CVE(CVEId=row[0], status=row[1])
                db.session.add(my_row)
    db.session.commit()
    return 1


# </editor-fold>
# </editor-fold>


# <editor-fold desc="Insert information from VAaaS Report">
def v_report(fpath):
    with open(fpath, "r") as fp:
        obj = json.load(fp)
        # todo: check what must be changed if a report has more than one devices
        if obj["report"]["@id"] is not None:
            reprow_reportId = obj["report"]["@id"]
            if db.session.query(exists().where(VReport.reportId == reprow_reportId)).scalar():
                my_json_report = db.session.query(VReport).filter_by(reportId=reprow_reportId).one()
            else:
                my_json_report = VReport(reportId=reprow_reportId)
            my_json_report.creation_time=obj["report"]["creation_time"] if obj["report"]["creation_time"] is not None else ""
            my_json_report.name=obj["report"]["name"] if obj["report"]["name"] is not None else ""
            db.session.add(my_json_report)
            try:
                db.session.commit()
            except SQLAlchemyError as e:
                db.session.rollback()
                return -1
        # Get CVE from the result nodes of the report
            for item in obj['report']['report']['results']['result']:
                if item["nvt"]["cve"] == "NOCVE":
                    continue
                else:
                    reprow_cveId = item["nvt"]["cve"]
                    if not db.session.query(exists().where(CVE.CVEId == reprow_cveId)).scalar():
                        continue
                    #my_report = db.session.query(VReport).filter_by(reportId=reprow_reportId).one()
                    my_cve = db.session.query(CVE).filter_by(CVEId=reprow_cveId).one()
                    if VReport.query.join(VReportCVELink).join(CVE).filter((VReportCVELink.vreport_id == my_json_report.id) & (VReportCVELink.cve_id == my_cve.id)).first() is None:
                        my_link = VReportCVELink(vreport_id=my_json_report.id, cve_id = my_cve.id)
                    else:
                        my_link = VReport.query.join(VReportCVELink).join(CVE).filter((VReportCVELink.vreport_id == my_json_report.id) & (VReportCVELink.cve_id == my_cve.id)).first()
                    my_link.VReport_assetID=item["host"]["asset"]["@asset_id"] if item["host"]["asset"][
                                                                                  "@asset_id"] is not None else ""
                    my_link.VReport_assetIp=obj["ip"] if obj["ip"] is not None else ""
                    my_link.VReport_port=item["port"] if item["port"] is not None else ""
                    my_link.comments=item["nvt"]["@oid"] if item["nvt"]["@oid"] is not None else ""
                    db.session.add(my_link)
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
                        my_cve = db.session.query(CVE).filter_by(CVEId=reprow_cveId).one()
                        my_cve.severity = impact["baseMetricV2"]["severity"] if impact["baseMetricV2"]["severity"] is not None else ""
                        my_cve.exploitabilityScore = impact["baseMetricV2"]['exploitabilityScore'] if impact["baseMetricV2"][
                                                                                          'exploitabilityScore'] is not None else ""
                        my_cve.impactScore = impact["baseMetricV2"]['impactScore'] if impact["baseMetricV2"]['impactScore'] is not None else ""
                        my_cve.obtainAllPrivilege = impact["baseMetricV2"]['obtainAllPrivilege'] if impact["baseMetricV2"][
                                                                                        'obtainAllPrivilege'] is not None else ""
                        my_cve.obtainUserPrivilege = impact["baseMetricV2"]['obtainUserPrivilege'] if impact["baseMetricV2"][
                                                                                          'obtainUserPrivilege'] is not None else ""
                        my_cve.obtainOtherPrivilege = impact["baseMetricV2"]['obtainOtherPrivilege'] if impact["baseMetricV2"][
                                                                                            'obtainOtherPrivilege'] is not None else ""
                        my_cve.userInteractionRequired = impact["baseMetricV2"]['userInteractionRequired'] if impact["baseMetricV2"][
                                                                                                  'userInteractionRequired'] is not None else ""
                        my_cve.accessVector = impact['baseMetricV2']['cvssV2']['accessVector'] if impact[
                                                                                                      'baseMetricV2']['cvssV2']['accessVector'] is not None else ""
                        my_cve.accessComplexity = impact['baseMetricV2']['cvssV2']['accessComplexity'] if impact[
                                                                                                              'baseMetricV2']['cvssV2']['accessComplexity'] is not None else ""
                        my_cve.authentication = impact['baseMetricV2']['cvssV2']['authentication'] if impact[
                                                                                                          'baseMetricV2']['cvssV2']['authentication'] is not None else ""
                        my_cve.confidentialityImpact = impact['baseMetricV2']['cvssV2']['confidentialityImpact'] if impact[
                                                                                                                        'baseMetricV2']['cvssV2']['confidentialityImpact'] is not None else ""
                        my_cve.integrityImpact = impact['baseMetricV2']['cvssV2']['integrityImpact'] if impact[
                                                                                                            'baseMetricV2']['cvssV2']['integrityImpact'] is not None else ""
                        my_cve.availabilityImpact = impact['baseMetricV2']['cvssV2']['availabilityImpact'] if impact[
                                                                                                                  'baseMetricV2']['cvssV2']['availabilityImpact'] is not None else ""
                        my_cve.baseScore = impact['baseMetricV2']['cvssV2']['baseScore'] if impact['baseMetricV2']['cvssV2']['baseScore'] is not None else ""
                        db.session.add(my_cve)
            # Get CWEs and link them with CVE
                        for api_cve_desc, api_cveId, api_cweId in get_cwe_codes_from_API_report(NVDreport):
                            my_cve.description = api_cve_desc
                            cwe_number = api_cweId.split("CWE-", 1)[1].strip()
                            if cwe_number.isnumeric():
                                if db.session.query(exists().where(CWE.CWEId == cwe_number)).scalar():
                                    my_CWE_row = db.session.query(CWE).filter_by(CWEId=cwe_number)[0]
                                else:
                                    my_CWE_row = CWE(CWEId=cwe_number)
                                    db.session.add(my_CWE_row)
                                if db.session.query(CVE).filter(cVecWe.cwe_id == my_CWE_row.id, cVecWe.cve_id == my_cve.id).first() is None:
                                    my_cVecWe = cVecWe(cve_id=my_cve.id, cwe_id=my_CWE_row.id, date=datetime.utcnow())
                                else:
                                    my_cVecWe = db.session.query(CVE).filter(cVecWe.cwe_id == my_CWE_row.id, cVecWe.cve_id == my_cve.id).first()
                                    my_cVecWe.date = datetime.utcnow()
                                db.session.add(my_cVecWe)
                        db.session.commit()
            return 1
# </editor-fold>


# <editor-fold desc="NVD API get_cwe_codes">
def get_cwe_codes_from_API_report(APIreport):
    for item in APIreport['result']['CVE_Items']:
        itemdescr = item["cve"]["description"]["description_data"][0]["value"]
        for problem in item["cve"]['problemtype']['problemtype_data']:
            for descr in problem['description']:
                yield itemdescr, item["cve"]["CVE_data_meta"]["ID"], descr["value"]
# </editor-fold>


# <editor-fold desc="get_assets">
# temporarily from VaasReport table
def get_assets():
    if db.session.query(VReportCVELink).distinct(VReportCVELink.VReport_assetID).count()>0:
        list_of_assets = db.session.query(VReportCVELink).distinct(VReportCVELink.VReport_assetID)
        return list_of_assets
    else:
        return -1
    # db.session.query(your_table.column1.distinct()).filter_by(column2 = 'some_column2_value').all()
# </editor-fold>

# <editor-fold desc="get Recommended CVEs for an asset">
def get_cve_recommendations(asset_id):
    if db.session.query(VReportCVELink).distinct(VReportCVELink.cve_id).filter(VReportCVELink.VReport_assetID == asset_id).count()>0:
        list_of_cve = db.session.query(VReportCVELink.cve_id).distinct(VReportCVELink.cve_id).filter(VReportCVELink.VReport_assetID == asset_id)
        result = db.session.query(CVE).filter(CVE.id.in_(list_of_cve))
        return result.all()
    else:
        return -1
# </editor-fold>

# <editor-fold desc="get Recommended CWEs for a selected CVE">
def get_cwe_recommendations(selected_cve_id):
    if db.session.query(cVecWe).distinct(cVecWe.cwe_id).filter(cVecWe.cve_id == selected_cve_id).count()>0:
        list_of_cwe = db.session.query(cVecWe.cwe_id).distinct(cVecWe.cwe_id).filter(cVecWe.cve_id == selected_cve_id)
        result = db.session.query(CWE).filter(CWE.id.in_(list_of_cwe))
        return result.all()
    else:
        return -1
# </editor-fold>

# <editor-fold desc="get Recommended CAPECs for a selected CVE">
def get_capec_recommendations(selected_cve_id):
    for cwe_item in get_cwe_recommendations(selected_cve_id):
        capecList = []
        for capec_item in CAPEC.query.filter(CAPEC.relatedWeaknesses.like("%" + cwe_item.CWEId + "%")):
            capecList.append(capec_item.id)
    if capecList:
        result = db.session.query(CAPEC).distinct(CAPEC.capecId).filter(CAPEC.id.in_(capecList)) if db.session.query(CAPEC).filter(CAPEC.id.in_(capecList)) is not None else -1
        return result.all()
    else:
        return -1
# </editor-fold>



# <editor-fold desc="Test area">
# db.create_all()
# x= v_report("Json_texts/report1.json")# for x in v_report("Json_texts/report1.json"):
# print(x)

# for y in get_assets():
#     print(y.VReport_assetID, y.cve_id)
#
# for y in get_cve_recommendations('f080c7b3-3038-4a52-8b14-4397136c9dad'):
#     print(y.CVEId, y.id)
#
# for y in get_cwe_recommendations('170528'):
#     print(y.CWEId, y.id)

# for xx in CAPEC.query.filter(CAPEC.relatedWeaknesses.like("%200%")):
#     print(xx.capecId, xx.relatedWeaknesses)
i=0
for xx in get_capec_recommendations('170528'):
    i=i+1
    print(i,xx.capecId, xx.relatedWeaknesses)

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
# for xx in CAPEC.query.all():
#     print(xx.id, xx.capecId, xx.name, xx.relatedWeaknesses)
#
# x = CWE_excel_insertData('xlsx_texts/CWE-Research Concepts-1000.xlsx')
# print('Return: {}'.format(x))
# for xx in CWE.query.all():
#     print(xx.id, xx.CWEId, xx.name)

# x = CVE_excel_insertData('xlsx_texts/CVE-allitems.xlsx')
# print('Return: {}'.format(x))
# for xx in CVE.query.all():
#     print(xx.id, xx.CVEId, xx.status)

# </editor-fold>
