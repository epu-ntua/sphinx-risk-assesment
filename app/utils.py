from sqlalchemy.exc import SQLAlchemyError

from app import db
from app.models import CAPEC, CWE, CVE, VReport, Association, cVecWe
from sqlalchemy import exists
from datetime import date
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
                my_report = db.session.query(VReport).filter_by(reportId=reprow_reportId).one()
            else:
                my_report = VReport(reportId=reprow_reportId)
            my_report.creation_time=obj["report"]["creation_time"] if obj["report"]["creation_time"] is not None else ""
            my_report.name=obj["report"]["name"] if obj["report"]["name"] is not None else ""
            db.session.add(my_report)
            try:
                db.session.flush()
            except SQLAlchemyError as e:
                db.session.rollback()
                return e

            for item in obj['report']['report']['results']['result']:
                if item["nvt"]["cve"] == "NOCVE":
                    continue
                else:
                    reprow_cveId = item["nvt"]["cve"]
                    # my_cve_code = CVE.query.filter_by(CVEId=item["nvt"]["cve"])[0]
                    if db.session.query(exists().where(CVE.CVEId == reprow_cveId)).scalar():
                        my_CVE_row = db.session.query(CVE).filter_by(CVEId=reprow_cveId).one()
                    else:
                        my_CVE_row = CVE(CVEId=reprow_cveId)
                    db.session.add(my_CVE_row)
                    db.session.flush()
                    my_association = Association(
                        VReport_assetID=item["host"]["asset"]["@asset_id"] if item["host"]["asset"][
                                                                                  "@asset_id"] is not None else "",
                        VReport_assetIp=obj["ip"] if obj["ip"] is not None else "",
                        VReport_port=item["port"] if item["port"] is not None else "",
                        comments=item["nvt"]["@oid"] if item["nvt"]["@oid"] is not None else "")
                    my_association.cve_s = db.session.query(CVE).filter_by(CVEId=reprow_cveId).one()
                    my_report.CVEs.append(my_association)
                    db.session.add(my_report)
                    try:
                        db.session.commit()
                    except SQLAlchemyError as e:
                        db.session.rollback()
                        return e
                    # response = requests.get("https://services.nvd.nist.gov/rest/json/cve/1.0/" + item["nvt"]["cve"])
                    # if response is not None and response.status_code == 200:
                    #     myNVDreport = response.json()
                    #     for api_cve_desc, api_cveId, api_cweId in get_cwe_codes(myNVDreport):
                    #         cwe_number = api_cweId.split("CWE-", 1)[1].strip()
                    #         if cwe_number.isnumeric():
                    #             print(api_cve_desc, api_cveId, cwe_number)
                    #             # todo update CVE - CWE table based on responses
                    #             if db.session.query(exists().where(CWE.CWEId == cwe_number)).scalar():
                    #                 my_CWE_row = db.session.query(CWE).filter_by(CWEId=cwe_number)[0]
                    #             else:
                    #                 my_CWE_row = CWE(CWEId=cwe_number)
                    #             db.session.add(my_CWE_row)
                    #
                    #             #not here-- because i will have to return the values---- my_CVE_row.accessVector
                    #             db.session.add(my_CVE_row)
                    #             comp_cVecWe = cVecWe(cve_id=my_CVE_row.CVEId,cwe_id=cwe_number, date=date.today())
            db.session.commit()
            return 1


# </editor-fold>

# todo find DISTINCT CAPEC values based on CWEs
# ######## for CWE - get CAPEC patterns
#             for x, y in my_excel_read('app/xlsx_texts/CAPEC-Domains of Attack-3000.xlsx', 'R', cwe_number):
#                 print(x, y)


# <editor-fold desc="NVD API get_cwe_codes">
def get_cwe_codes(myreport):
    for item in myreport['result']['CVE_Items']:
        itemdescr = item["cve"]["description"]["description_data"][0]["value"]
        for problem in item["cve"]['problemtype']['problemtype_data']:
            for descr in problem['description']:
                yield itemdescr, item["cve"]["CVE_data_meta"]["ID"], descr["value"]


# </editor-fold>

# <editor-fold desc="Test area">
# reprow_cveId='CVE-1999-0524'
# x=db.session.query(exists().where(CVE.CVEId == reprow_cveId)).scalar()
# y = db.session.query(CVE).filter_by(CVEId=reprow_cveId).one()
# z=  CVE.query.filter_by(CVEId=reprow_cveId).one()
# print (z.CVEId, z.status)

for x in v_report("Json_texts/report1.json"):
  print(x)

# db.create_all()
# x = CAPEC_excel_insertData('xlsx_texts/CAPEC-Domains of Attack-3000.xlsx')
# print('Return: {}'.format(x))
# for xx in CAPEC.query.all():
#     print(xx.id, xx.capecId, xx.name)

# x = CWE_excel_insertData('xlsx_texts/CWE-Research Concepts-1000.xlsx')
# print('Return: {}'.format(x))
# for xx in CWE.query.all():
#     print(xx.id, xx.CWEId, xx.name)

# x = CVE_excel_insertData('xlsx_texts/CVE-allitems.xlsx')
# print('Return: {}'.format(x))
# for xx in CVE.query.all():
#     print(xx.id, xx.CVEId, xx.status)

# </editor-fold>
