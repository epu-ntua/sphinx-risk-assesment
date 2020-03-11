from app import db
from app.models import CAPEC, CWE, CVE, VReport, Association
import openpyxl
import json
import requests

# <editor-fold desc="Insert all CAPEC records from Excel">
def CAPEC_excel_insertData(capecexcelpath):
    theFile = openpyxl.load_workbook(capecexcelpath)
    currentSheet = theFile.active
    for row in currentSheet.iter_rows(min_row=2, values_only=True):
        if row[0] is not None:  # We need to check that the cell is not empty.
            # id = db.Column(db.Integer, primary_key=True, autoincrement=True)
            # todo check if the records already exists in db
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
        if row[0] is not None:  # We need to check that the cell is not empty.
            # id = db.Column(db.Integer, primary_key=True, autoincrement=True)
            # todo check if the records already exists in db
            my_row = CWE(CWEId=row[0], name=row[1], weakness=row[2], abstraction=row[3], status=row[4],
                         description=row[5], extendedDescription=row[6], relatedWeaknesses=row[7],
                         weaknessOrdinalities=row[8], applicablePlatforms=row[9], backgroundDetails=row[10],
                         alternateTerms=row[11], modesOfIntroduction=row[12], exploitationFactors=row[13],
                         likelihoodOfExploit=row[14], commonConsequences=row[15], detectionMethods=row[16],
                         potentialMitigations=row[17], observedExamples=row[18], functionalAreas=row[19],
                         affectedResources=row[20], taxonomyMappings=row[21], relatedAttackPatterns=row[22],
                         notes=row[23])
            db.session.add(my_row)
    db.session.commit()
    return 1


# </editor-fold>

# <editor-fold desc="Insert information from VAaaS Report">
def v_report(fpath):
    with open(fpath, "r") as fp:
        obj = json.load(fp)
        # todo: check what must be changed if a report has more than one device
        if obj["report"]["@id"] is not None:
            my_report = VReport(
                reportId=obj["report"]["@id"],
                creation_time=obj["report"]["creation_time"] if obj["report"]["creation_time"] is not None else "",
                name=obj["report"]["name"] if obj["report"]["name"] is not None else "")
            for item in obj['report']['report']['results']['result']:
                if item["nvt"]["cve"] == "NOCVE":
                    continue
                else:
                    # todo run NVD API
                    response = requests.get("https://services.nvd.nist.gov/rest/json/cve/1.0/" + item["nvt"]["cve"])
                    if response is not None and response.status_code == 200:
                        myNVDreport = response.json()
                        for cve_desc, cveId, cwe in get_cwe_codes(myNVDreport):
                            cwe_number = cwe.split("CWE-", 1)[1].strip()
                            if cwe_number.isnumeric():
                                print(cve_desc, cveId, cwe_number)
                    # todo update CVE table based on responds

                    # todo find DISTINCT CAPEC values based on CWEs
                    # ######## for CWE - get CAPEC patterns
                    #             for x, y in my_excel_read('app/xlsx_texts/CAPEC-Domains of Attack-3000.xlsx', 'R', cwe_number):
                    #                 print(x, y)
                    # todo CWE -> insert VReport - CVE association
                    my_cve_code = CVE.query.filter_by(CVEId=item["nvt"]["cve"])
                    my_association = Association(
                        VReport_assetID=item["host"]["asset"]["@asset_id"] if item["host"]["asset"][
                                                                                  "@asset_id"] is not None else "",
                        VReport_assetIp=obj["ip"] if obj["ip"] is not None else "",
                        VReport_port=item["port"] if item["port"] is not None else "",
                        comments=item["nvt"]["@oid"] if item["nvt"]["@oid"] is not None else "")
                    my_association.cve_s = my_cve
                    my_report.CVEs.append(my_association)
                    db.session.add(my_report)
            db.session.commit()
            return 1
# </editor-fold>

# <editor-fold desc="NVD API get_cwe_codes">
def get_cwe_codes(myreport):
    for item in myreport['result']['CVE_Items']:
        itemdescr = item["cve"]["description"]["description_data"][0]["value"]
        for problem in item["cve"]['problemtype']['problemtype_data']:
            for descr in problem['description']:
                yield itemdescr, item["cve"]["CVE_data_meta"]["ID"], descr["value"]
# </editor-fold>

# <editor-fold desc="Test area">
## db.create_all()
# x = CAPEC_excel_insertData('xlsx_texts/CAPEC-Domains of Attack-3000.xlsx')
# print('Return: {}'.format(x))

# *** Read
# for xx in CAPEC.query.all():
#     print(xx.id, xx.capecId, xx.name)


# db.create_all()
# x = CWE_excel_insertData('xlsx_texts/CWE-Research Concepts-1000.xlsx')
# print('Return: {}'.format(x))

# *** Read
# for xx in CWE.query.all():
#     print(xx.id, xx.CWEId, xx.name)

# </editor-fold>
