from app import db
from app.models import CAPEC
from app.models import CWE
import openpyxl


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


# db.create_all()
# x = CAPEC_excel_insertData('xlsx_texts/CAPEC-Domains of Attack-3000.xlsx')
# print('Return: {}'.format(x))

# *** Read
# for xx in CAPEC.query.all():
#     print(xx.id, xx.capecId, xx.name)
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


# db.create_all()
# x = CWE_excel_insertData('xlsx_texts/CWE-Research Concepts-1000.xlsx')
# print('Return: {}'.format(x))

# *** Read
for xx in CWE.query.all():
    print(xx.id, xx.CWEId, xx.name)
# </editor-fold>
