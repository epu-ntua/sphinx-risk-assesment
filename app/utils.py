from app import db
from app.models import CAPEC
import openpyxl


######## Insert all CAPEC records from Excel
def my_excel_read(xpath):
    theFile = openpyxl.load_workbook(xpath)
    currentSheet = theFile.active
    for row in currentSheet.iter_rows(min_row=2, values_only=True):
        if row[0] is not None:  # We need to check that the cell is not empty.
            # id = db.Column(db.Integer, primary_key=True, autoincrement=True)
            my_row = CAPEC(capecId=row[0], name=row[1], abstraction=row[2], status=row[3], description=row[4],
                           alternateTerms=row[5], likelihoodOfAttack=row[6], typicalSeverity=row[7],
                           relatedAttackpatterns=row[8], executionFlow=row[9], prerequisites=row[10],
                           skillsRequired=row[11], resourcesRequired=row[12], indicators=row[13], consequences=row[14],
                           mitigations=row[15], exampleInstances=row[16], relatedWeaknesses=row[17],
                           taxonomyMappings=row[18], notes=row[19])
            db.session.add(my_row)
    db.session.commit()
    return 1


# x = my_excel_read('xlsx_texts/CAPEC-Domains of Attack-3000.xlsx')
# print('Return: {}'.format(x))

# db.create_all()
print(CAPEC.query.order_by(CAPEC.id).all())

