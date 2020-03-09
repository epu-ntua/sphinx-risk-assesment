from app import db
from app.models import CAPEC
import openpyxl


def my_excel_read(xpath, xcol, cwe_code):
    theFile = openpyxl.load_workbook(xpath)
    currentSheet = theFile.active
    for cell in currentSheet[xcol]:
        if cell.value is not None:  # We need to check that the cell is not empty.
            if cwe_code in cell.value:  # Check if the value of the cell contains the text 'Table'
                yield currentSheet.cell(cell.row, 1).value, currentSheet.cell(cell.row, 2).value


#
# for x, y in my_excel_read('xlsx_texts/CAPEC-Domains of Attack-3000.xlsx', 'R','200'):
#     print(x,y)

# for x, y in my_excel_read('xlsx_texts/CAPEC-Domains of Attack-3000.xlsx', 'R', '200'):
my_row = CAPEC(capecId=int(116), name='Excavation')
db.session.add(my_row)
db.session.commit()
