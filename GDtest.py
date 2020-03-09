import json
import openpyxl
import requests


def v_report(fpath):
    with open(fpath, "r") as fp:
        obj = json.load(fp)
        ip_test = obj["ip"]
        print(ip_test)
        for item in obj['report']['report']['results']['result']:
            print(item["host"]["asset"]["@asset_id"],
                  ' - ' + item["nvt"]["cvss_base"] + ' - ' + item["nvt"]["cve"] + ' - ' + item["nvt"]["@oid"],
                  ' - ' + item["name"])


def my_excel_read(xpath, xcol, cwe_code):
    theFile = openpyxl.load_workbook(xpath)
    print(theFile.sheetnames)
    print("All sheet names {} ".format(theFile.sheetnames))
    currentSheet = theFile.active
    # for rowidx in range(1, currentSheet.max_row + 1):
    # ws['B'] will return all cells on the B column until the last one (similar to max_row but it's only for the B column)
    for cell in currentSheet[xcol]:
        if cell.value is not None:  # We need to check that the cell is not empty.
            if cwe_code in cell.value:  # Check if the value of the cell contains the text 'Table'
                # print('Found header with name: {} at row: {} and column: {}. In cell {}'.format(cell.value, cell.row, cell.column, cell))
                yield currentSheet.cell(cell.row, 1).value, currentSheet.cell(cell.row, 2).value


#v_report("app/Json_texts/report1.json")
# for x in my_excel_read('app/xlsx_texts/CWE-Research Concepts-1000.xlsx', 'R', 'CVE-1999-0524'):
#    print(x)
# for x, y in my_excel_read('app/xlsx_texts/CAPEC-Domains of Attack-3000.xlsx', 'R','200'):
#     print(x,y)

response = requests.get("https://services.nvd.nist.gov/rest/json/cve/1.0/CVE-1999-0524")
if response.status_code == 200:
    myreport = response.json()
    # print(myreport['result']['CVE_Items'][0]["cve"]['problemtype']['problemtype_data'][0]['description'][0]['value'])
    for item in myreport['result']['CVE_Items']:
        print(item["cve"]["ID"])
        for problem in item["cve"]['problemtype']['problemtype_data']:
            for descr in problem['description']:
                print(item["cve"]["ID"] + ' - ' + descr["value"])

# print(response.json())
