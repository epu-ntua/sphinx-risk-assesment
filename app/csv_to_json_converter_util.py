import os

# csvFilePath = r'C:\Users\mkont\PycharmProjects\riskassessmentflask\app\fixtures\fixtures-to_convert\repo_service.csv'
# jsonFilePath = r'C:\Users\mkont\PycharmProjects\riskassessmentflask\app\fixtures\repo_service.json'

import csv
import json


def csv_to_json(csvFilePath, jsonFilePath):
    jsonArray = []

    # read csv file
    with open(csvFilePath, encoding='utf-8') as csvf:
        # load csv file data using csv library's dictionary reader
        csvReader = csv.DictReader(csvf)

        # convert each csv row into python dict
        for row in csvReader:
            # add this python dict to json array
            jsonArray.append(row)

    # convert python jsonArray to JSON String and write to file
    with open(jsonFilePath, 'w', encoding='utf-8') as jsonf:
        jsonString = json.dumps(jsonArray, indent=4)
        jsonf.write(jsonString)


def convert_csv(fileName):
    ''' This functions converts csv files to json.
        Inputs needed only filename without file extension
        Input file needs to be in app/fixtures/fixtures-to_convert
        Output will be put in app/fixtures
    '''
    csvFilePath = os.path.join(os.getcwd(), "app", "fixtures", "fixtures-to_convert", fileName + ".csv")
    jsonFilePath = os.path.join(os.getcwd(), "app", "fixtures", fileName + ".json")
    csv_to_json(csvFilePath, jsonFilePath)
