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

# region Insert information from Excel files
# region Insert all CAPEC records from Excel
from app.producer import SendKafkaReport
import pyAgrum as gum




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
