# import requests
# from flask import Flask, jsonify
#
# from flask_restful import Resource
#
#
# class RCRAgetFCDEversion(Resource):
#     #def __init__(self, username, password):
#     #    self.username = username
#     #    self.password = password
#
#     def get(self):
#         url = "http://sphinx-kubernetes.intracom-telecom.com:8080/SMPlatform/manager/rst/Authentication"
#         payload = {}
#         headers = {
#             'username': 'testR1',
#             'password': 'testR1123!@'
#         }
#         response = requests.request("GET", url, headers=headers, data=payload)
#         if response.ok:
#             response.json()
#             ticket = response.get("data")
#             if len(ticket)==128:
#                 url1 = "http://sphinx-kubernetes.intracom-telecom.com:8080/SMPlatform/manager/rst/ServiceInfo"
#                 payload = {}
#                 headers = {
#                     'reqservicename': 'FCDEgetversion'
#                 }
#                 response2 = requests.request("GET", url1, headers=headers, data=payload)
#                 if response2.ok:
#                     response.json()
#                     serviceid = response2.get("id")
#                     response3 = requests.get('http://127.0.0.1:5002/RCRAgetversion',params=(serviceid, ticket))
#                     return response3
#                 else:
#                     return -3
#             else:
#                 return -2
#         else:
#             return -1
#
#
# class RCRAgetversion(Resource):
#     def __init__(self, requestedservice, authTicket):
#         self.requestedservice = requestedservice
#         self.authTicket = authTicket
#
#     def get(self):
#         url = "http://sphinx-kubernetes.intracom-telecom.com:8080/SMPlatform/manager/rst/Authorization"
#         headers = {
#             'requestedservice': self.requestedservice,
#             'requestedTicket': self.authTicket
#             }
#         response = requests.request("GET", url, headers=headers)
#         if response == 200:
#             return jsonify({'name': 'RCRA', 'Version': '2020.2.3'})
#         else:
#             return jsonify({'name': 'RCRA', 'Version': "No Authorisation"})
#
#
