import requests
from flask import Flask, jsonify

from flask_restful import Resource


class RCRAgetFCDEversion(Resource):
    def __init__(self, username, password):
        self.username = username
        self.password = password

    def get(self):
        response = requests.get('http://service-manager:8080/SMPlatform/manager/rst/Authentication', auth=(self.username, self.password))
        if response.ok:
            response.json()
            if 'data' in response['post']['responses']['200']['content']['application/json']['examples']['success']['value']:
                ticket = response['post']['responses']['200']['content']['application/json']['examples']['success']['value']['data']
                if len(ticket)==128:
                    response2 = requests.get('http://service-manager:8080/SMPlatform/manager/rst/ServiceInfo',
                                            params=(ticket, 'serviceName'))
                    if response2.ok:
                        serviceid = response2['xxxxxxxxxxxxxxxxxxxxxx']
                        response3 = requests.get('http://127.0.0.1:5002/RCRAgetversion',params=(serviceid, ticket))
                        return response3
                    else:
                        return -4
                else:
                    return -3
            else:
                return -2
        else:
            return -1


class RCRAgetversion(Resource):
    def __init__(self, serviceid, authTicket):
        self.serviceid = serviceid
        self.authTicket = authTicket

    def get(self):
        response = requests.get('http://service-manager:8080/SMPlatform/manager/rst/Authorization',
                                params=(self.serviceid, self.authTicket))
        if response == 200:
            return jsonify({'name': 'RCRA', 'Version': '2020.2.3'})
        else:
            return jsonify({'name': 'RCRA', 'Version': "No Authorisation"})


