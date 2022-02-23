import os

from flask import render_template, request, redirect, jsonify, Response, flash
from multiprocessing import Process
from app.producer import *
from app.globals import *
from app.utils import *
from app.forms import *
from app import app
from app.utils.utils_communication import *
from app.utils.utils_risk_assessment import *
from app.utils.utils_risk_profiles import get_RiskML_value


@app.route('/alerts/new_asset/')
def alerts_new_asset():
    print("--HERe")
    try:
        repo_asset_first = RepoAsset.query.first()
    except SQLAlchemyError:
        return Response("SQLAlchemyError", 500)
    result = send_alert_new_asset(repo_asset_first)
    print("--HERe 2", result)

    return Response(status=200)

@app.route('/alerts/old_asset/')
def alerts_old_asset():
    try:
        repo_asset_first = RepoAsset.query.first()
    except SQLAlchemyError:
        return Response("SQLAlchemyError", 500)
    send_alert_old_asset(repo_asset_first)
    return Response(status=200)

@app.route('/alerts/info_update/')
def alerts_info_update():
    try:
        repo_asset_first = RepoAsset.query.first()
    except SQLAlchemyError:
        return Response("SQLAlchemyError", 500)

    try:
        repo_threat_first = RepoThreat.query.first()
    except SQLAlchemyError:
        return Response("SQLAlchemyError", 500)

    send_alert_info_update_needed(repo_asset_first, repo_threat_first, threat_exposure_info=1,
                                  threat_materialisation_info=1)
    return Response(status=200)

@app.route('/mlflow/info/')
def mlflow_info():
    experiments = ["asset.variety.Server", "asset.variety.User Dev"]
    experiments = "asset.variety.Server"
    current_dict = os.getcwd()
    dict_to_save = os.path.join(current_dict, "mlflow_info")
    print("PATH IS --------------", dict_to_save, flush=True)
    get_ml_flow_info(experiments, dict_to_save)
    return Response(status=200)

@app.route('/mlflow/data/test/')
def mlflow_data_test():
    response = get_mlflow_experiment()

    print("Response is --------------", response, flush=True)
    return Response(status=200)\

@app.route('/risk/siem/alert/test/')
def risk_siem_alert_test():
    rep = json.loads('{"attackType":"Worm", "agent.ip":"10.10.50.41"}')
    xx = siem_alerts(rep)
    # response = get_mlflow_experiment()

    print("Response is --------------", flush=True)
    print(xx)

    return Response(status=200)

@app.route('/mlflow/data/clean/test/')
def mlflow_data_clean_test():
    result = get_RiskML_value([], [], "action.Hacking", "5021")
    result = get_RiskML_value(["action.malware.variety.Exploit misconfig", "action.malware.variety.Exploit vuln"], [], "asset.variety.Server", "5010")
    result = get_RiskML_value(["action.malware.variety.Exploit misconfig", "action.malware.variety.Exploit vuln"], [],
                              "action.Malware", "5020")
    result = get_RiskML_value(["action.malware.variety.Exploit misconfig", "action.malware.variety.Exploit vuln"], [],
                              "action.malware.variety.Ransomware", "5022")
    # response = get_mlflow_experiment()
    print("Response is --------------", result, flush=True)
    return Response(status=200)


@app.route('/write_topic')
def write_topic_to_kafka():
    SendKafkaReport("positive")
    # generate_checkpoint(5, kafka)
    # kafka_connect(5)
    # CreateToken()
    return Response('Done' + str(datetime.utcnow()), mimetype="text/event-stream")


@app.route('/siem_event_alert', methods=['POST'])
def siem_event_alert():
    if request.method == 'POST':
        requestedservice = request.args.get('requestedservice', None)
        requestedTicket = request.args.get('requestedTicket', None)

        url = "http://sphinx-kubernetes.intracom-telecom.com:8080/SMPlatform/manager/rst/Authorization"
        params = {
            'requestedservice': requestedservice,
            'requestedTicket': requestedTicket
        }
        response = requests.request("GET", url, params=params)
        print("---------------------------------------", flush=True)
        print("Authorisation result is: ", response.status_code, flush=True)

        if response.status_code == 200:
            # Validate the input is correct
            # Currently not certain about what the input will be
            return Response(status=200)
        else:
            return Response(status=400)


@app.route('/ID_visualisation_data')
def ID_visualisation_data():
    requestedservice = "RCRA"
    # requestedTicket = request.args.get('requestedTicket', None)
    requestedTicket = request.headers.get('Authorization')
    requestedTicket = requestedTicket[7:]
    # serviceManagerUrl = request.args.get('serviceUrl', None)

    # url = "http://sphinx-kubernetes.intracom-telecom.com:80/SMPlatform/manager/rst/Authorization"
    url = os.environ.get('SM_IP') + "/Authorization"
    params = {
        'requestedservice': requestedservice,
        'requestedTicket': requestedTicket
    }
    print("---------------------------------------", flush=True)
    print(url)
    response = requests.request("GET", url, params=params)
    print("---------------------------------------", flush=True)
    print("Authorisation result is: ", response.status_code, flush=True)

    if response.status_code == 200:
        print("Authorisation is accepted", flush=True)
        print("---------------------------------------", flush=True)

        to_send = make_visualisation()
        print(to_send, flush=True)
        return to_send

    else:
        print("Authorisation is declined", flush=True)
        print("---------------------------------------", flush=True)
        return Response(status=400)


@app.route('/dss_alert_test')
def dss_alert_test():
    alert = send_dss_alert()
    return alert


@app.route('/save_report')
def save_report():
    status = sendDSSScore()
    if status == 0:
        return Response(status=200)
    else:
        return Response(status=500)


@app.route('/save_report_test')
def save_report_test():
    status = sendDSSScoreTest()
    if status == 0:
        return Response(status=200)
    else:
        return Response(status=500)

@app.route('/get_kafka_information/<topic>/')
def get_kafka_information(topic):
    # kafka = KafkaInitialiser()
    result = get_kafka_data_print_test(topic)
    print(result)
    return Response(result, mimetype="text/event-stream")


@app.route('/kb_cve')
def kb_cve():
    url = "http://sphinx-kubernetes.intracom-telecom.com:8080/SMPlatform/manager/rst/Authentication"
    payload = {
        'username': 'testR1',
        'password': 'testR1123!@'
    }
    response = requests.request("POST", url, data=payload)
    selectedticket = response.json()
    requestedTicket = selectedticket["data"]

    print("---------------------------------------", flush=True)
    print("Login ticket is: ", requestedTicket, flush=True)
    print("---------------------------------------", flush=True)

    # Need knowledge base url
    # id
    # name
    # keywords
    # This search the STYX objects for the id/name/keyword for example this searches for CVE-2018-4998
    url = "http://:re4000/api/v1/objects/id/CVE-2018-4998"
    params = {
        'requestedservice': 'KB',
        'requestedTicket': requestedTicket
    }
    response = requests.request("GET", url, params=params)
    reqdata = response.json()

    print("---------------------------------------", flush=True)
    print("KB response is: ", reqdata, flush=True)
    print("---------------------------------------", flush=True)

    return reqdata


@app.route('/test/dynamic/risk/', methods=['GET', 'POST'])
def test_dynamic_risk():
    if request.method == 'POST':
        return redirect('/test/dynamic/risk/')
    else:
        start_risk_assessment(1, 1)
        return Response(200)


@app.route('/test_repo/dtm/', methods=['GET', 'POST'])
def test_repo():
    if request.method == "POST":
        return redirect("/test_repo/dtm/")
    else:
        found_flag = 0
        repo_assets = RepoAsset.query.all()
        for repo_asset in repo_assets:
            if (repo_asset == "1"):
                found_flag = 1
                repo_asset.last_touch_date = ""
                if (repo_asset.verified == False):
                    send_asset_id_alert(repo_asset)

        if found_flag == 0:
            new_asset = RepoAsset(name="", last_touch_date="")
            db.session.add(new_asset)

        db.session.commit()


@app.route('/RCRAgetFCDEversion')
def RCRAgetFCDEversion():
    url = "http://sphinx-kubernetes.intracom-telecom.com:8080/SMPlatform/manager/rst/Authentication"
    payload = {
        'username': 'testR1',
        'password': 'testR1123!@'
    }
    response = requests.request("POST", url, data=payload)
    selectedticket = response.json()
    requestedTicket = selectedticket["data"]

    print("---------------------------------------", flush=True)
    print("Login ticket is: ", requestedTicket, flush=True)
    print("---------------------------------------", flush=True)

    # # this step was omitted in D6.2
    # url1 = "http://sphinx-kubernetes.intracom-telecom.com:8080/SMPlatform/manager/rst/ServiceInfo"
    # params = {
    #     'reqservicename': 'DEMOCOMPONENT2'
    # }
    # response2 = requests.request("GET", url1, params=params)
    # selected_service = response2.json()
    # serviceid =selected_service['service']['aaainfo']['id'][0]

    # This is called in FCDEgetversion
    urlx = "http://forensic-engine:5003/FCDEgetversion"
    params = {
        'requestedservice': 'FDCE',
        'requestedTicket': requestedTicket
    }
    responsex = requests.request("GET", urlx, params=params)
    reqdata = responsex.json()

    print("---------------------------------------", flush=True)
    print("FDCE response is: ", reqdata, flush=True)
    print("---------------------------------------", flush=True)

    #
    # url2 = "http://127.0.0.1:5003/FCDEgetversion"
    # params = {
    #     'requestedservice': "FCDEgetversion",
    #     'requestedTicket': requestedTicket
    # }
    # response3 = requests.request("GET", url2, params=params)
    # reqdata = response3.json()

    return reqdata


@app.route('/RCRAgetversion/')
def RCRAgetversion():
    requestedservice = request.args.get('requestedservice', None)
    authTicket = request.args.get('authTicket', None)

    url = "http://sphinx-kubernetes.intracom-telecom.com:8080/SMPlatform/manager/rst/Authorization"
    params = {
        'requestedservice': requestedservice,
        'requestedTicket': authTicket
    }
    response = requests.request("GET", url, params=params)
    if response == 200:
        return jsonify({'name': 'RCRA', 'Version': '2020.2.3'})
    else:
        return jsonify({'name': 'RCRA', 'Version': "No Authorisation"})
