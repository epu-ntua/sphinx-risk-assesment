from app import app
from flask import render_template, request, redirect, jsonify, Response, flash
from app.utils import *
from app.globals import *
# from app.producer import generate_checkpoint
from app.producer import *
from app.client import *
import json
from app.forms import *
from multiprocessing import Process

@app.context_processor
def serverInfo():
    return dict(serverAddress=serverAddress, serverPort=serverPort)

@app.before_first_request
def active_kafka_listeners():
    print("---- Before First Run ----", flush = True)
    # get_kafka_data_print_test("rcra-report-topic")
    t1 = Process(target=get_kafka_data_print_test, args=("rcra-report-topic",))
    # t2 = Process(target=get_kafka_data_print_test, args=("dtm-alert",))
    t1.start()
    # t2.start()


@app.route('/')
@app.route('/home/')
def entry_page():
    return render_template('entry_page.html')


@app.route('/assets/', defaults={"asset": -1})
@app.route('/assets/<asset>/', methods=['GET', 'POST'])
def assets(asset):
    if request.method == 'POST':
        if asset != -1:
            print(request.form)

            toRedirect = "vulnerabilities/"
            return redirect(toRedirect)
        else:
            return redirect("/assets/")
    else:
        # assetsArray = get_assets()
        # # print(assetsArray[0].VReport_assetID)
        #
        # proposedCVEArray = []
        # # print(assetsArray)
        # if assetsArray != -1:
        #     for tempAsset in assetsArray:
        #         proposedCVEArray.append(get_cve_recommendations(tempAsset.VReport_assetID))
        #
        # # Still need an fuction that will get the other CVE, or preferably being able to add CVE one by one by hand
        # othersCVEArray = []
        # for tempAsset in assetsArray:
        # othersCVEArray.append()

        assetsArray = [{"VReport_assetID": "85"}, {"VReport_assetID": "80"}]
        proposedCVEArray = ["2020-13720", "2020-13730"]
        othersCVEArray = ["2020-12350"]

        return render_template('assets.html', asset=asset, assets=assetsArray, proposedCVEArray=proposedCVEArray,
                               othersCVEArray=othersCVEArray)


@app.route('/assets/<asset>/vulnerabilities/', defaults={"asset": -1, "vulnerability": -1})
@app.route('/assets/<asset>/vulnerabilities/<vulnerability>/', methods=['GET', 'POST'])
def vulnerabilities(asset, vulnerability):
    if request.method == 'POST':
        i = 5
        toRedirect = "threats/"
        return redirect(toRedirect)
    else:
        # assetsArray = get_assets()
        # print(assetsArray[0].VReport_assetID)

        assetsArray = [{"VReport_assetID": "85"}, {"VReport_assetID": "80"}]

        return render_template('vulnerabilities.html', asset=asset, vulnerability=vulnerability, assets=assetsArray)


@app.route('/assets/<asset>/vulnerabilities/<vulnerability>/threats/',
           defaults={"asset": -1, "vulnerability": -1, "threat": -1})
@app.route('/assets/<asset>/vulnerabilities/<vulnerability>/threats/<threat>/', methods=['GET', 'POST'])
def threats(asset, vulnerability, threat):
    if request.method == 'POST':
        i = 5
    else:
        # assetsArray = get_assets()
        # print(assetsArray[0].VReport_assetID)

        assetsArray = [{"VReport_assetID": "85"}, {"VReport_assetID": "80"}]

        return render_template('threats.html', asset=asset, vulnerability=vulnerability, threat=threat,
                               assets=assetsArray)


@app.route('/gira_assess/', methods=['GET', 'POST'])
def gira_assess():
    if request.method == 'POST':
        return redirect("/gira_assess/")
    else:
        return render_template('gira_assess.html')


@app.route('/gira_assess/gira_assess_exposure/', methods=['GET'])
def gira_assess_exposure():
    exposure_instances = ModelThreatExposure.query.all()
    return render_template('gira_assess_exposure.html', exposure_instances=exposure_instances)


@app.route('/gira_assess/<exposure_id>/gira_assess_response/', methods=['GET', 'POST'])
def gira_assess_response(exposure_id):
    if request.method == 'POST':
        materialisation_instance = ModelThreatMaterialisation.query.filter_by(instance_id=exposure_id).first()

        instance_responses = ModelIncidentResponse.query.filter(
            ModelIncidentResponse.materialisation_instance.any(id=exposure_id)).all()
        # Sent Data are a dict with one entry containing the exposureIdToSend and the rest contain
        # The ids of the responses to be added to the keys and values dictate what to do [nothing, delete, add]
        for sent in request.form:
            # Skip exposureId
            if sent == "exposureIdToSend":
                continue

            if request.form[sent] == "nothing":
                continue
            elif request.form[sent] == "add":
                to_add_response = ModelIncidentResponse.query.filter_by(id=sent).first()
                materialisation_instance.incident_responses.append(to_add_response)
            elif request.form[sent] == "delete":
                to_remove_response = ModelIncidentResponse.query.filter_by(id=sent).first()
                materialisation_instance.incident_responses.remove(to_remove_response)

        db.session.commit()

        return redirect('/gira_assess/' + exposure_id + '/gira_assess_materialisation/')
    else:
        selected_exposure = ModelThreatExposure.query.filter_by(id=exposure_id).first()
        all_responses = ModelIncidentResponse.query.all()

        instance_responses = ModelIncidentResponse.query.filter(
            ModelIncidentResponse.materialisation_instance.any(id=exposure_id)).all()

        return render_template('gira_assess_response.html', all_responses=all_responses,
                               selected_exposure=selected_exposure, instance_responses=instance_responses)


# For xx% to appear in template need to create all entries at the same time at the start and then change values instead
# of creating when clicking.
@app.route('/gira_assess/<exposure_id>/gira_assess_materialisation/', methods=['GET', 'POST'])
def gira_assess_materialisation(exposure_id):
    if request.method == 'POST':
        if request.form["is_threat_materialising"] == "false":
            is_threat_materialising_bool = False
            # print("false")
        elif request.form["is_threat_materialising"] == "true":
            is_threat_materialising_bool = True
            # print("true")
        else:
            return Response(401)

        existing_entry = ModelThreatMaterialisationInstanceEntry.query.filter_by(table_id=int(request.form["table_id"]),
                                                                                 responses_id=int(
                                                                                     request.form["responses_id"]),
                                                                                 materialisations_id=int(request.form[
                                                                                                             "materialisations_id"]),
                                                                                 is_threat_materialising=is_threat_materialising_bool
                                                                                 ).first()
        if existing_entry:
            existing_entry.prob_threat_materialising = request.form["prob_threat_materialising"]
            existing_entry.prob_likelihood = request.form["prob_likelihood"]
            existing_entry.prob_likelihood_other = request.form["prob_likelihood_other"]
            existing_entry.prob_posterior = request.form["prob_posterior"]
        else:
            # Process each new entry of the table
            # is_threat_materialising_bool = request.form["is_threat_materialising"]

            # print("Data")
            # for entry in request.form.items():
            #     print(entry)

            # print(is_threat_materialising_bool)
            to_add_entry = ModelThreatMaterialisationInstanceEntry(table_id=int(request.form["table_id"]),
                                                                   responses_id=int(request.form["responses_id"]),
                                                                   materialisations_id=int(request.form[
                                                                                               "materialisations_id"]),
                                                                   prob_threat_materialising=int(request.form[
                                                                                                     "prob_threat_materialising"]),
                                                                   prob_likelihood=int(request.form["prob_likelihood"]),
                                                                   prob_likelihood_other=int(request.form[
                                                                                                 "prob_likelihood_other"]),
                                                                   prob_posterior=int(request.form["prob_posterior"]),
                                                                   is_threat_materialising=is_threat_materialising_bool)

            db.session.add(to_add_entry)
        db.session.commit()
        return Response(status=201)
    else:
        # NOT USING THE CORRECT KEYS TO SEARCH FOR THE RESPONSES AND SUCH

        selected_exposure = ModelThreatExposure.query.filter_by(id=exposure_id).first()

        # materialisation_instance = GiraThreatMaterialisationInstance.query.filter_by(instance_id=id_of_exposure).first()

        instance_responses = ModelIncidentResponse.query.filter(
            ModelIncidentResponse.materialisation_instance.any(id=exposure_id)).all()

        instance_materialisations = ModelThreatMaterialisation.query.filter(
            ModelThreatMaterialisation.materialisation_instance.any(id=exposure_id)).all()
        # print(instance_materialisations)

        instance_materialisations_entries = ModelThreatMaterialisationInstanceEntry.query.filter_by(
            table_id=exposure_id).all()

        return render_template('gira_assess_materialisation.html', selected_exposure=selected_exposure,
                               instance_materialisations=instance_materialisations,
                               instance_responses=instance_responses,
                               instance_materialisations_entries=instance_materialisations_entries)


@app.route('/gira_assess/<exposure_id>/gira_assess_materialisation/check_table/', methods=['POST'])
def gira_assess_materialisation_check_table(exposure_id):
    if request.method == 'POST':
        table_id = request.form["tableId"]
        # table_to_check = GiraThreatMaterialisationInstance.query.filter_by(id = table_id)

        instance_responses_count = ModelIncidentResponse.query.filter(
            ModelIncidentResponse.materialisation_instance.any(id=table_id)).count()

        instance_materialisations_count = ModelThreatMaterialisation.query.filter(
            ModelThreatMaterialisation.materialisation_instance.any(id=table_id)).count()

        target_entries_count = instance_materialisations_count * instance_responses_count * 2
        current_entries_count = ModelThreatMaterialisationInstanceEntry.query.filter_by(table_id=table_id).count()

        # This could check for the presence of the number itself in each entry but it shouldnt be normally needed
        if target_entries_count == current_entries_count:
            return redirect(
                Response(status=201))  # change to next page when ready /gira_assess/gira_assess_consequences
        else:
            return redirect(request.url)

        print(target_entries_count)
        print(current_entries_count)


@app.route('/gira_assess/gira_assess_consequence/', methods=['GET', 'POST'])
def gira_assess_consequence():
    if request.method == 'POST':
        return redirect("/gira_assess/gira_assess_consequence/")
    else:
        return render_template('gira_assess_consequence.html')


@app.route('/gira_assess/gira_assess_asset_status/', methods=['GET', 'POST'])
def gira_assess_asset_status():
    if request.method == 'POST':
        return redirect("/gira_assess/gira_assess_asset_status/")
    else:
        return render_template('gira_assess_asset_status.html')


@app.route('/gira_assess/gira_assess_asset_impact/', methods=['GET', 'POST'])
def gira_assess_asset_impact():
    if request.method == 'POST':
        return redirect("/gira_assess/gira_assess_asset_impact/")
    else:
        return render_template('gira_assess_asset_impact.html')


@app.route('/gira_assess/gira_assess_objective/', methods=['GET', 'POST'])
def gira_assess_objective():
    if request.method == 'POST':
        return redirect("/gira_assess/gira_assess_objective/")
    else:
        return render_template('gira_assess_objective.html')


@app.route('/gira_overview/', methods=['GET', 'POST'])
def gira_overview():
    if request.method == 'POST':
        return redirect("/gira_overview/")
    else:
        return render_template('gira_overview.html')


@app.route('/gira_overview/gira_threat_exposure/', methods=['GET', 'POST'])
def gira_threat_exposure():
    if request.method == 'POST':

        # Add new Threat Exposure
        to_add_exposure = ModelThreatExposure(name=request.form['name'], description=request.form['description'],
                                              probability=int(request.form['probability']))
        db.session.add(to_add_exposure)
        db.session.flush()

        # print(to_add_exposure.id)

        # Add new Instance of Gira
        to_add_instance = ModelInstance(threat=to_add_exposure.id)
        db.session.add(to_add_instance)
        db.session.flush()

        # Add a new Threat Materialistion Instance
        to_add_materialisation_instance = ModelThreatMaterialisation(instance_id=to_add_instance.id)

        to_add_materialisations_instance_id = request.form['materialisationsToAdd']
        to_add_materialisations_instance_id = json.loads(to_add_materialisations_instance_id)
        print(to_add_materialisations_instance_id)

        # Helper tanble to temporary store all the instances of materialisations
        to_add_materialisations_list = []

        # Query database for each instance of the Gira Materialisations we want
        for materialisation_id in to_add_materialisations_instance_id:
            print("Query")
            print(ModelThreatMaterialisation.query.filter_by(id=materialisation_id[0]).first())
            to_add_materialisations_list.append(
                ModelThreatMaterialisation.query.filter_by(id=materialisation_id[0]).first())

        print("TASTS")
        print(to_add_materialisations_list)
        # Append each gire materialisation to the materialisation instance
        for materialisation in to_add_materialisations_list:
            print("test")
            print(materialisation)
            to_add_materialisation_instance.materialisations.append(materialisation)

        db.session.add(to_add_materialisation_instance)
        db.session.commit()

        return redirect('/gira_overview/gira_threat_exposure/')
    else:
        threats = ModelThreatExposure.query.all()
        materialisations = ModelThreatMaterialisation.query.all()

        return render_template('gira_threat_exposure.html', threats=threats, materialisations=materialisations)


@app.route('/gira_overview/gira_threat_response/', methods=['GET', 'POST'])
def gira_threat_response():
    if request.method == 'POST':
        to_add = ModelIncidentResponse(name=request.form['name'], description=request.form['description'],
                                       default_effect=int(request.form['default_effect']))
        db.session.add(to_add)
        db.session.commit()

        return redirect('/gira_overview/gira_threat_response/')
    else:
        responses = ModelIncidentResponse.query.all()
        return render_template('gira_threat_response.html', responses=responses)


@app.route('/gira_overview/gira_threat_materialisation/', methods=['GET', 'POST'])
def gira_threat_materialisation():
    if request.method == 'POST':
        to_add = ModelThreatMaterialisation(name=request.form['name'], description=request.form['description'],
                                            probability=int(request.form['probability']))
        db.session.add(to_add)
        db.session.commit()

        return redirect('/gira_overview/gira_threat_materialisation/')
    else:
        materialisations = ModelThreatMaterialisation.query.all()
        consequences = ModelConsequence.query.all()

        return render_template('gira_threat_materialisation.html', materialisations=materialisations,
                               consequences=consequences)


@app.route('/gira_overview/gira_consequence/', methods=['GET', 'POST'])
def gira_consequence():
    if request.method == 'POST':
        to_add = ModelConsequence(name=request.form['name'], description=request.form['description'], )
        db.session.add(to_add)
        db.session.commit()

        return redirect('/gira_overview/gira_consequence/')
    else:
        consequences = ModelConsequence.query.all()

        return render_template('gira_consequences.html', consequences=consequences)


@app.route('/gira_overview/gira_asset_status/', methods=['GET', 'POST'])
def gira_asset_status():
    if request.method == 'POST':
        return redirect("/gira_overview/")
    else:
        return render_template('gira_asset_status.html')


@app.route('/gira_overview/gira_asset_impact/', methods=['GET', 'POST'])
def gira_asset_impact():
    if request.method == 'POST':
        return redirect("/gira_overview/")
    else:
        return render_template('gira_asset_impact.html')


@app.route('/gira_overview/gira_objective/', methods=['GET', 'POST'])
def gira_objective():
    if request.method == 'POST':
        return redirect("/gira_overview/")
    else:
        return render_template('gira_objective.html')


@app.route('/gira_overview/gira_result/', methods=['GET', 'POST'])
def gira_result():
    if request.method == 'POST':
        return redirect("/gira_overview/")
    else:
        return render_template('gira_result.html')


@app.route('/asset_dashboard/', methods=['GET', 'POST'])
def asset_dashboard():
    if request.method == 'POST':
        return redirect("/asset_dashboard/")
    else:
        # assetsArray = get_assetsfromrepository()
        # if assetsArray != -1:
        #     return render_template('asset_dashboard.html', assets=assetsArray)
        # else:
        return render_template('asset_dashboard.html')


@app.route('/general_dashboard/asset_view/', defaults={"asset": -1})
@app.route('/general_dashboard/asset_view/<asset>/', methods=['GET', 'POST'])
def general_dashboard_asset_view(asset):
    if request.method == 'POST':
        i = 5
        toRedirect = "/general_dashboard/asset_view/"
        return redirect(toRedirect)
    else:
        # assetsArray = get_assets()

        # print(assetsArray[0].VReport_assetID)
        assetsArray = []
        return render_template('general_dashboard_asset_view.html', asset=asset, assets=assetsArray)


@app.route('/general_dashboard/threat_view/', defaults={"threat": -1})
@app.route('/general_dashboard/threat_view/<threat>/', methods=['GET', 'POST'])
def general_dashboard_threat_view(threat):
    if request.method == 'POST':
        i = 5
        toRedirect = "/general_dashboard/threat_view/"
        return redirect(toRedirect)
    else:
        # assetsArray = get_assets()

        # print(assetsArray[0].VReport_assetID)
        assetsArray = []
        return render_template('general_dashboard_threat_view.html', threat=threat, assets=assetsArray)


@app.route('/general_dashboard/tree_view/', defaults={"threat": -1})
@app.route('/general_dashboard/tree_view/<threat>/', methods=['GET', 'POST'])
def general_dashboard_tree_view(threat):
    if request.method == 'POST':
        i = 5
        toRedirect = "/general_dashboard/threat_view/"
        return redirect(toRedirect)
    else:
        # assetsArray = get_assets()

        # print(assetsArray[0].VReport_assetID)
        assetsArray = []
        return render_template('general_dashboard_tree_view.html', threat=threat, assets=assetsArray)


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


@app.route('/hardwareassets/', defaults={"hardwareasset": -1})
@app.route('/hardwareassets/<hardwareasset>/', methods=['GET', 'POST'])
def hardwareassets(hardwareasset):
    if request.method == 'POST':
        if hardwareasset != -1:
            print(request.form)
            toRedirect = "/hardwareassets/"
            return redirect(toRedirect)
        else:
            return redirect("/hardwareassets/")
    else:
        # hardwareassetsArray = get_hardwareassets()
        return render_template('assets.html', asset=hardwareasset)


@app.route('/asset_discovery')
def asset_discovery():
    return render_template('asset_discovery.html')


@app.route('/asset_Asset_hardware')
def asset_Asset_hardware():
    return render_template('asset_Asset_hardware.html')


@app.route('/asset_Asset_hardware_type')
def asset_Asset_hardware_type():
    return render_template('asset_Asset_hardware_type.html')


@app.route('/asset_Asset_software')
def asset_Asset_software():
    return render_template('asset_Asset_software.html')


@app.route('/asset_Asset_software_type')
def asset_Asset_software_type():
    return render_template('asset_Asset_software_type.html')


@app.route('/asset_Asset_License_Type')
def asset_Asset_License_Type():
    return render_template('asset_Asset_License_Type.html')


@app.route('/asset_organisation_structure')
def asset_organisation_structure():
    return render_template('asset_organisation_structure.html')


@app.route('/asset_organisation_process')
def asset_organisation_process():
    return render_template('asset_organisation_process.html')


@app.route('/asset_Asset_usage_type')
def asset_Asset_usage_type():
    return render_template('asset_Asset_usage_type.html')


@app.route('/asset_Asset_hardware_non_it')
def asset_Asset_hardware_non_it():
    return render_template('asset_Asset_hardware_non_it.html')


@app.route('/asset_Asset_hardware_classification')
def asset_Asset_hardware_classification():
    return render_template('asset_Asset_hardware_classification.html')


@app.route('/asset_configuration_relationship')
def asset_configuration_relationship():
    return render_template('asset_configuration_relationship.html')


@app.route('/write_topic')
def write_topic_to_kafka():
    SendKafkaReport("positive")
    # generate_checkpoint(5, kafka)
    # kafka_connect(5)
    # CreateToken()
    return Response('Done' + str(datetime.utcnow()), mimetype="text/event-stream")

@app.route('/save_report_test')
def save_report_test():
    status = sendDSSScoreTest()
    if status == 0:
        return Response(status=200)
    else:
        return Response(status=500)

# @app.route('/topic/<topicname>')
# def get_messages(topicname):
#     client = get_kafka_client()
#     def events():
#         for i in client.topics[topicname].get_simple_consumer():
#             yield 'data:{0}\n\n'.format(i.value.decode())+
#     return Response(events(), mimetype="text/event-stream")

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


# @app.route('/activate_test')
# def activate_test():
#     status = rcra_1()
#     if status == 0:
#         return Response(status=200)
#     else:
#         return Response(status=500)


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


@app.route('/repo/assets/', methods=['GET', 'POST'])
def view_repo_assets():
    if request.method == 'POST':
        new_asset_form = FormAddRepoAsset()

        if new_asset_form.validate_on_submit():
            if new_asset_form.id.data:
                print("PUT ACTOR", "|", new_asset_form.id.data, "|", flush=True)

                try:
                    to_edit_asset = RepoAsset.query.filter_by(id=new_asset_form.id.data).first()
                except SQLAlchemyError:
                    return Response("SQLAlchemyError when editing records", 500)

                owner_id = None
                verified_by_id = None
                net_group_fk_id = None
                type_fk_id = None

                if new_asset_form.owner.data:
                    owner_id = new_asset_form.owner.data.id

                if new_asset_form.type_fk.data:
                    type_fk_id = new_asset_form.type_fk.data.id

                if new_asset_form.verified_by.data:
                    verified_by_id = new_asset_form.verified_by.data.id

                if new_asset_form.net_group_fk.data:
                    net_group_fk_id = new_asset_form.net_group_fk.id

                to_edit_asset.name = new_asset_form.name.data
                to_edit_asset.description = new_asset_form.description.data
                to_edit_asset.owner = owner_id
                to_edit_asset.location = new_asset_form.location.data
                to_edit_asset.verified = new_asset_form.verified.data
                to_edit_asset.verified_by = verified_by_id
                to_edit_asset.mac_address = new_asset_form.mac_address.data
                to_edit_asset.has_static_ip = new_asset_form.has_static_ip.data
                to_edit_asset.ip = new_asset_form.ip.data
                to_edit_asset.net_group_fk = net_group_fk_id
                to_edit_asset.value = new_asset_form.value.data
                to_edit_asset.loss_of_revenue = new_asset_form.loss_of_revenue.data
                to_edit_asset.additional_expenses = new_asset_form.additional_expenses.data
                to_edit_asset.regulatory_legal = new_asset_form.regulatory_legal.data
                to_edit_asset.customer_service = new_asset_form.customer_service.data
                to_edit_asset.goodwill = new_asset_form.goodwill.data
                to_edit_asset.last_touch_date = new_asset_form.last_touch_date.data
                to_edit_asset.type_fk = type_fk_id


                db.session.commit()
                return redirect("/repo/assets/")
            else:
                print("POST ACTOR", flush=True)
                owner_id = None
                verified_by_id = None
                net_group_fk_id = None
                type_fk_id = None

                if new_asset_form.owner.data:
                    owner_id = new_asset_form.owner.data.id

                if new_asset_form.type_fk.data:
                    type_fk_id = new_asset_form.type_fk.data.id

                if new_asset_form.verified_by.data:
                    verified_by_id = new_asset_form.verified_by.data.id

                if new_asset_form.net_group_fk.data:
                    net_group_fk_id = new_asset_form.net_group_fk.id

                # print(new_actor_form.name.data, flush=True)
                to_add_asset =  RepoAsset(name=new_asset_form.name.data,
                                     description=new_asset_form.description.data,
                                     owner=owner_id,
                                     location=new_asset_form.location.data,
                                     verified=new_asset_form.verified.data,
                                     verified_by=verified_by_id,
                                     mac_address=new_asset_form.mac_address.data,
                                     has_static_ip=new_asset_form.has_static_ip.data,
                                     ip=new_asset_form.ip.data,
                                     net_group_fk=net_group_fk_id,
                                     value=new_asset_form.value.data,
                                     loss_of_revenue=new_asset_form.loss_of_revenue.data,
                                     additional_expenses=new_asset_form.additional_expenses.data,
                                     regulatory_legal=new_asset_form.regulatory_legal.data,
                                     customer_service=new_asset_form.customer_service.data,
                                     goodwill=new_asset_form.goodwill.data,
                                     last_touch_date=new_asset_form.last_touch_date.data,
                                     type_fk=type_fk_id)
                db.session.add(to_add_asset)
                db.session.commit()

                flash('Actor "{}" Added Succesfully'.format(new_asset_form.name.data))
                return redirect("/repo/assets/")
        else:
            print(new_asset_form.errors)
            flash('Error: Validation Error - Couldn\'t add asset, ')
            return redirect("/repo/assets/")






        # new_asset_form = FormAddRepoAsset()
        # print(new_asset_form.errors)
        # print(new_asset_form.validate_on_submit())
        # if not new_asset_form.validate_on_submit():
        #     # print(new_service_form.name.data, flush=True)
        #     print("2")
        #     owner_id = None
        #     verified_by_id = None
        #     net_group_fk_id = None
        #     type_fk_id = None
        #
        #     if new_asset_form.owner.data:
        #         owner_id = new_asset_form.owner.data.id
        #
        #     if new_asset_form.type_fk.data:
        #         type_fk_id = new_asset_form.type_fk.data.id
        #
        #     if new_asset_form.verified_by.data:
        #         verified_by_id = new_asset_form.verified_by.data.id
        #
        #     if new_asset_form.net_group_fk.data:
        #         net_group_fk_id = new_asset_form.net_group_fk.id
        #
        #     to_add_asset = RepoAsset(name=new_asset_form.name.data,
        #                              description=new_asset_form.description.data,
        #                              owner=owner_id,
        #                              location=new_asset_form.location.data,
        #                              verified=new_asset_form.verified.data,
        #                              verified_by=verified_by_id,
        #                              mac_address=new_asset_form.mac_address.data,
        #                              has_static_ip=new_asset_form.has_static_ip.data,
        #                              ip=new_asset_form.ip.data,
        #                              net_group_fk=net_group_fk_id,
        #                              value=new_asset_form.value.data,
        #                              loss_of_revenue=new_asset_form.loss_of_revenue.data,
        #                              additional_expenses=new_asset_form.additional_expenses.data,
        #                              regulatory_legal=new_asset_form.regulatory_legal.data,
        #                              customer_service=new_asset_form.customer_service.data,
        #                              goodwill=new_asset_form.goodwill.data,
        #                              last_touch_date=new_asset_form.last_touch_date.data,
        #                              type_fk=type_fk_id)
        #     db.session.add(to_add_asset)
        #     db.session.commit()
        #
        #     flash('Service "{}" Added Succesfully'.format(new_asset_form.name.data))
        #     return redirect("/repo/assets/")

        return redirect("/repo/assets/")
    else:
        try:
            repo_assets = RepoAsset.query.all()
        except SQLAlchemyError:
            return Response("SQLAlchemyError", 500)

        json_assets = convert_database_items_to_json_table(repo_assets)
        json_assets = json.dumps(json_assets)

        new_asset_form = FormAddRepoAsset()

        print(json_assets)
        return render_template("view_repo_assets.html", repo_assets=json_assets,
                               new_asset_form=new_asset_form)


@app.route('/repo/actors/', methods=['GET', 'POST', 'PUT'])
def view_repo_actors():
    if request.method == 'POST':
        new_actor_form = FormAddRepoActor()

        if new_actor_form.validate_on_submit():
            if new_actor_form.id.data:
                print("PUT ACTOR", "|",new_actor_form.id.data, "|", flush=True)

                try:
                    to_edit_actor = RepoActor.query.filter_by(id=new_actor_form.id.data).first()
                except SQLAlchemyError:
                    return Response("SQLAlchemyError when editing records", 500)

                # print("---------------------")
                # print(to_edit_actor.id.data)
                # print(to_edit_actor.name.data)
                to_edit_actor.name = new_actor_form.name.data
                db.session.commit()
                return redirect("/repo/actors/")
            else:
                print("POST ACTOR", flush=True)
                # print(new_actor_form.name.data, flush=True)
                to_add_actor = RepoActor(name=new_actor_form.name.data)
                db.session.add(to_add_actor)
                db.session.commit()

                flash('Actor "{}" Added Succesfully'.format(new_actor_form.name.data))
                return redirect("/repo/actors/")
        else:
            print(new_actor_form.errors)
            flash('Error: Validation Error - Couldn\'t add actor, ')
            return redirect("/repo/actors/")

    else:
        try:
            repo_actors = RepoActor.query.all()
        except SQLAlchemyError:
            return Response("SQLAlchemyError", 500)
        # print("------------------------------")
        # print(repo_actors, flush=True)
        #
        # print(repo_actors[0].__table__.columns._data.keys(), flush=True)

        json_actors = convert_database_items_to_json_table(repo_actors)
        json_actors = json.dumps(json_actors)
        # print("ACTORS ARE --------")
        # print(json_actors)
        new_actor_form = FormAddRepoActor()
        return render_template("view_repo_actors.html", repo_actors=json_actors, new_actor_form=new_actor_form)


@app.route('/repo/services/', methods=['GET', 'POST'])
def view_repo_services():
    if request.method == 'POST':
        new_service_form = FormAddRepoService()

        if new_service_form.validate_on_submit():
            if new_service_form.id.data:
                # print("PUT ACTOR", "|", new_vulnerability_form.id.data, "|", flush=True)

                try:
                    to_add_service = RepoService.query.filter_by(id=new_service_form.id.data).first()
                except SQLAlchemyError:
                    return Response("SQLAlchemyError when editing records", 500)

                # print("---------------------")
                # print(to_edit_actor.id.data)
                # print(to_edit_actor.name.data)
                to_add_service.name = new_service_form.name.data
                db.session.commit()
                return redirect("/repo/services/")
            else:
                # print("POST ACTOR", flush=True)
                # print(new_actor_form.name.data, flush=True)
                to_add_service = RepoService(name=new_service_form.name.data)
                db.session.add(to_add_service)
                db.session.commit()

                flash('Service "{}" Added Succesfully'.format(new_service_form.name.data))
                return redirect("/repo/services/")
    else:
        try:
            repo_services = RepoService.query.all()
        except SQLAlchemyError:
            return Response("SQLAlchemyError", 500)
        # print("------------------------------")
        # print(repo_actors, flush=True)
        #
        # print(repo_actors[0].__table__.columns._data.keys(), flush=True)

        json_services = convert_database_items_to_json_table(repo_services)
        json_services = json.dumps(json_services)
        print("ACTORS ARE --------")
        print(json_services)
        new_service_form = FormAddRepoService()
        return render_template("view_repo_services.html", repo_services=json_services,
                               new_service_form=new_service_form)


@app.route('/repo/net_groups/', methods=['GET', 'POST'])
def view_repo_net_groups():
    if request.method == 'POST':
        new_net_group_form = FormAddRepoNetGroup()

        if new_net_group_form.validate_on_submit():
            if new_net_group_form.id.data:
                print("PUT ACTOR", "|", new_net_group_form.id.data, "|", flush=True)

                try:
                    to_add_net_group = RepoNetGroup.query.filter_by(id=new_net_group_form.id.data).first()
                except SQLAlchemyError:
                    return Response("SQLAlchemyError when editing records", 500)

                # print("---------------------")
                # print(to_edit_actor.id.data)
                # print(to_edit_actor.name.data)
                to_add_net_group.name = new_net_group_form.name.data
                db.session.commit()
                return redirect("/repo/net_groups/")
            else:
                print("POST ACTOR", flush=True)
                # print(new_actor_form.name.data, flush=True)
                to_add_net_group = RepoNetGroup(name=new_net_group_form.name.data)
                db.session.add(to_add_net_group)
                db.session.commit()

                flash('Net Group "{}" Added Succesfully'.format(new_net_group_form.name.data))
                return redirect("/repo/net_groups/")
    else:
        try:
            repo_net_groups = RepoNetGroup.query.all()
        except SQLAlchemyError:
            return Response("SQLAlchemyError", 500)
        # print("------------------------------")
        # print(repo_actors, flush=True)
        #
        # print(repo_actors[0].__table__.columns._data.keys(), flush=True)

        json_net_groups = convert_database_items_to_json_table(repo_net_groups)
        json_net_groups = json.dumps(json_net_groups)
        # print("ACTORS ARE --------")
        # print(json_actors)
        new_net_group_form = FormAddRepoNetGroup()
        return render_template("view_repo_net_group.html", repo_net_groups=json_net_groups,
                               new_net_group_form=new_net_group_form)


@app.route('/repo/vulnerabilities/', methods=['GET', 'POST'])
def view_repo_vulnerabilities():
    if request.method == 'POST':
        new_vulnerability_form = FormAddRepoVulnerability()

        if new_vulnerability_form.validate_on_submit():
            if new_vulnerability_form.id.data:
                # print("PUT ACTOR", "|", new_vulnerability_form.id.data, "|", flush=True)

                try:
                    to_add_vulnerability = RepoVulnerability.query.filter_by(id=new_vulnerability_form.id.data).first()
                except SQLAlchemyError:
                    return Response("SQLAlchemyError when editing records", 500)

                # print("---------------------")
                # print(to_edit_actor.id.data)
                # print(to_edit_actor.name.data)
                to_add_vulnerability.name = new_vulnerability_form.name.data
                db.session.commit()
                return redirect("/repo/vulnerabilities/")
            else:
                print("POST ACTOR", flush=True)
                # print(new_actor_form.name.data, flush=True)
                to_add_vulnerability = RepoVulnerability(name=new_vulnerability_form.name.data)
                db.session.add(to_add_vulnerability)
                db.session.commit()

                flash('Vulnerability "{}" Added Succesfully'.format(new_vulnerability_form.name.data))
                return redirect("/repo/vulnerabilities/")
    else:
        try:
            repo_services = RepoVulnerability.query.all()
        except SQLAlchemyError:
            return Response("SQLAlchemyError", 500)
        # print("------------------------------")
        # print(repo_actors, flush=True)
        #
        # print(repo_actors[0].__table__.columns._data.keys(), flush=True)

        json_vulnerabilities = convert_database_items_to_json_table(repo_services)
        json_vulnerabilities = json.dumps(json_vulnerabilities)
        # print("ACTORS ARE --------")
        # print(json_actors)
        new_vulnerability_form = FormAddRepoVulnerability()
        return render_template("view_repo_vulnerabilities.html", repo_vulnerabilities=json_vulnerabilities,
                               new_vulnerability_form=new_vulnerability_form)


@app.route('/repo/threats/', methods=['GET', 'POST'])
def view_repo_threats():
    if request.method == 'POST':
        new_threat_form = FormAddRepoThreat()

        if new_threat_form.validate_on_submit():
            if new_threat_form.id.data:
                # print("PUT ACTOR", "|", new_vulnerability_form.id.data, "|", flush=True)

                try:
                    to_add_threat = RepoThreat.query.filter_by(id=new_threat_form.id.data).first()
                except SQLAlchemyError:
                    return Response("SQLAlchemyError when editing records", 500)

                # print("---------------------")
                # print(to_edit_actor.id.data)
                # print(to_edit_actor.name.data)
                to_add_threat.name = new_threat_form.name.data
                db.session.commit()
                return redirect("/repo/threats/")
            else:
                print("POST ACTOR", flush=True)
                # print(new_actor_form.name.data, flush=True)
                to_add_threat = RepoThreat(name=new_threat_form.name.data)
                db.session.add(to_add_threat)
                db.session.commit()

                flash('Threat "{}" Added Succesfully'.format(new_threat_form.name.data))
                return redirect("/repo/threats/")
    else:
        try:
            repo_threats = RepoThreat.query.all()
        except SQLAlchemyError:
            return Response("SQLAlchemyError", 500)
        # print("------------------------------")
        # print(repo_actors, flush=True)
        #
        # print(repo_actors[0].__table__.columns._data.keys(), flush=True)

        json_threats = convert_database_items_to_json_table(repo_threats)
        json_threats = json.dumps(json_threats)
        print("Threats ARE --------")
        print(json_threats)
        new_threat_form = FormAddRepoThreat()
        return render_template("view_repo_threats.html", repo_threats=json_threats,
                               new_threat_form=new_threat_form)


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
