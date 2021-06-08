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
import ast
from copy import deepcopy
from deepdiff import DeepDiff


@app.context_processor
def serverInfo():
    return dict(serverAddress=serverAddress, serverPort=serverPort)


@app.before_first_request
def active_kafka_listeners():
    print("---- Before First Run ----", flush=True)
    # get_kafka_data_print_test("rcra-report-topic")
    t1 = Process(target=get_kafka_data_print_test, args=("rcra-report-topic",))
    # t2 = Process(target=get_kafka_data_print_test, args=("dtm-alert",))
    t1.start()
    # t2.start()


@app.route('/')
@app.route('/home/')
def entry_page():
    return render_template('entry_page.html')


@app.route('/setup-database/', methods=['GET'])
def setup_database():
    rcra_db_init()
    return Response(status=200)


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
    # ----------------------------------------------------------
    # exposure_instances = ModelThreatExposure.query.all()
    exposure_instances = [{'id': '1', 'name': 'Hurricane'}, {'id': '2', 'name': 'Firestorm'}]
    print(exposure_instances)
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
        # ---------------------------------
        # selected_exposure = ModelThreatExposure.query.filter_by(id=exposure_id).first()
        selected_exposure = []
        # all_responses = ModelIncidentResponse.query.all()
        all_responses = []
        # instance_responses = ModelIncidentResponse.query.filter(
        #     ModelIncidentResponse.materialisation_instance.any(id=exposure_id)).all()
        instance_responses = []
        return render_template('gira_assess_response.html', all_responses=all_responses,
                               selected_exposure=selected_exposure, instance_responses=instance_responses)


# For xx% to appear in template need to create all entries at the same time at the start and then change values instead
# of creating when clicking.
@app.route('//gira_assess/<exposure_id>/gira_assess_materialisation', methods=['GET', 'POST'])
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

        # selected_exposure = ModelThreatExposure.query.filter_by(id=exposure_id).first()

        selected_exposure = []
        # materialisation_instance = GiraThreatMaterialisationInstance.query.filter_by(instance_id=id_of_exposure).first()

        # instance_responses = ModelIncidentResponse.query.filter(
        #     ModelIncidentResponse.materialisation_instance.any(id=exposure_id)).all()

        instance_responses = []

        # instance_materialisations = ModelThreatMaterialisation.query.filter(
        #     ModelThreatMaterialisation.materialisation_instance.any(id=exposure_id)).all()
        # print(instance_materialisations)

        instance_materialisations = []

        # instance_materialisations_entries = ModelThreatMaterialisationInstanceEntry.query.filter_by(
        # table_id=exposure_id).all()

        instance_materialisations_entries = []

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
        print("This adds new MOdel Instance, Exposure: ", to_add_exposure, ", ID", to_add_exposure.id)
        to_add_instance = ModelInstance(threat_id=to_add_exposure.id)
        db.session.add(to_add_instance)
        db.session.flush()

        # Add a new Threat Materialistion Instance
        to_add_materialisation_instance = ModelThreatMaterialisation(instances=to_add_instance.id)

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


@app.route('/repo/dashboard/asset/', methods=['GET', 'POST'])
def repo_dashboard_asset():
    if request.method == 'POST':
        return redirect("/repo/dashboard/asset/")
    else:
        # assetsArray = get_assetsfromrepository()
        # if assetsArray != -1:
        #     return render_template('asset_dashboard.html', assets=assetsArray)
        # else:
        repo_assets = [
            {
                "id": "1",
                "name": "Asset1",
                "location": "Group1",
                "Verified": "false",
                "mac_address": "xx:xx:xx:xx",
                "ip": "xxx.xxx.xxx.xxx",
                "last_touch_date": "today",
            }
        ]
        print(repo_assets)
        return render_template('repo_asset_dashboard.html', repo_assets=repo_assets)


@app.route('/repo/dashboard/threat/', methods=['GET', 'POST'])
def repo_dashboard_threat():
    if request.method == 'POST':
        return redirect("/repo/dashboard/threat/")
    else:
        # assetsArray = get_assetsfromrepository()
        # if assetsArray != -1:
        #     return render_template('asset_dashboard.html', assets=assetsArray)
        # else:
        repo_threats = [
            {
                "id": "1",
                "name": "1",
                "capec": "1",
                "cwe": "1"
            }
        ]
        print(repo_threats)
        return render_template('repo_threat_dashboard.html', repo_threats=repo_threats)


@app.route('/repo/dashboard/risk/objectives/', methods=['GET', 'POST'])
def repo_dashboard_risk_objectives():
    if request.method == 'POST':
        return redirect("/repo/dashboard/risk/objectives/")
    else:
        # assetsArray = get_assetsfromrepository()
        # if assetsArray != -1:
        #     return render_template('asset_dashboard.html', assets=assetsArray)
        # else:
        repo_threats = [
            {
                "likelihood": "Certain",
                "monetary": "(Low) No monetary loss",
                "confidentiality": "(Low) No records leaked",
                "integrity": "(Low) No records lost or altered",
                "availability": "(Low) No disruption of services",
                "safety": "-"
            },
            {
                "likelihood": "Possible",
                "monetary": "-",
                "confidentiality": "-",
                "integrity": "-",
                "availability": "-",
                "safety": "(Low) No injuries or fatalities likely"
            },
            {
                "likelihood": "Rare",
                "monetary": "-",
                "confidentiality": "-",
                "integrity": "(Medium) Some records lost or altered",
                "availability": "(Medium) Some disruption of services",
                "safety": "(Medium) Injuries are likely"
            },
            {
                "likelihood": "Rare than Rare",
                "monetary": "(High) Significant monetary loss",
                "confidentiality": "(High) Many records leaked",
                "integrity": "(High) Many records lost or altered",
                "availability": "-",
                "safety": "-"
            },
            {
                "likelihood": "Oddness 3 or higher",
                "monetary": "(Medium) Some monetary loss",
                "confidentiality": "(Medium) Some records leaked",
                "integrity": "-",
                "availability": "(High) Significant disruption of services",
                "safety": "(High) Fatalities are likley"
            }
        ]
        print(repo_threats)
        return render_template('repo_risk_objectives_dashboard.html', repo_threats=repo_threats)


@app.route('/repo/dashboard/vulnerability/', methods=['GET', 'POST'])
def repo_dashboard_vulnerability():
    if request.method == 'POST':
        return redirect("/repo/dashboard/vulnerability/")
    else:
        # assetsArray = get_assetsfromrepository()
        # if assetsArray != -1:
        #     return render_template('asset_dashboard.html', assets=assetsArray)
        # else:
        repo_vulnerabilities = [
            {
                "id": "1",
                "name": "1",
                "location": "1",
                "Verified": "1",
                "mac_address": "1",
                "ip": "1",
                "last_touch_date": "1",
            }
        ]
        print(repo_vulnerabilities)
        return render_template('repo_vulnerability_dashboard.html', repo_vulnerabilities=repo_vulnerabilities)


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


@app.route('/save_report_test')
def save_report_test():
    status = sendDSSScoreTest()
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
                to_add_asset = RepoAsset(name=new_asset_form.name.data,
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

        print("REPO ASSETS", json_assets)
        return render_template("view_repo_assets.html", repo_assets=json_assets,
                               new_asset_form=new_asset_form)


@app.route('/repo/impacts/', methods=['GET', 'POST', 'PUT'])
def view_repo_impacts():
    if request.method == 'POST':
        new_impact_form = FormAddRepoImpact()

        if new_impact_form.validate_on_submit():
            new_impact = RepoImpact(name=new_impact_form.name.data,
                                    description=new_impact_form.description.data)
            db.session.add(new_impact)
            db.session.commit()

            flash('Impact "{}" Added Succesfully'.format(new_impact_form.name.data))
            return redirect('/repo/impacts/')
        else:
            print("Errors", new_impact_form.errors, flush=True)
            flash('Objective "{}" Error on add'.format(new_impact_form.name.data))

        return redirect('/repo/impacts/')
    else:
        try:
            repo_impacts = RepoImpact.query.all()
        except SQLAlchemyError:
            return Response("SQLAlchemyError", 500)

        # print("------------------------------")
        # print(repo_actors, flush=True)
        #
        # print(repo_actors[0].__table__.columns._data.keys(), flush=True)

        repo_impacts = convert_database_items_to_json_table(repo_impacts)
        repo_impacts = json.dumps(repo_impacts)
        # print("ACTORS ARE --------")
        # print("JSON OBJECTIVES LIST IS", json_objectives)

        new_impact_form = FormAddRepoImpact()
        return render_template("view_repo_impacts.html", repo_impacts=repo_impacts,
                               new_impact_form=new_impact_form)


@app.route('/repo/objectives/', methods=['GET', 'POST', 'PUT'])
def view_repo_objectives():
    if request.method == 'POST':
        if 'objective_alert_form' in request.form:
            # print("ID ALRT CHANGE", request.form)
            objective_states = RepoObjectivesOptions.query.filter_by(
                objective_fk=request.form["objectiveAlertId"]).all()

            # print(objective_states)
            for objective_state in objective_states:
                objective_state.alert_level = request.form[objective_state.name]

            db.session.commit()
        else:
            new_objective_form = FormAddRepoObjective()

            if new_objective_form.validate_on_submit():
                new_objective = RepoObjective(name=new_objective_form.name.data,
                                              description=new_objective_form.description.data)
                db.session.add(new_objective)
                db.session.flush()

                for state in new_objective_form.states.data:
                    # print("Repo Options:", stat
                    new_objective_state = RepoObjectivesOptions(name=state["name"], objective_fk=new_objective.id)
                    db.session.add(new_objective_state)
                    db.session.flush()

                db.session.commit()
                flash('Objective "{}" Added Succesfully'.format(new_objective_form.name.data))
                # add_new_objective = RepoObjective(name=new_objective_form.name.data)
                return redirect('/repo/objectives/')
            else:
                print("Errors", new_objective_form.errors, flush=True)

            flash('Objective "{}" Error on add'.format(new_objective_form.name.data))

        return redirect('/repo/objectives/')
    else:
        try:
            repo_objectives = RepoObjective.query.all()
        except SQLAlchemyError:
            return Response("SQLAlchemyError", 500)

        # print("------------------------------")
        # print(repo_actors, flush=True)
        #
        # print(repo_actors[0].__table__.columns._data.keys(), flush=True)

        json_objectives = convert_database_items_to_json_table(repo_objectives)
        json_objectives = json.dumps(json_objectives)
        # print("ACTORS ARE --------")
        json_objectives = ast.literal_eval(json_objectives)
        # print("JSON OBJECTIVES LIST IS", json_objectives)

        for it in json_objectives:
            it["states"] = "|"
            it["alerts"] = "|"
            # print(it)
            try:
                json_objective_current_state = RepoObjectivesOptions.query.filter_by(objective_fk=it["id"]).all()
            except SQLAlchemyError:
                return Response("SQLAlchemyError", 500)

            for current_state in json_objective_current_state:
                it["states"] = it["states"] + current_state.name + "|"
                it["alerts"] = it["alerts"] + str(current_state.alert_level) + "|"

        # print(json_objectives)
        # it["states"] = json_objective_current_state
        # json_objectives = [{'id': '1', 'name': 'Monetary', 'states': 'x<1000 | 1000 < x < 10000 | x > 10000'},
        #                    {'id': '2', 'name': 'Confidentiality', 'states': 'Low | Med | High'},
        #                    {'id': '3', 'name': 'Integrity', 'states': 'Low | Med | High'},
        #                    {'id': '4', 'name': 'Availability', 'states': 'Low | Med | High'},
        #                    {'id': '5', 'name': 'Safety', 'states': 'No Injuries | Injuries | Fatalities'}
        #                    ]
        new_objective_form = FormAddRepoObjective()
        return render_template("view_repo_objectives.html", repo_objectives=json_objectives,
                               new_objective_form=new_objective_form)


@app.route('/repo/objective/<objective_id>/info/', methods=['GET', 'POST'])
def view_repo_objective_info(objective_id):
    if request.method == 'POST':
        new_objective_impact_form = FormAddRepoObjectiveImpact()

        if new_objective_impact_form.validate_on_submit():
            try:
                this_objective = RepoObjective.query.filter_by(id=objective_id).first()
            except SQLAlchemyError:
                return Response("SQLAlchemyError", 500)

            try:
                to_relate_impact = RepoImpact.query.filter_by(id=new_objective_impact_form.impact_fk.data.id).first()
            except SQLAlchemyError:
                return Response("SQLAlchemyError", 500)

            this_objective.impacts.append(to_relate_impact)
            db.session.commit()
        else:
            print("Form Consequence Impact Error :", new_objective_impact_form.errors)

        return redirect("/repo/objective/" + objective_id + "/info/")
    else:
        try:
            this_objective = RepoObjective.query.filter_by(id=objective_id).all()
        except SQLAlchemyError:
            return Response("SQLAlchemyError", 500)

        try:
            repo_related_impacts = RepoImpact.query.filter(RepoImpact.objectives.any(id=objective_id)).all()
        except SQLAlchemyError:
            return Response("SQLAlchemyError", 500)

        this_objective = convert_database_items_to_json_table(this_objective)
        this_objective_dict = this_objective
        this_objective = json.dumps(this_objective)

        repo_related_impacts = convert_database_items_to_json_table(repo_related_impacts)
        repo_related_impacts = json.dumps(repo_related_impacts)

        new_objective_impact_form = FormAddRepoObjectiveImpact()

        return render_template("view_repo_objective_info.html", this_objective=this_objective,
                               this_objective_dict=this_objective_dict,
                               repo_related_impacts=repo_related_impacts,
                               new_objective_impact_form=new_objective_impact_form)


@app.route('/repo/actors/', methods=['GET', 'POST', 'PUT'])
def view_repo_actors():
    if request.method == 'POST':
        new_actor_form = FormAddRepoActor()

        if new_actor_form.validate_on_submit():
            if new_actor_form.id.data:
                print("PUT ACTOR", "|", new_actor_form.id.data, "|", flush=True)

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
        print(json_actors)
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


@app.route('/repo/threat/<threat_id>/info/', methods=['GET', 'POST'])
def view_repo_threat_info(threat_id):
    if request.method == 'POST':
        # new_materialisation_consequence_form = FormAddRepoMaterialisationConsequence()

        new_materialisation_form = FormAddRepoMaterialisation()
        new_consequence_form = FormAddRepoConsequence()

        new_response_form = FormAddRepoResponse()

        if new_materialisation_form.validate_on_submit():
            print("SAVING MATERIALISATION")
            to_add_materialisation = RepoMaterialisation(
                name=new_materialisation_form.name_materialisation.data,
                threat_id=new_materialisation_form.threat_id.data)

            db.session.add(to_add_materialisation)
            db.session.commit()
        else:
            print("Form Materialisation Error :", new_materialisation_form.errors)

        if new_consequence_form.validate_on_submit():
            print("SAVING CONSEQUENCE")
            to_add_consequences = RepoConsequence(name=new_consequence_form.name_consequence.data,
                                                  threat_id=new_consequence_form.threat_id.data,
                                                  materialisation_id=new_consequence_form.materialisation_fk.data.id)

            db.session.add(to_add_consequences)
            db.session.commit()
        else:
            print("Form Materialisation Error :", new_materialisation_form.errors)

        if new_response_form.validate_on_submit():
            print("SAVING RESPONSE")
            to_add_response = RepoResponse(name=new_response_form.name.data, threat_id=new_response_form.threat_id.data)

            db.session.add(to_add_response)
            db.session.commit()
        else:
            print("Form Response :", new_response_form.errors)

        return redirect("/repo/threat/" + threat_id + "/info/")
    else:
        try:
            repo_threat = RepoThreat.query.filter_by(id=threat_id).all()
        except SQLAlchemyError:
            return Response("SQLAlchemyError", 500)

        try:
            repo_materialisations = RepoMaterialisation.query.filter_by(threat_id=threat_id).all()
        except SQLAlchemyError:
            return Response("SQLAlchemyError", 500)

        try:
            repo_consequences = RepoConsequence.query.filter_by(threat_id=threat_id).all()
        except SQLAlchemyError:
            return Response("SQLAlchemyError", 500)

        try:
            repo_responses = RepoResponse.query.filter_by(threat_id=threat_id).all()
        except SQLAlchemyError:
            return Response("SQLAlchemyError", 500)

        repo_threat = convert_database_items_to_json_table(repo_threat)
        repo_threat_dict = repo_threat
        repo_threat = json.dumps(repo_threat)

        repo_materialisations = convert_database_items_to_json_table(repo_materialisations)
        repo_materialisations = json.dumps(repo_materialisations)

        repo_consequences = convert_database_items_to_json_table(repo_consequences)
        repo_consequences = json.dumps(repo_consequences)

        repo_responses = convert_database_items_to_json_table(repo_responses)
        repo_responses = json.dumps(repo_responses)

        # new_materialisation_consequence_form = FormAddRepoMaterialisationConsequence()
        new_materialisation_form = FormAddRepoMaterialisation()
        new_consequence_form = FormAddRepoConsequence()

        new_response_form = FormAddRepoResponse()
        print("Mats here is: ", repo_materialisations)
        return render_template("view_repo_threat_info.html", repo_threat=repo_threat,
                               repo_threat_dict=repo_threat_dict,
                               repo_materialisations=repo_materialisations, repo_consequences=repo_consequences,
                               new_materialisation_form=new_materialisation_form,
                               new_consequence_form=new_consequence_form,
                               repo_responses=repo_responses, new_response_form=new_response_form)


@app.route('/repo/threat/<threat_id>/info/consequence/<consequence_id>/info/', methods=['GET', 'POST'])
def view_repo_threat_info_consequence_info(threat_id, consequence_id):
    if request.method == 'POST':
        new_consequence_impact_form = FormAddRepoConsequenceImpact()

        if new_consequence_impact_form.validate_on_submit():
            try:
                this_consequence = RepoConsequence.query.filter_by(id=consequence_id).first()
            except SQLAlchemyError:
                return Response("SQLAlchemyError", 500)

            try:
                to_relate_impact = RepoImpact.query.filter_by(id=new_consequence_impact_form.impact_fk.data.id).first()
            except SQLAlchemyError:
                return Response("SQLAlchemyError", 500)

            this_consequence.impacts.append(to_relate_impact)
            db.session.commit()
        else:
            print("Form Consequence Impact Error :", new_consequence_impact_form.errors)

        return redirect("/repo/threat/" + threat_id + "/info/consequence/" + consequence_id + "/info/")
    else:
        try:
            this_threat = RepoThreat.query.filter_by(id=threat_id).all()
        except SQLAlchemyError:
            return Response("SQLAlchemyError", 500)

        try:
            this_consequence = RepoConsequence.query.filter_by(id=consequence_id).all()
        except SQLAlchemyError:
            return Response("SQLAlchemyError", 500)

        try:
            repo_related_impacts = RepoImpact.query.filter(RepoImpact.consequences.any(id=consequence_id)).all()
        except SQLAlchemyError:
            return Response("SQLAlchemyError", 500)

        this_threat = convert_database_items_to_json_table(this_threat)
        this_threat_dict = this_threat
        this_threat = json.dumps(this_threat)

        this_consequence = convert_database_items_to_json_table(this_consequence)
        this_consequence_dict = this_consequence
        this_consequence = json.dumps(this_consequence)

        repo_related_impacts = convert_database_items_to_json_table(repo_related_impacts)
        repo_related_impacts = json.dumps(repo_related_impacts)

        new_consequence_impact_form = FormAddRepoConsequenceImpact()

        return render_template("view_repo_threat_info_consequence_info.html", this_threat=this_threat,
                               this_threat_dict=this_threat_dict,
                               this_consequence=this_consequence,
                               this_consequence_dict=this_consequence_dict,
                               repo_related_impacts=repo_related_impacts,
                               new_consequence_impact_form=new_consequence_impact_form)


@app.route('/repo/service/<service_id>/info/', methods=['GET', 'POST'])
def view_repo_serivce_info(service_id):
    if request.method == 'POST':
        new_service_impact_form = FormAddRepoServiceImpact()

        if new_service_impact_form.validate_on_submit():
            print("SAVING SERVICE IMPACT CONNECTION: ")
            print(new_service_impact_form.impact_fk.data.id)
            try:
                this_service = RepoService.query.filter_by(id=service_id).first()
            except SQLAlchemyError:
                return Response("SQLAlchemyError", 500)

            try:
                this_impact = RepoImpact.query.filter_by(id=new_service_impact_form.impact_fk.data.id).first()
            except SQLAlchemyError:
                return Response("SQLAlchemyError", 500)
            print("SAVING SERVICE IMPACT CONNECTION 2")
            this_service.impacts.append(this_impact)
            print("SAVING SERVICE IMPACT CONNECTION 3")
            db.session.commit()
            print("SAVING SERVICE IMPACT CONNECTION 4")
            # to_add_materialisation = RepoMaterialisation(
            #     name=new_materialisation_form.name_materialisation.data,
            #     threat_id=new_materialisation_form.threat_id.data)
            #
            # db.session.add(to_add_materialisation)
            # db.session.commit()
        else:
            print("Form Service Impact Error :", new_service_impact_form.errors)

        return redirect("/repo/service/" + service_id + "/info/")
    else:
        try:
            repo_impacts = RepoImpact.query.all()
        except SQLAlchemyError:
            return Response("SQLAlchemyError", 500)

        try:
            this_service = RepoService.query.filter_by(id=service_id).all()
        except SQLAlchemyError:
            return Response("SQLAlchemyError", 500)

        try:
            repo_impacts_service_connected = RepoImpact.query.filter(RepoImpact.services.any(id=service_id)).all()
        except SQLAlchemyError:
            return Response("SQLAlchemyError", 500)

        repo_impacts_service_connected = convert_database_items_to_json_table(repo_impacts_service_connected)
        repo_impacts_service_connected = json.dumps(repo_impacts_service_connected)

        repo_impacts = convert_database_items_to_json_table(repo_impacts)

        this_service = convert_database_items_to_json_table(this_service)
        this_service = json.dumps(this_service)

        # new_materialisation_consequence_form = FormAddRepoMaterialisationConsequence()
        new_service_impact_form = FormAddRepoServiceImpact()

        return render_template("view_repo_service_info.html", repo_impacts=repo_impacts, service_id=service_id,
                               this_service=this_service,
                               repo_impacts_service_connected=repo_impacts_service_connected,
                               new_service_impact_form=new_service_impact_form)


@app.route('/repo/assets/threats-relations/<asset_id>/', methods=['GET', 'POST'])
def view_repo_asset_threats_relation(asset_id):
    if request.method == 'POST':
        # flash('Threat "{}" Added Succesfully'.format(new_threat_form.name.data))
        return redirect("/repo/assets/threats-relations/1/")
    else:
        try:
            repo_asset = RepoAsset.query.filter_by(id=int(asset_id)).all()
        except SQLAlchemyError:
            return Response("SQLAlchemyError", 500)

        try:
            repo_threats = RepoThreat.query.all()
        except SQLAlchemyError:
            return Response("SQLAlchemyError", 500)

        repo_asset = convert_database_items_to_json_table(repo_asset)
        repo_asset = json.dumps(repo_asset)
        # new_threat_form = FormAddRepoThreat()
        return render_template("view_repo_assets_threats_relation.html", repo_assets=repo_asset,
                               repo_threats=repo_threats)


@app.route('/repo/assets/services-relations/<asset_id>/', methods=['GET', 'POST'])
def view_repo_asset_services_relation(asset_id):
    if request.method == 'POST':
        try:
            repo_asset = RepoAsset.query.filter_by(id=int(asset_id)).first()
        except SQLAlchemyError:
            return Response("SQLAlchemyError", 500)

        # Add new asset-services relations
        try:
            services = RepoService.query.all()
        except SQLAlchemyError:
            return Response("SQLAlchemyError", 500)

        try:
            related_services = RepoService.query.filter(RepoService.assets.any(id=asset_id)).all()
        except SQLAlchemyError:
            return Response("SQLAlchemyError", 500)

        for service in services:
            related_service = None
            for potentialy_related in related_services:
                if potentialy_related.id == service.id:
                    related_service = potentialy_related
                    break
            else:
                related_service = None
            if request.form[str(service.id)] == "0":
                print("NO RELATION", service.name)
                # Find if service was prebiously related

                if related_service is not None:
                    # If it exists delete it
                    print("NO RELATION DELETE", service.name, ":", repo_asset.services)
                    repo_asset.services.remove(related_service)
                else:
                    print("NO RELATION NOTHING", service.name)
                    # Otherwise do nothing
                    continue
            else:
                print("RELATION", service.name)

                if related_service is not None:
                    # If it exists do nothing
                    print("RELATION NOTHING", service.name)
                    continue
                else:
                    print("RELATION ADD", service.name)
                    # Otherwise add it
                    repo_asset.services.append(service)

        db.session.commit()
        # for service in services:
        #     to_add_asset.services.append(service)

        # flash('Threat "{}" Added Succesfully'.format(new_threat_form.name.data))
        return redirect("/repo/assets/services-relations/" + asset_id + "/")
    else:
        try:
            repo_asset = RepoAsset.query.filter_by(id=int(asset_id)).all()
        except SQLAlchemyError:
            return Response("SQLAlchemyError", 500)

        try:
            all_services = RepoService.query.all()
        except SQLAlchemyError:
            return Response("SQLAlchemyError", 500)

        try:
            related_services = RepoService.query.filter(RepoService.assets.any(id=asset_id)).all()
        except SQLAlchemyError:
            return Response("SQLAlchemyError", 500)

        print("Start Related Services:", related_services)
        repo_asset = convert_database_items_to_json_table(repo_asset)
        repo_asset = json.dumps(repo_asset)

        related_services = convert_database_items_to_json_table(related_services)

        unrelated_services = convert_database_items_to_json_table(all_services)

        for related_service in related_services:
            unrelated_services.remove(related_service)

        related_services = json.dumps(related_services)
        unrelated_services = json.dumps(unrelated_services)
        related_services = ast.literal_eval(related_services)
        unrelated_services = ast.literal_eval(unrelated_services)

        print("Related Services:", related_services)
        print("Unrelated Services:", unrelated_services)
        return render_template("view_repo_assets_services_relation.html", repo_assets=repo_asset,
                               related_services=related_services, unrelated_services=unrelated_services,
                               asset_id=asset_id)


@app.route('/repo/risk/configuration/threat/<threat_id>/asset/<asset_id>/', methods=['GET', 'POST'])
@app.route('/repo/risk/configuration/threat/<threat_id>/', methods=['GET', 'POST'], defaults={'asset_id': -1})
def repo_risk_configuration_threat_asset(threat_id, asset_id):
    if request.method == 'POST':
        # new_service_form = FormAddRepoService
        print("Requests are: ")
        print(request.form)
        # The name in the input forms has the following template
        # "mat|<materialisation_id>|<response_id>|<threat_occurrence>" for materialisations
        # "cons|<consequence_id>|<response_id>|<threat_occurrence>" for consequences

        # Check if there are already data for this threat-asset pair
        if RepoRiskThreatAssetMaterialisation.query.filter_by(repo_asset_id=asset_id,
                                                              repo_threat_id=threat_id).count() is not 0:
            for user_input in request.form:
                deconstructedId = user_input.split("|")
                print("deconstructedId Mat")
                print(deconstructedId)
                if deconstructedId[0] == "mat":
                    if deconstructedId[3] == "True":
                        to_add_threat_occurence_bool = True
                    elif deconstructedId[3] == "False":
                        to_add_threat_occurence_bool = False
                    else:
                        flash('Error adding user input, this shouldnt happen: Malformed Mat threat occurrence form')
                        return redirect("/repo/risk/configuration/threat/" + threat_id + "/asset/" + asset_id + "/")

                    to_edit_mat_node = RepoRiskThreatAssetMaterialisation.query.filter_by(repo_asset_id=asset_id,
                                                                                          repo_threat_id=threat_id,
                                                                                          repo_materialisation_id=
                                                                                          deconstructedId[1],
                                                                                          repo_response_id=
                                                                                          deconstructedId[2],
                                                                                          threat_occurrence=to_add_threat_occurence_bool).first()
                    to_edit_mat_node.prob = request.form[user_input]
                    db.session.commit()

                elif deconstructedId[0] == "cons":
                    print("deconstructedId Cons")
                    print(deconstructedId)
                    if deconstructedId[3] == "True":
                        to_add_threat_occurence_bool = True
                    elif deconstructedId[3] == "False":
                        to_add_threat_occurence_bool = False
                    else:
                        flash('Error adding user input, this shouldnt happen: Malformed Cons threat occurrence form')
                        return redirect("/repo/risk/configuration/threat/" + threat_id + "/asset/" + asset_id + "/")

                    to_edit_cons_node = RepoRiskThreatAssetConsequence.query.filter_by(repo_asset_id=asset_id,
                                                                                       repo_threat_id=threat_id,
                                                                                       repo_consequence_id=
                                                                                       deconstructedId[1],
                                                                                       repo_response_id=deconstructedId[
                                                                                           2],
                                                                                       threat_occurrence=to_add_threat_occurence_bool).first()

                    to_edit_cons_node.prob = request.form[user_input]
                    db.session.commit()
                else:
                    flash('Error adding user input, this shouldnt happen: Malformed Input forms')
                    return redirect("/repo/risk/configuration/threat/" + threat_id + "/asset/" + asset_id + "/")
        else:
            for user_input in request.form:
                deconstructedId = user_input.split("|")
                print("deconstructedId Mat")
                print(deconstructedId)
                if deconstructedId[0] == "mat":
                    if deconstructedId[3] == "True":
                        to_add_threat_occurence_bool = True
                    elif deconstructedId[3] == "False":
                        to_add_threat_occurence_bool = False
                    else:
                        flash('Error adding user input, this shouldnt happen: Malformed Mat threat occurrence form')
                        return redirect("/repo/risk/configuration/threat/" + threat_id + "/asset/" + asset_id + "/")

                    to_add_mat_node = RepoRiskThreatAssetMaterialisation(repo_asset_id=asset_id,
                                                                         repo_threat_id=threat_id,
                                                                         repo_materialisation_id=deconstructedId[1],
                                                                         repo_response_id=deconstructedId[2],
                                                                         threat_occurrence=to_add_threat_occurence_bool,
                                                                         prob=request.form[user_input])

                    db.session.add(to_add_mat_node)
                elif deconstructedId[0] == "cons":
                    print("deconstructedId Cons")
                    print(deconstructedId)
                    if deconstructedId[3] == "True":
                        to_add_threat_occurence_bool = True
                    elif deconstructedId[3] == "False":
                        to_add_threat_occurence_bool = False
                    else:
                        flash('Error adding user input, this shouldnt happen: Malformed Cons threat occurrence form')
                        return redirect("/repo/risk/configuration/threat/" + threat_id + "/asset/" + asset_id + "/")

                    to_add_cons_node = RepoRiskThreatAssetConsequence(repo_asset_id=asset_id, repo_threat_id=threat_id,
                                                                      repo_consequence_id=deconstructedId[1],
                                                                      repo_response_id=deconstructedId[2],
                                                                      threat_occurrence=to_add_threat_occurence_bool,
                                                                      prob=request.form[user_input])

                    db.session.add(to_add_cons_node)
                else:
                    flash('Error adding user input, this shouldnt happen: Malformed Input forms')
                    return redirect("/repo/risk/configuration/threat/" + threat_id + "/asset/" + asset_id + "/")

        db.session.commit()
        flash('User input for threat "{}" and asset "{}" Added Succesfully'.format(threat_id, asset_id))
        return redirect("/repo/risk/configuration/threat/" + threat_id + "/asset/" + asset_id + "/")
    else:
        print("Threat id is" + str(threat_id))
        try:
            repo_threats = RepoThreat.query.all()
        except SQLAlchemyError:
            return Response("SQLAlchemyError", 500)

        try:
            this_threat = RepoThreat.query.filter_by(id=threat_id).all()
        except SQLAlchemyError:
            return Response("SQLAlchemyError", 500)

        try:
            repo_assets = RepoAsset.query.all()
        except SQLAlchemyError:
            return Response("SQLAlchemyError", 500)

        # print("------------------------------")
        # print(repo_actors, flush=True)
        #
        # print(repo_actors[0].__table__.columns._data.keys(), flush=True)

        try:
            repo_threat_materialisations = RepoMaterialisation.query.filter_by(threat_id=threat_id).all()
        except SQLAlchemyError:
            return Response("SQLAlchemyError", 500)

        array_threat_materialisation_calculation = []
        array_threat_consequence_calculation = []

        if asset_id != -1:
            # If we view specific asset create/load the input forms
            try:
                repo_threat_responses = RepoResponse.query.filter_by(threat_id=threat_id).all()
            except SQLAlchemyError:
                return Response("SQLAlchemyError", 500)

            try:
                repo_threat_consequence = RepoConsequence.query.filter_by(threat_id=threat_id).all()
            except SQLAlchemyError:
                return Response("SQLAlchemyError", 500)

            repo_threat_materialisations = convert_database_items_to_json_table(repo_threat_materialisations)
            repo_threat_responses = convert_database_items_to_json_table(repo_threat_responses)
            repo_threat_consequence = convert_database_items_to_json_table(repo_threat_consequence)

            # Check if there are already data for this threat-asset pair
            if RepoRiskThreatAssetMaterialisation.query.filter_by(
                    repo_asset_id=asset_id,
                    repo_threat_id=threat_id).count() is 0:
                print("NO PREVIOUS INPUT------------------------")
                print(RepoRiskThreatAssetMaterialisation.query.filter_by(
                    repo_asset_id=asset_id,
                    repo_threat_id=threat_id).first())
                print("threat_id =" + str(type(threat_id)) + "asset_id= " + str(type(asset_id)))
                for materialisation in repo_threat_materialisations:
                    temp_array_threat_materialisation_calculation = []
                    for response in repo_threat_responses:
                        temp_array_threat_materialisation_calculation.append(
                            {"response": response, "materialisation": materialisation, "threat_occurrence": True,
                             "prob": 50})
                        temp_array_threat_materialisation_calculation.append(
                            {"response": response, "materialisation": materialisation, "threat_occurrence": False,
                             "prob": 50})

                    array_threat_materialisation_calculation.append(temp_array_threat_materialisation_calculation)

                for consequence in repo_threat_consequence:
                    temp_array_threat_consequence_calculation = []
                    for response in repo_threat_responses:
                        temp_array_threat_consequence_calculation.append(
                            {"response": response, "consequence": consequence, "threat_occurrence": True, "prob": 50})

                        temp_array_threat_consequence_calculation.append(
                            {"response": response, "consequence": consequence, "threat_occurrence": False, "prob": 50})

                    array_threat_consequence_calculation.append(temp_array_threat_consequence_calculation)
            else:
                try:
                    existing_user_input_materialisation = RepoRiskThreatAssetMaterialisation.query.filter_by(
                        repo_asset_id=asset_id,
                        repo_threat_id=threat_id).all()
                except SQLAlchemyError:
                    return Response("SQLAlchemyError", 500)

                try:
                    existing_user_input_consequence = RepoRiskThreatAssetConsequence.query.filter_by(
                        repo_asset_id=asset_id,
                        repo_threat_id=threat_id).all()
                except SQLAlchemyError:
                    return Response("SQLAlchemyError", 500)

                existing_user_input_consequence = convert_database_items_to_json_table(existing_user_input_consequence)
                existing_user_input_materialisation = convert_database_items_to_json_table(
                    existing_user_input_materialisation)
                print("Existing Input:")
                print(existing_user_input_consequence)

                for materialisation in repo_threat_materialisations:
                    temp_array_threat_materialisation_calculation = []
                    for response in repo_threat_responses:
                        prob_item = next(item for item in existing_user_input_materialisation if
                                         item["repo_response_id"] == response["id"] and item[
                                             "repo_materialisation_id"] == materialisation["id"] and item[
                                             "threat_occurrence"] is True)
                        temp_array_threat_materialisation_calculation.append(
                            {"response": response, "materialisation": materialisation, "threat_occurrence": True,
                             "prob": prob_item['prob']})

                        prob_item = next(item for item in existing_user_input_materialisation if
                                         item["repo_response_id"] == response["id"] and item[
                                             "repo_materialisation_id"] == materialisation["id"] and item[
                                             "threat_occurrence"] is False)
                        temp_array_threat_materialisation_calculation.append(
                            {"response": response, "materialisation": materialisation, "threat_occurrence": False,
                             "prob": prob_item['prob']})

                    array_threat_materialisation_calculation.append(temp_array_threat_materialisation_calculation)

                for consequence in repo_threat_consequence:
                    temp_array_threat_consequence_calculation = []
                    for response in repo_threat_responses:
                        prob_item = next(item for item in existing_user_input_consequence if
                                         item["repo_response_id"] == response["id"] and item["repo_consequence_id"] ==
                                         consequence["id"] and item["threat_occurrence"] is True)
                        temp_array_threat_consequence_calculation.append(
                            {"response": response, "consequence": consequence, "threat_occurrence": True,
                             "prob": prob_item['prob']})
                        prob_item = next(item for item in existing_user_input_consequence if
                                         item["repo_response_id"] == response["id"] and item["repo_consequence_id"] ==
                                         materialisation["id"] and item["threat_occurrence"] is False)
                        temp_array_threat_consequence_calculation.append(
                            {"response": response, "consequence": consequence, "threat_occurrence": False,
                             "prob": prob_item['prob']})

                    array_threat_consequence_calculation.append(temp_array_threat_consequence_calculation)

        repo_threats = convert_database_items_to_json_table(repo_threats)
        this_threat = convert_database_items_to_json_table(this_threat)
        repo_assets = convert_database_items_to_json_table(repo_assets)
        # repo_threats = json.dumps(repo_threats)
        # print("This threat is", this_threat)
        # for toprint =in array_threat_materialisation_calculation:
        #     print("Materialisations are: ", toprint)
        #
        # for toprint in array_threat_consequence_calculation:
        #     print("Consequences are: ", toprint)

        print("Threat id is" + str(threat_id))
        return render_template("repo_risk_configuration_threat_asset.html", threat_id=threat_id, asset_id=asset_id,
                               repo_threats=repo_threats, this_threat=this_threat, repo_assets=repo_assets,
                               array_threat_consequence_calculation=array_threat_consequence_calculation,
                               array_threat_materialisation_calculation=array_threat_materialisation_calculation)


@app.route('/repo/risk/configuration/impact/threat/<threat_id>/', methods=['GET', 'POST'])
@app.route('/repo/risk/configuration/impact/threat/<threat_id>/asset/<asset_id>/', methods=['GET', 'POST'])
@app.route('/repo/risk/configuration/impact/<impact_id>/threat/<threat_id>/asset/<asset_id>/', methods=['GET', 'POST'])
def repo_risk_configuration_impacts_risk(threat_id=1, asset_id=-1, impact_id=-1):
    if request.method == 'POST':
        # If there are any entries regarding this pair of threats, assets and impacts, entries need to be edited not added
        # Add new entries since none exist
        for user_input in request.form:
            deconstructedId = user_input.split("|")
            print("deconstructedId Mat")
            print(deconstructedId)

            # Entries for low,medium and high states are in the same table entry
            # but arent sent by the frontend as one entry but as three in succession
            # We are currently assuming data is send in order but this should become a check
            # The format of data sent is and should such as this
            # ['low', 'serv', '1', 'False', 'serv', '4', 'False', 'cons', '1', 'False', 'cons', '3', 'False']

            # Create two lists one with this entries related services- state and impacts-state
            related_service_state = []
            related_service_list = []
            related_consequence_state = []
            related_consequence_list = []
            related_mixed_state = []
            # Copy current entry and prepare to create the lists above
            temp_entry = deepcopy(deconstructedId)
            temp_entry.pop(0)
            for custom_it in range(0, len(temp_entry), 3):
                if temp_entry[custom_it] == "serv":
                    # If this entry is about services
                    related_service_state.append(
                        {"serv_id": str(temp_entry[custom_it + 1]), "state": temp_entry[custom_it + 2]})
                    related_service_list.append(temp_entry[custom_it + 1])
                else:
                    related_consequence_state.append(
                        {"cons_id": str(temp_entry[custom_it + 1]), "state": temp_entry[custom_it + 2]})
                    related_consequence_list.append(temp_entry[custom_it + 1])
            # If this entry is about consequences
            print(related_service_state)
            # print(related_consequence_state)
            related_mixed_state = related_service_state + related_consequence_state
            # Find if this specific input exists
            joined = db.session.query(RepoAssetThreatConsequenceServiceImpactRelationship,
                                      RepoAssetThreatConsequenceServiceImpactRelationshipConsequenceManyToMany,
                                      RepoAssetThreatConsequenceServiceImpactRelationshipServiceManyToMany) \
                .join(
                RepoAssetThreatConsequenceServiceImpactRelationshipConsequenceManyToMany,
                RepoAssetThreatConsequenceServiceImpactRelationshipServiceManyToMany) \
                .filter(
                RepoAssetThreatConsequenceServiceImpactRelationship.repo_threat_id == threat_id,
                RepoAssetThreatConsequenceServiceImpactRelationship.repo_impact_id == impact_id,
                RepoAssetThreatConsequenceServiceImpactRelationship.repo_asset_id == asset_id,
                # RepoAssetThreatConsequenceServiceImpactRelationshipConsequenceManyToMany.repo_consequence_id == 1,
                # RepoAssetThreatConsequenceServiceImpactRelationshipServiceManyToMany.repo_service_id == 1,
            )
            # print("NUMBER OF RECORDS")
            # print(joined.count())
            joined = joined.all()

            concatted = {}

            for temp_joined in joined:
                # print("Single Line")
                # print("Inner Line")
                if temp_joined[0] not in concatted:
                    concatted[temp_joined[0]] = []
                for inner_joined in temp_joined:
                    if inner_joined is temp_joined[0]:
                        continue
                    # print(concatted[temp_joined[0]])
                    if type(inner_joined) is RepoAssetThreatConsequenceServiceImpactRelationshipConsequenceManyToMany:
                        # inner_joined_arrayed = ['cons', inner_joined.repo_consequence_id, inner_joined.repo_consequence_state]
                        inner_joined_arrayed = {"cons_id": str(inner_joined.repo_consequence_id),
                                                "state": str(inner_joined.repo_consequence_state)}
                    else:
                        # inner_joined_arrayed = ['serv', inner_joined.repo_service_id, inner_joined.repo_service_state]
                        inner_joined_arrayed = {"serv_id": str(inner_joined.repo_service_id),
                                                "state": str(inner_joined.repo_service_state)}
                    if inner_joined_arrayed not in concatted[temp_joined[0]]:
                        concatted[temp_joined[0]].append(inner_joined_arrayed)
                    # print(inner_joined)
            # print(concatted)

            existing_entry = None
            # print(concatted.items())
            # print("------------ RESULTS ARE ----------")
            for concatted_entry_key, concatted_entry_value in concatted.items():
                # print(related_mixed_state)
                # print(concatted_entry_value)
                if sorted(concatted_entry_value, key=lambda ele: sorted(ele.items())) == sorted(related_mixed_state,
                                                                                                key=lambda ele: sorted(
                                                                                                        ele.items())):
                    # print("SSSSSSSSSSSSSSSSSSSSSSSSSSSSSSAAAAAAAAAAAAAAAAAAAAAAAAMMMMMMMMMMMMEEEEEEEEEE")
                    # print(related_mixed_state)
                    # print(concatted_entry_value)
                    # print("STOOOOOOOOOOOOOOOOOOOOOOOOOOOOPPPPPPPPPPPSSSSSSSSSSSSSSSSSSSSSSS")
                    existing_entry = concatted_entry_key
                    break

            # print(existing_entry)
            # print("THIS QUERY RESULT IS")
            # print()
            # current_entry = convert_database_items_to_json_table(joined)
            # for temp_joined in current_entry:
            #     # temp_temp = convert_database_items_to_json_table(temp_joined)
            #     print(temp_joined)
            if existing_entry:
                # Entry already exists

                # print("Already exists")
                # print(related_mixed_state)
                # print(existing_entry)
                if deconstructedId[0] == "low":
                    existing_entry.low_prob = request.form[user_input]
                elif deconstructedId[0] == "medium":
                    existing_entry.med_prob = request.form[user_input]
                else:
                    existing_entry.high_prob = request.form[user_input]

                # print("Not yet 2")
            else:
                # print("NEW ENTRY")
                # print(related_mixed_state)
                # Entry doesnt exist create new one
                # Create main entry
                to_add_main = RepoAssetThreatConsequenceServiceImpactRelationship(repo_asset_id=asset_id,
                                                                                  repo_threat_id=threat_id,
                                                                                  repo_impact_id=impact_id,
                                                                                  )
                db.session.add(to_add_main)
                db.session.flush()
                # Create secondary entries
                for single_service in related_service_state:
                    # Convert String to bool
                    if single_service["state"] == "True":
                        temp_bool = True
                    else:
                        temp_bool = False
                    to_add_secondary_serv = RepoAssetThreatConsequenceServiceImpactRelationshipServiceManyToMany(
                        repo_service_id=single_service["serv_id"],
                        repo_service_state=temp_bool
                    )
                    to_add_main.services.append(to_add_secondary_serv)
                    db.session.add(to_add_secondary_serv)
                    db.session.flush()

                for single_consequence in related_consequence_state:
                    # Convert String to bool
                    if single_consequence["state"] == "True":
                        temp_bool = True
                    else:
                        temp_bool = False
                    to_add_secondary_cons = RepoAssetThreatConsequenceServiceImpactRelationshipConsequenceManyToMany(
                        repo_consequence_id=single_consequence["cons_id"],
                        repo_consequence_state=temp_bool
                    )
                    to_add_main.consequences.append(to_add_secondary_cons)
                    db.session.add(to_add_secondary_cons)
                    db.session.flush()

                if deconstructedId[0] == "low":
                    to_add_main.low_prob = request.form[user_input]
                elif deconstructedId[0] == "medium":
                    to_add_main.med_prob = request.form[user_input]
                else:
                    to_add_main.high_prob = request.form[user_input]

        print("WILL SAVE NOW")
        db.session.commit()
        flash('Impact Info Added-Edited Successfully')
        return redirect(
            "/repo/risk/configuration/impact/" + impact_id + "/threat/" + threat_id + "/asset/" + asset_id + "/")
    else:
        try:
            this_threat = RepoThreat.query.filter_by(id=threat_id).all()
        except SQLAlchemyError:
            return Response("SQLAlchemyError", 500)

        try:
            repo_threats = RepoThreat.query.all()
        except SQLAlchemyError:
            return Response("SQLAlchemyError", 500)

        try:
            this_asset = RepoAsset.query.filter_by(id=asset_id).all()
        except SQLAlchemyError:
            return Response("SQLAlchemyError", 500)

        try:
            repo_assets = RepoAsset.query.all()
        except SQLAlchemyError:
            return Response("SQLAlchemyError", 500)

        try:
            this_impact = RepoImpact.query.filter_by(id=impact_id).all()
        except SQLAlchemyError:
            return Response("SQLAlchemyError", 500)

        try:
            repo_impacts = RepoImpact.query.all()
        except SQLAlchemyError:
            return Response("SQLAlchemyError", 500)

        try:
            repo_related_services = RepoService.query.filter(RepoService.assets.any(id=asset_id),
                                                             RepoService.impacts.any(id=impact_id)).all()
        except SQLAlchemyError:
            return Response("SQLAlchemyError", 500)

        try:
            repo_related_consequences = RepoConsequence.query.filter(RepoConsequence.threat_id == threat_id,
                                                                     RepoConsequence.impacts.any(id=impact_id)).all()
        except SQLAlchemyError:
            return Response("SQLAlchemyError", 500)
        # print("------------------------------")
        # print(repo_actors, flush=True)
        #
        # print(repo_actors[0].__table__.columns._data.keys(), flush=True)

        repo_related_services = convert_database_items_to_json_table(repo_related_services)
        repo_impacts = convert_database_items_to_json_table(repo_impacts)
        this_impact = convert_database_items_to_json_table(this_impact)
        repo_assets = convert_database_items_to_json_table(repo_assets)
        this_asset = convert_database_items_to_json_table(this_asset)
        repo_threats = convert_database_items_to_json_table(repo_threats)
        this_threat = convert_database_items_to_json_table(this_threat)
        repo_related_consequences = convert_database_items_to_json_table(repo_related_consequences)

        array_impact_calculation = []

        print("Related services are")
        print(repo_related_services)

        print("Related Consequence are")
        print(repo_related_consequences)

        for repo_temp_service in repo_related_services:
            if not array_impact_calculation:
                temp_to_add_1 = {"service": repo_temp_service, "state": True}
                temp_to_add_2 = {"service": repo_temp_service, "state": False}
                array_impact_calculation.append([temp_to_add_1])
                array_impact_calculation.append([temp_to_add_2])
            else:
                temp_impact_array = deepcopy(array_impact_calculation)
                for to_be_added in temp_impact_array:
                    to_be_added.append({"service": repo_temp_service, "state": True})

                for to_be_added in array_impact_calculation:
                    to_be_added.append({"service": repo_temp_service, "state": False})

                array_impact_calculation = array_impact_calculation + temp_impact_array

        for repo_temp_consequence in repo_related_consequences:
            if not array_impact_calculation:
                temp_to_add_1 = {"consequence": repo_temp_consequence, "state": True}
                temp_to_add_2 = {"consequence": repo_temp_consequence, "state": False}
                array_impact_calculation.append([temp_to_add_1])
                array_impact_calculation.append([temp_to_add_2])
            else:
                temp_impact_array = deepcopy(array_impact_calculation)
                for to_be_added in temp_impact_array:
                    to_be_added.append({"consequence": repo_temp_consequence, "state": True})

                for to_be_added in array_impact_calculation:
                    to_be_added.append({"consequence": repo_temp_consequence, "state": False})

                array_impact_calculation = array_impact_calculation + temp_impact_array

        print("--- FINAL ARRAY ---")
        for temp in array_impact_calculation:
            print(temp)

        # If there are aready values
        existing_values = db.session.query(RepoAssetThreatConsequenceServiceImpactRelationship,
                                           RepoAssetThreatConsequenceServiceImpactRelationshipConsequenceManyToMany,
                                           RepoAssetThreatConsequenceServiceImpactRelationshipServiceManyToMany).join(
            RepoAssetThreatConsequenceServiceImpactRelationshipConsequenceManyToMany,
            RepoAssetThreatConsequenceServiceImpactRelationshipServiceManyToMany).filter(
            RepoAssetThreatConsequenceServiceImpactRelationship.repo_threat_id == threat_id,
            RepoAssetThreatConsequenceServiceImpactRelationship.repo_impact_id == impact_id,
            RepoAssetThreatConsequenceServiceImpactRelationship.repo_asset_id == asset_id,
        )
        if existing_values.count() > 0:
            joined = existing_values.all()

            concatted = {}

            for temp_joined in joined:
                # print("Single Line")
                # print("Inner Line")
                if temp_joined[0] not in concatted:
                    concatted[temp_joined[0]] = []
                for inner_joined in temp_joined:
                    if inner_joined is temp_joined[0]:
                        continue
                    # print(concatted[temp_joined[0]])
                    if type(inner_joined) is RepoAssetThreatConsequenceServiceImpactRelationshipConsequenceManyToMany:
                        # inner_joined_arrayed = ['cons', inner_joined.repo_consequence_id, inner_joined.repo_consequence_state]
                        inner_joined_arrayed = {"consequence": {'id': inner_joined.repo_consequence_id,
                                                                'name': inner_joined.repo_consequence.name,
                                                                'threat_id': inner_joined.repo_consequence.threat_id,
                                                                'materialisation_id' : inner_joined.repo_consequence.materialisation_id
                                                                },
                                                "state": inner_joined.repo_consequence_state}
                    else:
                        # inner_joined_arrayed = ['serv', inner_joined.repo_service_id, inner_joined.repo_service_state]
                        inner_joined_arrayed = {
                            "service": {'id': inner_joined.repo_service_id, 'name': inner_joined.repo_service.name},
                            "state": inner_joined.repo_service_state}
                    if inner_joined_arrayed not in concatted[temp_joined[0]]:
                        concatted[temp_joined[0]].append(inner_joined_arrayed)
            print("------------ RESULTS ARE ----------")
            print(concatted.items())
            for to_send in array_impact_calculation:
                for concatted_entry_key, concatted_entry_value in concatted.items():
                    # print("------Comparison------")
                    # print(to_send)
                    # print(concatted_entry_value)
                    ddiff = DeepDiff(to_send, concatted_entry_value, ignore_order=True)
                    # print(ddiff)

                    if ddiff == {}:
                        print("SAMEEEEEEEEEEEEEEE")
                        to_send.append(concatted_entry_key.low_prob)
                        to_send.append(concatted_entry_key.med_prob)
                        to_send.append(concatted_entry_key.high_prob)
                        print(to_send)


                    # if sorted(concatted_entry_value, key=lambda ele: sorted(ele.items())) == sorted(
                    #         to_send, key=lambda ele: sorted(ele.items())):
                #             print("SSSSSSSSSSSSSSSSSSSSSSSSSSSSSSAAAAAAAAAAAAAAAAAAAAAAAAMMMMMMMMMMMMEEEEEEEEEE")
                #     # print(related_mixed_state)
                # #     # print(concatted_entry_value)
                #  print("STOOOOOOOOOOOOOOOOOOOOOOOOOOOOPPPPPPPPPPPSSSSSSSSSSSSSSSSSSSSSSS")
                # #             existing_entry = concatted_entry_key
                #         break
        else:
            for to_send in array_impact_calculation:
                to_send.append(50)
                to_send.append(50)
                to_send.append(50)


        return render_template("repo_risk_configuration_impacts_risk.html",
                               repo_impacts=repo_impacts, repo_threats=repo_threats, repo_assets=repo_assets,
                               this_threat=this_threat,
                               impact_id=impact_id, threat_id=threat_id, asset_id=asset_id, this_asset=this_asset,
                               this_impact=this_impact, array_impact_calculation=array_impact_calculation)


@app.route('/repo/risk/configuration/objective/<objective_id>/', methods=['GET', 'POST'])
def repo_risk_configuration_objective_risk(objective_id=1):
    if request.method == 'POST':
        # new_service_form = FormAddRepoService()
        for user_input in request.form:
            deconstructedId = user_input.split("|")
            print("deconstructedId Mat")
            print(deconstructedId)

            # Entries for low,medium and high states are in the same table entry
            # but arent sent by the frontend as one entry but as three in succession
            # We are currently assuming data is send in order but this should become a check
            # The format of data sent is and should such as this
            # ['low', 'serv', '1', 'False', 'serv', '4', 'False', 'cons', '1', 'False', 'cons', '3', 'False']

            # Create two lists one with this entries related services- state and impacts-state

            related_impact_state = []
            related_impact_list = []
            # Copy current entry and prepare to create the lists above
            temp_entry = deepcopy(deconstructedId)
            temp_entry.pop(0)
            for custom_it in range(0, len(temp_entry), 2):
                if temp_entry[custom_it + 1] == "low":
                    temp_state = 0
                elif temp_entry[custom_it + 1] == "med":
                    temp_state = 1
                else:
                    temp_state = 2
                related_impact_state.append(
                    {"imp_id": str(temp_entry[custom_it + 0]), "state": str(temp_state)})
                related_impact_list.append(temp_entry[custom_it + 1])

            print(related_impact_state)
            #             # Find if this specific input exists
            joined = db.session.query(RepoObjectiveImpactRelationship,RepoObjectiveImpactRelationshipImpactManyToMany)\
                .join(RepoObjectiveImpactRelationshipImpactManyToMany) \
                .filter(
                RepoObjectiveImpactRelationship.repo_objective_id == objective_id,
                # RepoAssetThreatConsequenceServiceImpactRelationshipConsequenceManyToMany.repo_consequence_id == 1,
                # RepoAssetThreatConsequenceServiceImpactRelationshipServiceManyToMany.repo_service_id == 1,
            )
            # print("NUMBER OF RECORDS")
            # print(joined.count())
            joined = joined.all()

            concatted = {}

            for temp_joined in joined:
                # print("Single Line")
                # print("Inner Line")
                if temp_joined[0] not in concatted:
                    concatted[temp_joined[0]] = []
                for inner_joined in temp_joined:
                    if inner_joined is temp_joined[0]:
                        continue
                    # print(concatted[temp_joined[0]])
                    inner_joined_arrayed = {"imp_id": str(inner_joined.repo_impact_id),
                                            "state": str(inner_joined.repo_impact_state)}

                    if inner_joined_arrayed not in concatted[temp_joined[0]]:
                        concatted[temp_joined[0]].append(inner_joined_arrayed)
                    # print(inner_joined)
            # print(concatted)

            existing_entry = None
            # print(concatted.items())
            print("------------ COMPARISON ARE ----------")
            for concatted_entry_key, concatted_entry_value in concatted.items():
                print(related_impact_state)
                print(concatted_entry_value)
                if sorted(concatted_entry_value, key=lambda ele: sorted(ele.items())) == sorted(related_impact_state,
                                                                                                key=lambda ele: sorted(
                                                                                                        ele.items())):
                    # print("SSSSSSSSSSSSSSSSSSSSSSSSSSSSSSAAAAAAAAAAAAAAAAAAAAAAAAMMMMMMMMMMMMEEEEEEEEEE")
                    # print(related_mixed_state)
                    # print(concatted_entry_value)
                    # print("STOOOOOOOOOOOOOOOOOOOOOOOOOOOOPPPPPPPPPPPSSSSSSSSSSSSSSSSSSSSSSS")
                    existing_entry = concatted_entry_key
                    break

            # print(existing_entry)
            # print("THIS QUERY RESULT IS")
            # print()
            # current_entry = convert_database_items_to_json_table(joined)
            # for temp_joined in current_entry:
            #     # temp_temp = convert_database_items_to_json_table(temp_joined)
            #     print(temp_joined)
            if existing_entry:
                # Entry already exists

                # print("Already exists")
                # print(related_mixed_state)
                # print(existing_entry)
                if deconstructedId[0] == "low":
                    existing_entry.low_prob = request.form[user_input]
                elif deconstructedId[0] == "med":
                    existing_entry.med_prob = request.form[user_input]
                else:
                    existing_entry.high_prob = request.form[user_input]

                # print("Not yet 2")
            else:
                # print("NEW ENTRY")
                # print(related_mixed_state)
                # Entry doesnt exist create new one
                # Create main entry
                to_add_main = RepoObjectiveImpactRelationship(repo_objective_id=objective_id)
                db.session.add(to_add_main)
                db.session.flush()
                # Create secondary entries

                for single_impact in related_impact_state:
                    # Convert String to bool
                    # if single_impact["state"] == "low":
                    #     temp_bool = 0
                    # elif single_impact["state"] == "med":
                    #     temp_bool = 1
                    # else:
                    #     temp_bool = 2
                    to_add_secondary_imp = RepoObjectiveImpactRelationshipImpactManyToMany(
                        repo_impact_id=single_impact["imp_id"],
                        repo_impact_state= int(single_impact["state"])
                    )
                    print("ADDING")
                    print(to_add_secondary_imp)
                    print(to_add_main)
                    to_add_main.impacts.append(to_add_secondary_imp)
                    db.session.add(to_add_secondary_imp)
                    db.session.flush()

                if deconstructedId[0] == "low":
                    to_add_main.low_prob = request.form[user_input]
                elif deconstructedId[0] == "medium":
                    to_add_main.med_prob = request.form[user_input]
                else:
                    to_add_main.high_prob = request.form[user_input]

        print("WILL SAVE NOW")
        db.session.commit()

        flash('Objective Risk "{}" Added Succesfully'.format(objective_id))
        return redirect("/repo/risk/configuration/objective/" + objective_id + "/")
    else:
        try:
            this_objective = RepoObjective.query.filter_by(id=objective_id).all()
        except SQLAlchemyError:
            return Response("SQLAlchemyError", 500)

        try:
            this_objective_options = RepoObjectivesOptions.query.filter_by(objective_fk=objective_id).all()
        except SQLAlchemyError:
            return Response("SQLAlchemyError", 500)

        try:
            repo_objectives = RepoObjective.query.all()
        except SQLAlchemyError:
            return Response("SQLAlchemyError", 500)

        try:
            repo_related_impacts = RepoImpact.query.filter(RepoImpact.objectives.any(id=objective_id)).all()
        except SQLAlchemyError:
            return Response("SQLAlchemyError", 500)
        # print("------------------------------")
        # print(repo_actors, flush=True)
        #
        # print(repo_actors[0].__table__.columns._data.keys(), flush=True)

        repo_objectives = convert_database_items_to_json_table(repo_objectives)
        this_objective = convert_database_items_to_json_table(this_objective)
        array_impact_calculation = []

        # print(repo_related_impacts)
        for repo_temp_impact in repo_related_impacts:
            if not array_impact_calculation:
                temp_to_add_1 = {"impact": repo_temp_impact, "state": "high"}
                temp_to_add_2 = {"impact": repo_temp_impact, "state": "med"}
                temp_to_add_3 = {"impact": repo_temp_impact, "state": "low"}
                array_impact_calculation.append([temp_to_add_1])
                array_impact_calculation.append([temp_to_add_2])
                array_impact_calculation.append([temp_to_add_3])
            else:
                temp_impact_array = deepcopy(array_impact_calculation)
                temp_impact_array_2 = deepcopy(array_impact_calculation)
                for to_be_added in temp_impact_array:
                    to_be_added.append({"impact": repo_temp_impact, "state": "high"})

                for to_be_added in temp_impact_array_2:
                    to_be_added.append({"impact": repo_temp_impact, "state": "med"})

                for to_be_added in array_impact_calculation:
                    to_be_added.append({"impact": repo_temp_impact, "state": "low"})

                array_impact_calculation = array_impact_calculation + temp_impact_array + temp_impact_array_2


        existing_values = db.session.query(RepoObjectiveImpactRelationship, RepoObjectiveImpactRelationshipImpactManyToMany) \
            .join(RepoObjectiveImpactRelationshipImpactManyToMany) \
            .filter(
            RepoObjectiveImpactRelationship.repo_objective_id == objective_id,
        )


        if existing_values.count() > 0:
            joined = existing_values.all()

            concatted = {}

            for temp_joined in joined:
                # print("Single Line")
                # print("Inner Line")
                if temp_joined[0] not in concatted:
                    concatted[temp_joined[0]] = []
                for inner_joined in temp_joined:
                    if inner_joined is temp_joined[0]:
                        continue
                    # print(concatted[temp_joined[0]])
                    if inner_joined.repo_impact_state == 0:
                        temp_state = "low"
                    elif inner_joined.repo_impact_state == 1:
                        temp_state = "med"
                    else:
                        temp_state = "high"
                    inner_joined_arrayed = {"impact": inner_joined.repo_impact,
                                            "state": temp_state}
                    # if type(inner_joined) is RepoAssetThreatConsequenceServiceImpactRelationshipConsequenceManyToMany:
                    #     # inner_joined_arrayed = ['cons', inner_joined.repo_consequence_id, inner_joined.repo_consequence_state]
                    #     inner_joined_arrayed = {"consequence": {'id': inner_joined.repo_consequence_id,
                    #                                             'name': inner_joined.repo_consequence.name,
                    #                                             'threat_id': inner_joined.repo_consequence.threat_id,
                    #                                             'materialisation_id': inner_joined.repo_consequence.materialisation_id
                    #                                             },
                    #                             "state": inner_joined.repo_consequence_state}
                    # else:
                    #     # inner_joined_arrayed = ['serv', inner_joined.repo_service_id, inner_joined.repo_service_state]
                    #     inner_joined_arrayed = {
                    #         "service": {'id': inner_joined.repo_service_id, 'name': inner_joined.repo_service.name},
                    #         "state": inner_joined.repo_service_state}
                    if inner_joined_arrayed not in concatted[temp_joined[0]]:
                        concatted[temp_joined[0]].append(inner_joined_arrayed)
            print("------------ RESULTS ARE ----------")
            print(concatted.items())
            for to_send in array_impact_calculation:
                for concatted_entry_key, concatted_entry_value in concatted.items():
                    # print("------Comparison------")
                    # print(to_send)
                    # print(concatted_entry_value)
                    ddiff = DeepDiff(to_send, concatted_entry_value, ignore_order=True)
                    # print(ddiff)

                    if ddiff == {}:
                        print("SAMEEEEEEEEEEEEEEE")
                        print(to_send)
                        print(concatted_entry_value)
                        to_send.append(concatted_entry_key.low_prob)
                        to_send.append(concatted_entry_key.med_prob)
                        to_send.append(concatted_entry_key.high_prob)
                        # print(to_send)

                    # if sorted(concatted_entry_value, key=lambda ele: sorted(ele.items())) == sorted(
                    #         to_send, key=lambda ele: sorted(ele.items())):
                #             print("SSSSSSSSSSSSSSSSSSSSSSSSSSSSSSAAAAAAAAAAAAAAAAAAAAAAAAMMMMMMMMMMMMEEEEEEEEEE")
                #     # print(related_mixed_state)
                # #     # print(concatted_entry_value)
                #  print("STOOOOOOOOOOOOOOOOOOOOOOOOOOOOPPPPPPPPPPPSSSSSSSSSSSSSSSSSSSSSSS")
                # #             existing_entry = concatted_entry_key
                #         break
        else:
            for to_send in array_impact_calculation:
                to_send.append(50)
                to_send.append(50)
                to_send.append(50)

            print(to_send)
        # for

        for to_send in array_impact_calculation:
            print(to_send)

        return render_template("repo_risk_configuration_objectives_risk.html", repo_objectives=repo_objectives,
                               objective_id=objective_id,
                               this_objective=this_objective, array_objective_calculation=array_impact_calculation)


@app.route('/repo/risk/assessment/<threat_id>/asset/<asset_id>/', methods=['GET', 'POST'])
def repo_risk_assessment(threat_id = 1, asset_id = -1):
    if request.method == 'POST':
        # new_service_form = FormAddRepoService()
        try:
            this_risk_assessment = RepoRiskAssessment.query.filter_by(repo_threat_id=threat_id, repo_asset_id=asset_id)
        except SQLAlchemyError:
            return Response("SQLAlchemyError", 500)

        if this_risk_assessment.count() == 0:
            this_risk_assessment = RepoRiskAssessment(repo_threat_id=threat_id, repo_asset_id=asset_id)
            db.session.add(this_risk_assessment)
            db.session.commit()

        flash('Assed "{}" Added Succesfully to risk assessment'.format(asset_id))
        return redirect("/repo/risk/assessment/"+ threat_id+"/asset/"+asset_id+"/")
    else:
        try:
            this_threat = RepoThreat.query.filter_by(id=threat_id).all()
        except SQLAlchemyError:
            return Response("SQLAlchemyError", 500)

        try:
            repo_threats = RepoThreat.query.all()
        except SQLAlchemyError:
            return Response("SQLAlchemyError", 500)

        try:
            all_assets = RepoAsset.query.all()
        except SQLAlchemyError:
            return Response("SQLAlchemyError", 500)

        try:
            related_assessments = RepoRiskAssessment.query.filter_by(repo_threat_id=threat_id).all()
        except SQLAlchemyError:
            return Response("SQLAlchemyError", 500)

        related_assets = []
        print(all_assets)
        for related_assessment in related_assessments:
            related_assets.append(related_assessment.asset)
            # print(related_assessment.asset)

        if asset_id != -1:
            try:
                this_asset = RepoAsset.query.filter_by(id=asset_id).all()
            except SQLAlchemyError:
                return Response("SQLAlchemyError", 500)
        else:
            this_asset = []

        # print("------------------------------")
        # print(repo_actors, flush=True)
        #
        # print(repo_actors[0].__table__.columns._data.keys(), flush=True)

        repo_threats = convert_database_items_to_json_table(repo_threats)
        this_threat = convert_database_items_to_json_table(this_threat)

        related_assets = convert_database_items_to_json_table(related_assets)
        unrelated_assets = convert_database_items_to_json_table(all_assets)



        this_asset = convert_database_items_to_json_table(this_asset)
        for related_asset in related_assets:
            unrelated_assets.remove(related_asset)
        # array_objective_calculation = [[{}], [{}]                                       ]
        # for

        return render_template("repo_risk_assessment.html", repo_threats=repo_threats,
                               threat_id=threat_id, asset_id =asset_id,
                               this_threat=this_threat,
                               related_assets=related_assets,
                               unrelated_assets=unrelated_assets,
                               this_asset=this_asset)


@app.route('/test/dynamic/risk/', methods=['GET', 'POST'])
def test_dynamic_risk():
    if request.method == 'POST':
        return redirect('/test/dynamic/risk/')
    else:
        start_risk_assessment(1,1)
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
