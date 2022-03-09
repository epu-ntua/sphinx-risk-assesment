from app import app
from flask import render_template, request, redirect, jsonify, Response, flash
from app.utils import *
from app.globals import *
# from app.producer import generate_checkpoint
from app.producer import *
import json
from app.forms import *
from multiprocessing import Process
import ast
from copy import deepcopy
from deepdiff import DeepDiff

# @app.route('/gira_assess/', methods=['GET', 'POST'])
# def gira_assess():
#     if request.method == 'POST':
#         return redirect("/gira_assess/")
#     else:
#         return render_template('gira_assess.html')
#
#
# @app.route('/gira_assess/gira_assess_exposure/', methods=['GET'])
# def gira_assess_exposure():
#     # ----------------------------------------------------------
#     # exposure_instances = ModelThreatExposure.query.all()
#     exposure_instances = [{'id': '1', 'name': 'Hurricane'}, {'id': '2', 'name': 'Firestorm'}]
#     print(exposure_instances)
#     return render_template('gira_assess_exposure.html', exposure_instances=exposure_instances)
#
#
# @app.route('/gira_assess/<exposure_id>/gira_assess_response/', methods=['GET', 'POST'])
# def gira_assess_response(exposure_id):
#     if request.method == 'POST':
#         materialisation_instance = ModelThreatMaterialisation.query.filter_by(instance_id=exposure_id).first()
#
#         instance_responses = ModelIncidentResponse.query.filter(
#             ModelIncidentResponse.materialisation_instance.any(id=exposure_id)).all()
#         # Sent Data are a dict with one entry containing the exposureIdToSend and the rest contain
#         # The ids of the responses to be added to the keys and values dictate what to do [nothing, delete, add]
#         for sent in request.form:
#             # Skip exposureId
#             if sent == "exposureIdToSend":
#                 continue
#
#             if request.form[sent] == "nothing":
#                 continue
#             elif request.form[sent] == "add":
#                 to_add_response = ModelIncidentResponse.query.filter_by(id=sent).first()
#                 materialisation_instance.incident_responses.append(to_add_response)
#             elif request.form[sent] == "delete":
#                 to_remove_response = ModelIncidentResponse.query.filter_by(id=sent).first()
#                 materialisation_instance.incident_responses.remove(to_remove_response)
#
#         db.session.commit()
#
#         return redirect('/gira_assess/' + exposure_id + '/gira_assess_materialisation/')
#     else:
#         # ---------------------------------
#         # selected_exposure = ModelThreatExposure.query.filter_by(id=exposure_id).first()
#         selected_exposure = []
#         # all_responses = ModelIncidentResponse.query.all()
#         all_responses = []
#         # instance_responses = ModelIncidentResponse.query.filter(
#         #     ModelIncidentResponse.materialisation_instance.any(id=exposure_id)).all()
#         instance_responses = []
#         return render_template('gira_assess_response.html', all_responses=all_responses,
#                                selected_exposure=selected_exposure, instance_responses=instance_responses)
#
#
# # For xx% to appear in template need to create all entries at the same time at the start and then change values instead
# # of creating when clicking.
# @app.route('//gira_assess/<exposure_id>/gira_assess_materialisation', methods=['GET', 'POST'])
# def gira_assess_materialisation(exposure_id):
#     if request.method == 'POST':
#         if request.form["is_threat_materialising"] == "false":
#             is_threat_materialising_bool = False
#             # print("false")
#         elif request.form["is_threat_materialising"] == "true":
#             is_threat_materialising_bool = True
#             # print("true")
#         else:
#             return Response(401)
#
#         existing_entry = ModelThreatMaterialisationInstanceEntry.query.filter_by(table_id=int(request.form["table_id"]),
#                                                                                  responses_id=int(
#                                                                                      request.form["responses_id"]),
#                                                                                  materialisations_id=int(request.form[
#                                                                                                              "materialisations_id"]),
#                                                                                  is_threat_materialising=is_threat_materialising_bool
#                                                                                  ).first()
#         if existing_entry:
#             existing_entry.prob_threat_materialising = request.form["prob_threat_materialising"]
#             existing_entry.prob_likelihood = request.form["prob_likelihood"]
#             existing_entry.prob_likelihood_other = request.form["prob_likelihood_other"]
#             existing_entry.prob_posterior = request.form["prob_posterior"]
#         else:
#             # Process each new entry of the table
#             # is_threat_materialising_bool = request.form["is_threat_materialising"]
#
#             # print("Data")
#             # for entry in request.form.items():
#             #     print(entry)
#
#             # print(is_threat_materialising_bool)
#             to_add_entry = ModelThreatMaterialisationInstanceEntry(table_id=int(request.form["table_id"]),
#                                                                    responses_id=int(request.form["responses_id"]),
#                                                                    materialisations_id=int(request.form[
#                                                                                                "materialisations_id"]),
#                                                                    prob_threat_materialising=int(request.form[
#                                                                                                      "prob_threat_materialising"]),
#                                                                    prob_likelihood=int(request.form["prob_likelihood"]),
#                                                                    prob_likelihood_other=int(request.form[
#                                                                                                  "prob_likelihood_other"]),
#                                                                    prob_posterior=int(request.form["prob_posterior"]),
#                                                                    is_threat_materialising=is_threat_materialising_bool)
#
#             db.session.add(to_add_entry)
#         db.session.commit()
#         return Response(status=201)
#     else:
#         # NOT USING THE CORRECT KEYS TO SEARCH FOR THE RESPONSES AND SUCH
#
#         # selected_exposure = ModelThreatExposure.query.filter_by(id=exposure_id).first()
#
#         selected_exposure = []
#         # materialisation_instance = GiraThreatMaterialisationInstance.query.filter_by(instance_id=id_of_exposure).first()
#
#         # instance_responses = ModelIncidentResponse.query.filter(
#         #     ModelIncidentResponse.materialisation_instance.any(id=exposure_id)).all()
#
#         instance_responses = []
#
#         # instance_materialisations = ModelThreatMaterialisation.query.filter(
#         #     ModelThreatMaterialisation.materialisation_instance.any(id=exposure_id)).all()
#         # print(instance_materialisations)
#
#         instance_materialisations = []
#
#         # instance_materialisations_entries = ModelThreatMaterialisationInstanceEntry.query.filter_by(
#         # table_id=exposure_id).all()
#
#         instance_materialisations_entries = []
#
#         return render_template('gira_assess_materialisation.html', selected_exposure=selected_exposure,
#                                instance_materialisations=instance_materialisations,
#                                instance_responses=instance_responses,
#                                instance_materialisations_entries=instance_materialisations_entries)
#
#
# @app.route('/gira_assess/<exposure_id>/gira_assess_materialisation/check_table/', methods=['POST'])
# def gira_assess_materialisation_check_table(exposure_id):
#     if request.method == 'POST':
#         table_id = request.form["tableId"]
#         # table_to_check = GiraThreatMaterialisationInstance.query.filter_by(id = table_id)
#
#         instance_responses_count = ModelIncidentResponse.query.filter(
#             ModelIncidentResponse.materialisation_instance.any(id=table_id)).count()
#
#         instance_materialisations_count = ModelThreatMaterialisation.query.filter(
#             ModelThreatMaterialisation.materialisation_instance.any(id=table_id)).count()
#
#         target_entries_count = instance_materialisations_count * instance_responses_count * 2
#         current_entries_count = ModelThreatMaterialisationInstanceEntry.query.filter_by(table_id=table_id).count()
#
#         # This could check for the presence of the number itself in each entry but it shouldnt be normally needed
#         if target_entries_count == current_entries_count:
#             return redirect(
#                 Response(status=201))  # change to next page when ready /gira_assess/gira_assess_consequences
#         else:
#             return redirect(request.url)
#
#         print(target_entries_count)
#         print(current_entries_count)
#
#
# @app.route('/gira_assess/gira_assess_consequence/', methods=['GET', 'POST'])
# def gira_assess_consequence():
#     if request.method == 'POST':
#         return redirect("/gira_assess/gira_assess_consequence/")
#     else:
#         return render_template('gira_assess_consequence.html')
#
#
# @app.route('/gira_assess/gira_assess_asset_status/', methods=['GET', 'POST'])
# def gira_assess_asset_status():
#     if request.method == 'POST':
#         return redirect("/gira_assess/gira_assess_asset_status/")
#     else:
#         return render_template('gira_assess_asset_status.html')
#
#
# @app.route('/gira_assess/gira_assess_asset_impact/', methods=['GET', 'POST'])
# def gira_assess_asset_impact():
#     if request.method == 'POST':
#         return redirect("/gira_assess/gira_assess_asset_impact/")
#     else:
#         return render_template('gira_assess_asset_impact.html')
#
#
# @app.route('/gira_assess/gira_assess_objective/', methods=['GET', 'POST'])
# def gira_assess_objective():
#     if request.method == 'POST':
#         return redirect("/gira_assess/gira_assess_objective/")
#     else:
#         return render_template('gira_assess_objective.html')
#
#
# @app.route('/gira_overview/', methods=['GET', 'POST'])
# def gira_overview():
#     if request.method == 'POST':
#         return redirect("/gira_overview/")
#     else:
#         return render_template('gira_overview.html')
#
#
# @app.route('/gira_overview/gira_threat_exposure/', methods=['GET', 'POST'])
# def gira_threat_exposure():
#     if request.method == 'POST':
#
#         # Add new Threat Exposure
#         to_add_exposure = ModelThreatExposure(name=request.form['name'], description=request.form['description'],
#                                               probability=int(request.form['probability']))
#         db.session.add(to_add_exposure)
#         db.session.flush()
#
#         # print(to_add_exposure.id)
#
#         # Add new Instance of Gira
#         print("This adds new MOdel Instance, Exposure: ", to_add_exposure, ", ID", to_add_exposure.id)
#         to_add_instance = ModelInstance(threat_id=to_add_exposure.id)
#         db.session.add(to_add_instance)
#         db.session.flush()
#
#         # Add a new Threat Materialistion Instance
#         to_add_materialisation_instance = ModelThreatMaterialisation(instances=to_add_instance.id)
#
#         to_add_materialisations_instance_id = request.form['materialisationsToAdd']
#         to_add_materialisations_instance_id = json.loads(to_add_materialisations_instance_id)
#         print(to_add_materialisations_instance_id)
#
#         # Helper tanble to temporary store all the instances of materialisations
#         to_add_materialisations_list = []
#
#         # Query database for each instance of the Gira Materialisations we want
#         for materialisation_id in to_add_materialisations_instance_id:
#             print("Query")
#             print(ModelThreatMaterialisation.query.filter_by(id=materialisation_id[0]).first())
#             to_add_materialisations_list.append(
#                 ModelThreatMaterialisation.query.filter_by(id=materialisation_id[0]).first())
#
#         print("TASTS")
#         print(to_add_materialisations_list)
#         # Append each gire materialisation to the materialisation instance
#         for materialisation in to_add_materialisations_list:
#             print("test")
#             print(materialisation)
#             to_add_materialisation_instance.materialisations.append(materialisation)
#
#         db.session.add(to_add_materialisation_instance)
#         db.session.commit()
#
#         return redirect('/gira_overview/gira_threat_exposure/')
#     else:
#         threats = ModelThreatExposure.query.all()
#         materialisations = ModelThreatMaterialisation.query.all()
#
#         return render_template('gira_threat_exposure.html', threats=threats, materialisations=materialisations)
#
#
# @app.route('/gira_overview/gira_threat_response/', methods=['GET', 'POST'])
# def gira_threat_response():
#     if request.method == 'POST':
#         to_add = ModelIncidentResponse(name=request.form['name'], description=request.form['description'],
#                                        default_effect=int(request.form['default_effect']))
#         db.session.add(to_add)
#         db.session.commit()
#
#         return redirect('/gira_overview/gira_threat_response/')
#     else:
#         responses = ModelIncidentResponse.query.all()
#         return render_template('gira_threat_response.html', responses=responses)
#
#
# @app.route('/gira_overview/gira_threat_materialisation/', methods=['GET', 'POST'])
# def gira_threat_materialisation():
#     if request.method == 'POST':
#         to_add = ModelThreatMaterialisation(name=request.form['name'], description=request.form['description'],
#                                             probability=int(request.form['probability']))
#         db.session.add(to_add)
#         db.session.commit()
#
#         return redirect('/gira_overview/gira_threat_materialisation/')
#     else:
#         materialisations = ModelThreatMaterialisation.query.all()
#         consequences = ModelConsequence.query.all()
#
#         return render_template('gira_threat_materialisation.html', materialisations=materialisations,
#                                consequences=consequences)
#
#
# @app.route('/gira_overview/gira_consequence/', methods=['GET', 'POST'])
# def gira_consequence():
#     if request.method == 'POST':
#         to_add = ModelConsequence(name=request.form['name'], description=request.form['description'], )
#         db.session.add(to_add)
#         db.session.commit()
#
#         return redirect('/gira_overview/gira_consequence/')
#     else:
#         consequences = ModelConsequence.query.all()
#
#         return render_template('gira_consequences.html', consequences=consequences)
#
#
# @app.route('/gira_overview/gira_asset_status/', methods=['GET', 'POST'])
# def gira_asset_status():
#     if request.method == 'POST':
#         return redirect("/gira_overview/")
#     else:
#         return render_template('gira_asset_status.html')
#
#
# @app.route('/gira_overview/gira_asset_impact/', methods=['GET', 'POST'])
# def gira_asset_impact():
#     if request.method == 'POST':
#         return redirect("/gira_overview/")
#     else:
#         return render_template('gira_asset_impact.html')
#
#
# @app.route('/gira_overview/gira_objective/', methods=['GET', 'POST'])
# def gira_objective():
#     if request.method == 'POST':
#         return redirect("/gira_overview/")
#     else:
#         return render_template('gira_objective.html')
#
#
# @app.route('/gira_overview/gira_result/', methods=['GET', 'POST'])
# def gira_result():
#     if request.method == 'POST':
#         return redirect("/gira_overview/")
#     else:
#         return render_template('gira_result.html')

# @app.route('/general_dashboard/asset_view/', defaults={"asset": -1})
# @app.route('/general_dashboard/asset_view/<asset>/', methods=['GET', 'POST'])
# def general_dashboard_asset_view(asset):
#     if request.method == 'POST':
#         i = 5
#         toRedirect = "/general_dashboard/asset_view/"
#         return redirect(toRedirect)
#     else:
#         # assetsArray = get_assets()
#
#         # print(assetsArray[0].VReport_assetID)
#         assetsArray = []
#         return render_template('general_dashboard_asset_view.html', asset=asset, assets=assetsArray)
#
#
# @app.route('/general_dashboard/threat_view/', defaults={"threat": -1})
# @app.route('/general_dashboard/threat_view/<threat>/', methods=['GET', 'POST'])
# def general_dashboard_threat_view(threat):
#     if request.method == 'POST':
#         i = 5
#         toRedirect = "/general_dashboard/threat_view/"
#         return redirect(toRedirect)
#     else:
#         # assetsArray = get_assets()
#
#         # print(assetsArray[0].VReport_assetID)
#         assetsArray = []
#         return render_template('general_dashboard_threat_view.html', threat=threat, assets=assetsArray)
#
#
# @app.route('/general_dashboard/tree_view/', defaults={"threat": -1})
# @app.route('/general_dashboard/tree_view/<threat>/', methods=['GET', 'POST'])
# def general_dashboard_tree_view(threat):
#     if request.method == 'POST':
#         i = 5
#         toRedirect = "/general_dashboard/threat_view/"
#         return redirect(toRedirect)
#     else:
#         # assetsArray = get_assets()
#
#         # print(assetsArray[0].VReport_assetID)
#         assetsArray = []
#         return render_template('general_dashboard_tree_view.html', threat=threat, assets=assetsArray)




# @app.route('/asset_discovery')
# def asset_discovery():
#     return render_template('asset_discovery.html')
#
#
# @app.route('/asset_Asset_hardware')
# def asset_Asset_hardware():
#     return render_template('asset_Asset_hardware.html')
#
#
# @app.route('/asset_Asset_hardware_type')
# def asset_Asset_hardware_type():
#     return render_template('asset_Asset_hardware_type.html')
#
#
# @app.route('/asset_Asset_software')
# def asset_Asset_software():
#     return render_template('asset_Asset_software.html')
#
#
# @app.route('/asset_Asset_software_type')
# def asset_Asset_software_type():
#     return render_template('asset_Asset_software_type.html')
#
#
# @app.route('/asset_Asset_License_Type')
# def asset_Asset_License_Type():
#     return render_template('asset_Asset_License_Type.html')
#
#
# @app.route('/asset_organisation_structure')
# def asset_organisation_structure():
#     return render_template('asset_organisation_structure.html')
#
#
# @app.route('/asset_organisation_process')
# def asset_organisation_process():
#     return render_template('asset_organisation_process.html')
#
#
# @app.route('/asset_Asset_usage_type')
# def asset_Asset_usage_type():
#     return render_template('asset_Asset_usage_type.html')
#
#
# @app.route('/asset_Asset_hardware_non_it')
# def asset_Asset_hardware_non_it():
#     return render_template('asset_Asset_hardware_non_it.html')
#
#
# @app.route('/asset_Asset_hardware_classification')
# def asset_Asset_hardware_classification():
#     return render_template('asset_Asset_hardware_classification.html')
#
#
# @app.route('/asset_configuration_relationship')
# def asset_configuration_relationship():
#     return render_template('asset_configuration_relationship.html')

# @app.route('/topic/<topicname>')
# def get_messages(topicname):
#     client = get_kafka_client()
#     def events():
#         for i in client.topics[topicname].get_simple_consumer():
#             yield 'data:{0}\n\n'.format(i.value.decode())+
#     return Response(events(), mimetype="text/event-stream")
# @app.route('/activate_test')
# def activate_test():
#     status = rcra_1()
#     if status == 0:
#         return Response(status=200)
#     else:
#         return Response(status=500)

# @app.route('/assets/', defaults={"asset": -1})
# @app.route('/assets/<asset>/', methods=['GET', 'POST'])
# def assets(asset):
#     if request.method == 'POST':
#         if asset != -1:
#             print(request.form)
#
#             toRedirect = "vulnerabilities/"
#             return redirect(toRedirect)
#         else:
#             return redirect("/assets/")
#     else:
#         # assetsArray = get_assets()
#         # # print(assetsArray[0].VReport_assetID)
#         #
#         # proposedCVEArray = []
#         # # print(assetsArray)
#         # if assetsArray != -1:
#         #     for tempAsset in assetsArray:
#         #         proposedCVEArray.append(get_cve_recommendations(tempAsset.VReport_assetID))
#         #
#         # # Still need an fuction that will get the other CVE, or preferably being able to add CVE one by one by hand
#         # othersCVEArray = []
#         # for tempAsset in assetsArray:
#         # othersCVEArray.append()
#
#         assetsArray = [{"VReport_assetID": "85"}, {"VReport_assetID": "80"}]
#         proposedCVEArray = ["2020-13720", "2020-13730"]
#         othersCVEArray = ["2020-12350"]
#
#         return render_template('assets.html', asset=asset, assets=assetsArray, proposedCVEArray=proposedCVEArray,
#                                othersCVEArray=othersCVEArray)
#
#
# @app.route('/assets/<asset>/vulnerabilities/', defaults={"asset": -1, "vulnerability": -1})
# @app.route('/assets/<asset>/vulnerabilities/<vulnerability>/', methods=['GET', 'POST'])
# def vulnerabilities(asset, vulnerability):
#     if request.method == 'POST':
#         i = 5
#         toRedirect = "threats/"
#         return redirect(toRedirect)
#     else:
#         # assetsArray = get_assets()
#         # print(assetsArray[0].VReport_assetID)
#
#         assetsArray = [{"VReport_assetID": "85"}, {"VReport_assetID": "80"}]
#
#         return render_template('vulnerabilities.html', asset=asset, vulnerability=vulnerability, assets=assetsArray)
#
#
# @app.route('/assets/<asset>/vulnerabilities/<vulnerability>/threats/',
#            defaults={"asset": -1, "vulnerability": -1, "threat": -1})
# @app.route('/assets/<asset>/vulnerabilities/<vulnerability>/threats/<threat>/', methods=['GET', 'POST'])
# def threats(asset, vulnerability, threat):
#     if request.method == 'POST':
#         i = 5
#     else:
#         # assetsArray = get_assets()
#         # print(assetsArray[0].VReport_assetID)
#
#         assetsArray = [{"VReport_assetID": "85"}, {"VReport_assetID": "80"}]
#
#         return render_template('threats.html', asset=asset, vulnerability=vulnerability, threat=threat,
#                                assets=assetsArray)
#
#
# @app.route('/hardwareassets/', defaults={"hardwareasset": -1})
# @app.route('/hardwareassets/<hardwareasset>/', methods=['GET', 'POST'])
# def hardwareassets(hardwareasset):
#     if request.method == 'POST':
#         if hardwareasset != -1:
#             print(request.form)
#             toRedirect = "/hardwareassets/"
#             return redirect(toRedirect)
#         else:
#             return redirect("/hardwareassets/")
#     else:
#         # hardwareassetsArray = get_hardwareassets()
#         return render_template('assets.html', asset=hardwareasset)
