import json

from flask import render_template, request, redirect, jsonify, Response, flash
from multiprocessing import Process
from app.producer import *
from app.globals import *
from app.utils import *
from app.forms import *
from app import app
# from app.utils.utils_communication import send_risk_report
from app.utils.utils_3rd_party_data_handling import send_risk_report
from app.utils.utils_database import *
from sqlalchemy.exc import SQLAlchemyError
from copy import deepcopy
from deepdiff import DeepDiff

from app.utils.utils_risk_assessment import start_risk_assessment, start_risk_assessment_alert, risk_assessment_save_report


@app.route('/repo/risk/configuration/threat/exposure/<threat_id>/', methods=['GET', 'POST'])
@app.route('/repo/risk/configuration/threat/exposure/<threat_id>/asset/<asset_id>/', methods=['GET', 'POST'])
def repo_risk_configuration_threat_exposure(threat_id=1, asset_id=-1):
    if request.method == 'POST':
        # # new_service_form = FormAddRepoService
        print("Requests are: ")
        print(request.form)
        # # The name in the input forms has the following template
        # # "mat|<materialisation_id>|<response_id>|<threat_occurrence>" for materialisations
        # # "cons|<consequence_id>|<response_id>|<threat_occurrence>" for consequences
        #
        # # Check if there are already data for this threat-asset pair
        existing_exposure_item = RepoAssetRepoThreatRelationship.query.filter_by(repo_asset_id=asset_id,
                                                                                 repo_threat_id=threat_id)
        if existing_exposure_item.count() != 0:
            to_edit_exposure_node = existing_exposure_item.first()
            to_edit_exposure_node.risk_skill_level = request.form["risk_skill"]
            to_edit_exposure_node.risk_actor = request.form["risk_actor"]
            to_edit_exposure_node.risk_motive = request.form["risk_motive"]
            to_edit_exposure_node.risk_source = request.form["risk_source"]
            to_edit_exposure_node.risk_opportunity = request.form["risk_opportunity"]
            db.session.commit()
            flash('Edited threat "{}" and asset "{}" exposure information'.format(threat_id, asset_id))
        else:
            to_add_exposure = RepoAssetRepoThreatRelationship(repo_asset_id=asset_id, repo_threat_id=threat_id,
                                                              risk_skill_level=request.form["risk_skill"],
                                                              risk_actor=request.form["risk_actor"],
                                                              risk_motive=request.form["risk_motive"],
                                                              risk_source=request.form["risk_source"],
                                                              risk_opportunity=request.form["risk_opportunity"])
            db.session.add(to_add_exposure)
            db.session.commit()
            flash('Added threat "{}" and asset "{}" exposure information'.format(threat_id, asset_id))
        return redirect("/repo/risk/configuration/threat/exposure/" + threat_id + "/asset/" + asset_id + "/")
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

        risk_skill_level = 50
        risk_actor = 50
        risk_motive = 50
        risk_source = 50
        risk_opportunity = 50

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
            existing_exposure_item = RepoAssetRepoThreatRelationship.query.filter_by(
                repo_asset_id=asset_id,
                repo_threat_id=threat_id)

            if existing_exposure_item.count() == 0:
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
                existing_exposure_item = existing_exposure_item.all()

                existing_user_input_exposure = convert_database_items_to_json_table(
                    existing_exposure_item)
                print("Existing Input:")
                print(existing_user_input_exposure[0])

                risk_skill_level = existing_user_input_exposure[0]["risk_skill_level"]
                risk_actor = existing_user_input_exposure[0]["risk_actor"]
                risk_motive = existing_user_input_exposure[0]["risk_motive"]
                risk_source = existing_user_input_exposure[0]["risk_source"]
                risk_opportunity = existing_user_input_exposure[0]["risk_opportunity"]

                # for materialisation in repo_threat_materialisations:
                #     temp_array_threat_materialisation_calculation = []
                #     for response in repo_threat_responses:
                #         prob_item = next(item for item in existing_user_input_exposure if
                #                          item["repo_response_id"] == response["id"] and item[
                #                              "repo_materialisation_id"] == materialisation["id"] and item[
                #                              "threat_occurrence"] is True)
                #         temp_array_threat_materialisation_calculation.append(
                #             {"response": response, "materialisation": materialisation, "threat_occurrence": True,
                #              "prob": prob_item['prob']})
                #
                #         prob_item = next(item for item in existing_user_input_exposure if
                #                          item["repo_response_id"] == response["id"] and item[
                #                              "repo_materialisation_id"] == materialisation["id"] and item[
                #                              "threat_occurrence"] is False)
                #         temp_array_threat_materialisation_calculation.append(
                #             {"response": response, "materialisation": materialisation, "threat_occurrence": False,
                #              "prob": prob_item['prob']})
                #
                #     array_threat_materialisation_calculation.append(temp_array_threat_materialisation_calculation)
                #
                # for consequence in repo_threat_consequence:
                #     temp_array_threat_consequence_calculation = []
                #     for response in repo_threat_responses:
                #         prob_item = next(item for item in existing_user_input_consequence if
                #                          item["repo_response_id"] == response["id"] and item["repo_consequence_id"] ==
                #                          consequence["id"] and item["threat_occurrence"] is True)
                #         temp_array_threat_consequence_calculation.append(
                #             {"response": response, "consequence": consequence, "threat_occurrence": True,
                #              "prob": prob_item['prob']})
                #         prob_item = next(item for item in existing_user_input_consequence if
                #                          item["repo_response_id"] == response["id"] and item["repo_consequence_id"] ==
                #                          materialisation["id"] and item["threat_occurrence"] is False)
                #         temp_array_threat_consequence_calculation.append(
                #             {"response": response, "consequence": consequence, "threat_occurrence": False,
                #              "prob": prob_item['prob']})

                # array_threat_consequence_calculation.append(temp_array_threat_consequence_calculation)

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
        return render_template("templates_risk_assessment/repo_risk_configuration_threat_exposure.html",
                               threat_id=threat_id, asset_id=asset_id,
                               repo_threats=repo_threats, this_threat=this_threat, repo_assets=repo_assets,
                               risk_skill_level=risk_skill_level,
                               risk_actor=risk_actor,
                               risk_motive=risk_motive,
                               risk_source=risk_source,
                               risk_opportunity=risk_opportunity
                               )


@app.route('/repo/risk/configuration/threat/<threat_id>/asset/<asset_id>/', methods=['GET', 'POST'])
@app.route('/repo/risk/configuration/threat/<threat_id>/', methods=['GET', 'POST'], defaults={'asset_id': -1})
def repo_risk_configuration_threat_asset(threat_id, asset_id):
    if request.method == 'POST':
        # new_service_form = FormAddRepoService
        # print("Requests are: ")
        # print(request.form)
        # The name in the input forms has the following template
        # "mat|<materialisation_id>|<response_id>|<threat_occurrence>" for materialisations
        # "cons|<consequence_id>|<response_id>|<threat_occurrence>" for consequences

        # Check if there are already data for this threat-asset pair
        if RepoRiskThreatAssetMaterialisation.query.filter_by(repo_asset_id=asset_id,
                                                              repo_threat_id=threat_id).count() != 0:
            for user_input in request.form:
                deconstructedId = user_input.split("|")
                # print("deconstructedId Mat")
                # print(deconstructedId)
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
                                                                                          threat_occurrence=to_add_threat_occurence_bool)
                    if to_edit_mat_node.count() > 0:
                        to_edit_mat_node = to_edit_mat_node.first()
                        to_edit_mat_node.prob = request.form[user_input]
                    else:
                        to_add_missing_mat_node = RepoRiskThreatAssetMaterialisation(repo_asset_id=asset_id,
                                                                                     repo_threat_id=threat_id,
                                                                                     repo_materialisation_id=
                                                                                     deconstructedId[1],
                                                                                     repo_response_id=deconstructedId[
                                                                                         2],
                                                                                     threat_occurrence=to_add_threat_occurence_bool,
                                                                                     prob=request.form[user_input])
                        db.session.add(to_add_missing_mat_node)
                    db.session.commit()

                elif deconstructedId[0] == "cons":
                    # print("deconstructedId Cons")
                    # print(deconstructedId)
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
                                                                                       threat_occurrence=to_add_threat_occurence_bool)

                    to_edit_cons_node.prob = request.form[user_input]

                    if to_edit_cons_node.count() > 0:
                        to_edit_cons_node = to_edit_cons_node.first()
                        to_edit_cons_node.prob = request.form[user_input]
                    else:
                        to_add_missing_cons_node = RepoRiskThreatAssetConsequence(repo_asset_id=asset_id,
                                                                                  repo_threat_id=threat_id,
                                                                                  repo_consequence_id=
                                                                                  deconstructedId[1],
                                                                                  repo_response_id=deconstructedId[
                                                                                      2],
                                                                                  threat_occurrence=to_add_threat_occurence_bool,
                                                                                  prob=request.form[user_input])
                        db.session.add(to_add_missing_cons_node)
                    db.session.commit()
                else:
                    flash('Error adding user input, this shouldnt happen: Malformed Input forms')
                    return redirect("/repo/risk/configuration/threat/" + threat_id + "/asset/" + asset_id + "/")
        else:
            for user_input in request.form:
                deconstructedId = user_input.split("|")
                # print("deconstructedId Mat")
                # print(deconstructedId)
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
                    # print("deconstructedId Cons")
                    # print(deconstructedId)
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
        if db.session.query(RepoOrganisationSecurityPosture.id).first():
            repo_organisation_security_posture = RepoOrganisationSecurityPosture.query.first()
        else:
            repo_organisation_security_posture = RepoOrganisationSecurityPosture()
            db.session.add(repo_organisation_security_posture)
            db.session.commit()
        new_security_posture_form = FormEditRepoOrganisationSecurityPosture()
        new_security_posture_form.id.data = repo_organisation_security_posture.id
        new_security_posture_form.q1_completedSRA.data = str(repo_organisation_security_posture.q1_completedSRA)
        new_security_posture_form.q2_include_IS_SRA.data = str(repo_organisation_security_posture.q2_include_IS_SRA)
        new_security_posture_form.q3_compliance.data = str(repo_organisation_security_posture.q3_compliance)
        new_security_posture_form.q4_respond.data = str(repo_organisation_security_posture.q4_respond)
        new_security_posture_form.q5_respond_personnel.data = str(repo_organisation_security_posture.q5_respond_personnel)

        new_security_posture_form.q6_communicate_responses.data =str(repo_organisation_security_posture.q6_communicate_responses)
        new_security_posture_form.q7_documented_policies.data =str(repo_organisation_security_posture.q7_documented_policies)
        new_security_posture_form.q8_reflect_business_practices.data =str(repo_organisation_security_posture.q8_reflect_business_practices)
        new_security_posture_form.q9_documentation_availability.data =str(repo_organisation_security_posture.q9_documentation_availability)
        new_security_posture_form.q10_responsible.data =str(repo_organisation_security_posture.q10_responsible)
        new_security_posture_form.q11_defined_access.data =str(repo_organisation_security_posture.q11_defined_access)
        new_security_posture_form.q12_member_screening.data =str(repo_organisation_security_posture.q12_member_screening)
        new_security_posture_form.q13_security_training.data =str(repo_organisation_security_posture.q13_security_training)
        new_security_posture_form.q14_monitoring_login.data =str(repo_organisation_security_posture.q14_monitoring_login)
        new_security_posture_form.q15_protection_malicious.data =str(repo_organisation_security_posture.q15_protection_malicious)
        new_security_posture_form.q16_password_security.data =str(repo_organisation_security_posture.q16_password_security)
        new_security_posture_form.q17_awareness_training.data =str(repo_organisation_security_posture.q17_awareness_training)
        new_security_posture_form.q18_sanction_policy.data =str(repo_organisation_security_posture.q18_sanction_policy)
        new_security_posture_form.q19_personnel_access.data =str(repo_organisation_security_posture.q19_personnel_access)
        new_security_posture_form.q20_access_to_PHI.data =str(repo_organisation_security_posture.q20_access_to_PHI)
        new_security_posture_form.q21_kind_of_access.data =str(repo_organisation_security_posture.q21_kind_of_access)
        new_security_posture_form.q22_use_of_encryption.data =str(repo_organisation_security_posture.q22_use_of_encryption)
        new_security_posture_form.q23_periodic_review_of_IS.data =str(repo_organisation_security_posture.q23_periodic_review_of_IS)
        new_security_posture_form.q24_monitor_system_activity.data =str(repo_organisation_security_posture.q24_monitor_system_activity)
        new_security_posture_form.q25_logoff_policy.data =str(repo_organisation_security_posture.q25_logoff_policy)
        new_security_posture_form.q26_user_authentication_policy.data =str(repo_organisation_security_posture.q26_user_authentication_policy)
        new_security_posture_form.q27_unauthorised_modification.data =str(repo_organisation_security_posture.q27_unauthorised_modification)
        new_security_posture_form.q28_unauthorised_modification_transmitted.data =str(repo_organisation_security_posture.q28_unauthorised_modification_transmitted)
        new_security_posture_form.q29_manage_facility_access.data =str(repo_organisation_security_posture.q29_manage_facility_access)
        new_security_posture_form.q30_manage_device_access.data =str(repo_organisation_security_posture.q30_manage_device_access)
        new_security_posture_form.q31_device_inventory.data =str(repo_organisation_security_posture.q31_device_inventory)
        new_security_posture_form.q32_validate_facility_access.data =str(repo_organisation_security_posture.q32_validate_facility_access)
        new_security_posture_form.q33_activity_on_IS_with_PHI.data =str(repo_organisation_security_posture.q33_activity_on_IS_with_PHI)
        new_security_posture_form.q34_backup_PHI.data =str(repo_organisation_security_posture.q34_backup_PHI)
        new_security_posture_form.q35_sanitise_disposed_devices.data =str(repo_organisation_security_posture.q35_sanitise_disposed_devices)
        new_security_posture_form.q36_connected_devices.data =str(repo_organisation_security_posture.q36_connected_devices)
        new_security_posture_form.q37_necessary_access_rules.data =str(repo_organisation_security_posture.q37_necessary_access_rules)
        new_security_posture_form.q38_monitor_3rd_access.data =str(repo_organisation_security_posture.q38_monitor_3rd_access)
        new_security_posture_form.q39_sanitise_new_devices.data =str(repo_organisation_security_posture.q39_sanitise_new_devices)
        new_security_posture_form.q40_BAA.data =str(repo_organisation_security_posture.q40_BAA)
        new_security_posture_form.q41_monitor_BA.data =str(repo_organisation_security_posture.q41_monitor_BA)
        new_security_posture_form.q42_contingency_plan.data =str(repo_organisation_security_posture.q42_contingency_plan)
        new_security_posture_form.q43_determine_critical_IS.data =str(repo_organisation_security_posture.q43_determine_critical_IS)
        new_security_posture_form.q44_pdr_security_incidents.data =str(repo_organisation_security_posture.q44_pdr_security_incidents)
        new_security_posture_form.q45_incident_response_plan.data =str(repo_organisation_security_posture.q45_incident_response_plan)
        new_security_posture_form.q46_incident_response_team.data =str(repo_organisation_security_posture.q46_incident_response_team)
        new_security_posture_form.q47_necessary_IS.data =str(repo_organisation_security_posture.q47_necessary_IS)
        new_security_posture_form.q48_access_when_emergency.data =str(repo_organisation_security_posture.q48_access_when_emergency)
        new_security_posture_form.q49_backup_plan.data =str(repo_organisation_security_posture.q49_backup_plan)
        new_security_posture_form.q50_disaster_recovery_plan.data =str(repo_organisation_security_posture.q50_disaster_recovery_plan)



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
                    repo_threat_id=threat_id).count() == 0:
                print("NO PREVIOUS INPUT------------------------")
                print(RepoRiskThreatAssetMaterialisation.query.filter_by(
                    repo_asset_id=asset_id,
                    repo_threat_id=threat_id).first())
                print("threat_id =" + str(type(threat_id)) + "asset_id= " + str(type(asset_id)))
                print("----------==============----------")
                print(repo_threat_materialisations)
                print(repo_threat_responses)
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

                        # prob_item = next(item for item in existing_user_input_materialisation if
                        #                  item["repo_response_id"] == response["id"] and item[
                        #                      "repo_materialisation_id"] == materialisation["id"] and item[
                        #                      "threat_occurrence"] is True)

                        prob_item = False

                        for item in existing_user_input_materialisation:
                            if item["repo_response_id"] == response["id"] and item[
                                "repo_materialisation_id"] == materialisation["id"] and item[
                                "threat_occurrence"] is True:
                                prob_item = item

                        if prob_item:
                            print("Prob Item is:")
                            print(prob_item)
                            temp_array_threat_materialisation_calculation.append(
                                {"response": response, "materialisation": materialisation, "threat_occurrence": True,
                                 "prob": prob_item['prob']})
                        else:
                            temp_array_threat_materialisation_calculation.append(
                                {"response": response, "materialisation": materialisation, "threat_occurrence": True,
                                 "prob": 50})

                        # prob_item = next(item for item in existing_user_input_materialisation if
                        #                  item["repo_response_id"] == response["id"] and item[
                        #                      "repo_materialisation_id"] == materialisation["id"] and item[
                        #                      "threat_occurrence"] is False)

                        prob_item = False

                        for item in existing_user_input_materialisation:
                            if item["repo_response_id"] == response["id"] and item[
                                "repo_materialisation_id"] == materialisation["id"] and item[
                                "threat_occurrence"] is False:
                                prob_item = item

                        if prob_item:
                            print("Prob Item is:")
                            print(prob_item)
                            temp_array_threat_materialisation_calculation.append(
                                {"response": response, "materialisation": materialisation, "threat_occurrence": False,
                                 "prob": prob_item['prob']})
                        else:
                            temp_array_threat_materialisation_calculation.append(
                                {"response": response, "materialisation": materialisation, "threat_occurrence": False,
                                 "prob": 50})

                    array_threat_materialisation_calculation.append(temp_array_threat_materialisation_calculation)

                for consequence in repo_threat_consequence:
                    temp_array_threat_consequence_calculation = []
                    for response in repo_threat_responses:

                        # prob_item = next(item for item in existing_user_input_consequence if
                        #                  item["repo_response_id"] == response["id"] and item["repo_consequence_id"] ==
                        #                  consequence["id"] and item["threat_occurrence"] is True)

                        prob_item = False

                        for item in existing_user_input_consequence:
                            if item["repo_response_id"] == response["id"] and item["repo_consequence_id"] == \
                                    consequence["id"] and item["threat_occurrence"] is True:
                                prob_item = item

                        if prob_item:
                            print("Prob Item is:")
                            print(prob_item)
                            temp_array_threat_consequence_calculation.append(
                                {"response": response, "consequence": consequence, "threat_occurrence": True,
                                 "prob": prob_item['prob']})
                        else:
                            temp_array_threat_consequence_calculation.append(
                                {"response": response, "consequence": consequence, "threat_occurrence": True,
                                 "prob": 50})

                        # prob_item = next(item for item in existing_user_input_consequence if
                        #                  item["repo_response_id"] == response["id"] and item["repo_consequence_id"] ==
                        #                  materialisation["id"] and item["threat_occurrence"] is False)

                        prob_item = False

                        for item in existing_user_input_consequence:
                            if item["repo_response_id"] == response["id"] and item["repo_consequence_id"] == \
                                    consequence["id"] and item["threat_occurrence"] is False:
                                prob_item = item

                        if prob_item:
                            print("Prob Item is:")
                            print(prob_item)
                            temp_array_threat_consequence_calculation.append(
                                {"response": response, "consequence": consequence, "threat_occurrence": False,
                                 "prob": prob_item['prob']})
                        else:
                            temp_array_threat_consequence_calculation.append(
                                {"response": response, "consequence": consequence, "threat_occurrence": False,
                                 "prob": 50})

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
        try:
            # repo_vulnerabilities = VulnerabilityReportVulnerabilitiesLink.query.filter_by(asset_id=asset_id).all()
            # NNEEEED TO CHECK THIS
            repo_vulnerabilities = db.session.query(VulnerabilityReportVulnerabilitiesLink).join(
                CommonVulnerabilitiesAndExposures, VulnerabilityReportVulnerabilitiesLink.cve).join(RepoThreat,
                                                                                                    CommonVulnerabilitiesAndExposures.threats).filter(
                VulnerabilityReportVulnerabilitiesLink.asset_id == asset_id, RepoThreat.id == threat_id).all()
            # repo_vulnerabilities = VulnerabilityReportVulnerabilitiesLink.join(VulnerabilityReportVulnerabilitiesLink.cve).query.filter().all()
        except SQLAlchemyError:
            return Response("SQLAlchemyError", 500)

        try:
            repo_controls = RepoControl.query.join(VulnerabilityReportVulnerabilitiesLink).filter(
                VulnerabilityReportVulnerabilitiesLink.asset_id == asset_id).all()
        except SQLAlchemyError:
            return Response("SQLAlchemyError", 500)

        print("------------------------------======================================================")

        #
        # print(repo_actors[0].__table__.columns._data.keys(), flush=True)

        json_controls = convert_database_items_to_json_table(repo_controls)

        json_vulnerabilities = convert_database_items_to_json_table(repo_vulnerabilities)
        for it, instance in enumerate(json_vulnerabilities):
            instance["cve_actual_id"] = repo_vulnerabilities[it].cve.CVEId
            print(instance, flush=True)
            print("---")
        json_controls = json.dumps(json_controls, default=str)
        json_vulnerabilities = json.dumps(json_vulnerabilities, default=str)

        print("Threat id is" + str(threat_id))
        print(json_controls)
        print(json_vulnerabilities)
        print(array_threat_materialisation_calculation)
        return render_template("templates_risk_assessment/repo_risk_configuration_threat_asset.html",
                               threat_id=threat_id, asset_id=asset_id, json_controls=json_controls,
                               json_vulnerabilities=json_vulnerabilities,
                               repo_threats=repo_threats, this_threat=this_threat, repo_assets=repo_assets,
                               array_threat_consequence_calculation=array_threat_consequence_calculation,
                               array_threat_materialisation_calculation=array_threat_materialisation_calculation,
                               new_security_posture_form=new_security_posture_form)


@app.route('/repo/risk/configuration/impact/threat/<threat_id>/', methods=['GET', 'POST'])
@app.route('/repo/risk/configuration/impact/threat/<threat_id>/asset/<asset_id>/', methods=['GET', 'POST'])
@app.route('/repo/risk/configuration/impact/<impact_id>/threat/<threat_id>/asset/<asset_id>/', methods=['GET', 'POST'])
def repo_risk_configuration_impacts_risk(threat_id=1, asset_id=-1, impact_id=-1):
    """ Page that setups values for impact asset threat relationship risk assessment values
    The value assignment depends on knowing what the order of the entries will be since we know the
    metadat of the table if these change then this will not work correctly or at all
    This page will not work if static datam such as service -a asset relationship is changed """
    if request.method == 'POST':
        # existing_values = RepoAssetThreatConsequenceServiceImpactRelationship.query.filter_by(
        #     repo_threat_id=threat_id,
        #     repo_impact_id=impact_id,
        #     repo_asset_id=asset_id)

        for user_input in request.form:
            deconstructedId = user_input.split("|")
            # print("deconstructedId Mat")
            # print(deconstructedId)

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

            # print("NEW ENTRY")
            # print(related_mixed_state)
            # Entry doesnt exist create new one
            # Create main entry
            print("ARRAYS ARE")
            print(related_service_state)
            print(related_service_list)
            # print(json.dumps(related_service_list))
            print(related_consequence_state)
            print(related_consequence_list)
            # print(json.dumps(related_consequence_list))
            does_exist = RepoAssetThreatConsequenceServiceImpactRelationship.query.filter_by(
                repo_asset_id=asset_id,
                repo_threat_id=threat_id,
                repo_impact_id=impact_id,
                services_state=json.dumps(related_service_state),
                consequences_state=json.dumps(related_consequence_state)
            )
            if does_exist.count() > 0:
                print("Value exists =-=-=-=-=-=-=-=-=-=-=-=-=-=")
                to_score_entry = does_exist.first()
            else:
                print("Value new =-=-=-=-=-=-=-=-=-=-=-=-=-=")
                to_score_entry = RepoAssetThreatConsequenceServiceImpactRelationship(repo_asset_id=asset_id,
                                                                                     repo_threat_id=threat_id,
                                                                                     repo_impact_id=impact_id,
                                                                                     services_state=json.dumps(
                                                                                         related_service_state),
                                                                                     consequences_state=json.dumps(
                                                                                         related_consequence_state)
                                                                                     )
                db.session.add(to_score_entry)
                db.session.flush()
            print(to_score_entry)
            if deconstructedId[0] == "low":
                print("Value low is: ----------", request.form[user_input], "-------------")
                to_score_entry.low_prob = request.form[user_input]
            elif deconstructedId[0] == "medium":
                print("Value med is: ----------", request.form[user_input], "-------------")
                to_score_entry.med_prob = request.form[user_input]
            else:
                print("Value high is: ----------", request.form[user_input], "-------------")
                to_score_entry.high_prob = request.form[user_input]

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
        does_exist = RepoAssetThreatConsequenceServiceImpactRelationship.query.filter_by(
            repo_asset_id=asset_id,
            repo_threat_id=threat_id,
            repo_impact_id=impact_id
            # services_state=json.dumps(related_service_state),
            # consequences_state=json.dumps(related_consequence_state)
        )
        if does_exist.count() == 0:
            for to_send in array_impact_calculation:
                to_send.append(34)
                to_send.append(33)
                to_send.append(33)
            # to_score_entry = does_exist.first()
        else:
            print("---Doesnt Exist ----")
            custom_it = 0
            does_exist = does_exist.all()
            for to_send in array_impact_calculation:
                print(does_exist[custom_it])
                to_send.append(does_exist[custom_it].low_prob)
                to_send.append(does_exist[custom_it].med_prob)
                to_send.append(does_exist[custom_it].high_prob)
                custom_it = custom_it + 1

        return render_template("templates_risk_assessment/repo_risk_configuration_impacts_risk.html",
                               repo_impacts=repo_impacts, repo_threats=repo_threats, repo_assets=repo_assets,
                               this_threat=this_threat,
                               impact_id=impact_id, threat_id=threat_id, asset_id=asset_id, this_asset=this_asset,
                               this_impact=this_impact, array_impact_calculation=array_impact_calculation)


@app.route('/repo/risk/configuration/objective/<objective_id>/', methods=['GET', 'POST'])
def repo_risk_configuration_objective_risk(objective_id=1):
    """ Page that setups values for objectives impact values
        The value assignment depends on knowing what the order of the entries will be since we know the
        metadat of the table if these change then this will not work correctly or at all
        This page will not work if static datam such as impact objective relations is changed """
    if request.method == 'POST':
        # new_service_form = FormAddRepoService()
        for user_input in request.form:
            deconstructedId = user_input.split("|")
            # print("deconstructedId Mat")
            # print(deconstructedId)

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

            does_exist = RepoObjectiveImpactRelationship.query.filter_by(
                repo_objective_id=objective_id,
                impacts_state=json.dumps(related_impact_state)
            )
            if does_exist.count() > 0:
                to_score_entry = does_exist.first()
            else:
                to_score_entry = RepoObjectiveImpactRelationship(repo_objective_id=objective_id,
                                                                 impacts_state=json.dumps(related_impact_state))
                db.session.add(to_score_entry)
                db.session.flush()

            if deconstructedId[0] == "low":
                to_score_entry.low_prob = request.form[user_input]
            elif deconstructedId[0] == "med":
                to_score_entry.med_prob = request.form[user_input]
            else:
                to_score_entry.high_prob = request.form[user_input]
            #     Find if this specific input exists

            # joined = db.session.query(RepoObjectiveImpactRelationship, RepoObjectiveImpactRelationshipImpactManyToMany) \
            #     .join(RepoObjectiveImpactRelationshipImpactManyToMany) \
            #     .filter(
            #     RepoObjectiveImpactRelationship.repo_objective_id == objective_id,
            #     # RepoAssetThreatConsequenceServiceImpactRelationshipConsequenceManyToMany.repo_consequence_id == 1,
            #     # RepoAssetThreatConsequenceServiceImpactRelationshipServiceManyToMany.repo_service_id == 1,
            # )
            # # print("NUMBER OF RECORDS")
            # # print(joined.count())
            # joined = joined.all()
            #
            # concatted = {}
            #
            # for temp_joined in joined:
            #     # print("Single Line")
            #     # print("Inner Line")
            #     if temp_joined[0] not in concatted:
            #         concatted[temp_joined[0]] = []
            #     for inner_joined in temp_joined:
            #         if inner_joined is temp_joined[0]:
            #             continue
            #         # print(concatted[temp_joined[0]])
            #         inner_joined_arrayed = {"imp_id": str(inner_joined.repo_impact_id),
            #                                 "state": str(inner_joined.repo_impact_state)}
            #
            #         if inner_joined_arrayed not in concatted[temp_joined[0]]:
            #             concatted[temp_joined[0]].append(inner_joined_arrayed)
            #         # print(inner_joined)
            # # print(concatted)
            #
            # existing_entry = None
            # # print(concatted.items())
            # print("------------ COMPARISON ARE ----------")
            # for concatted_entry_key, concatted_entry_value in concatted.items():
            #     print(related_impact_state)
            #     print(concatted_entry_value)
            #     if sorted(concatted_entry_value, key=lambda ele: sorted(ele.items())) == sorted(related_impact_state,
            #                                                                                     key=lambda ele: sorted(
            #                                                                                         ele.items())):
            #         # print("SSSSSSSSSSSSSSSSSSSSSSSSSSSSSSAAAAAAAAAAAAAAAAAAAAAAAAMMMMMMMMMMMMEEEEEEEEEE")
            #         # print(related_mixed_state)
            #         # print(concatted_entry_value)
            #         # print("STOOOOOOOOOOOOOOOOOOOOOOOOOOOOPPPPPPPPPPPSSSSSSSSSSSSSSSSSSSSSSS")
            #         existing_entry = concatted_entry_key
            #         break
            #
            # # print(existing_entry)
            # # print("THIS QUERY RESULT IS")
            # # print()
            # # current_entry = convert_database_items_to_json_table(joined)
            # # for temp_joined in current_entry:
            # #     # temp_temp = convert_database_items_to_json_table(temp_joined)
            # #     print(temp_joined)
            # if existing_entry:
            #     # Entry already exists
            #
            #     # print("Already exists")
            #     # print(related_mixed_state)
            #     # print(existing_entry)
            #     if deconstructedId[0] == "low":
            #         existing_entry.low_prob = request.form[user_input]
            #     elif deconstructedId[0] == "med":
            #         existing_entry.med_prob = request.form[user_input]
            #     else:
            #         existing_entry.high_prob = request.form[user_input]
            #
            #     # print("Not yet 2")
            # else:
            #     # print("NEW ENTRY")
            #     # print(related_mixed_state)
            #     # Entry doesnt exist create new one
            #     # Create main entry
            #     to_add_main = RepoObjectiveImpactRelationship(repo_objective_id=objective_id)
            #     db.session.add(to_add_main)
            #     db.session.flush()
            #     # Create secondary entries
            #
            #     for single_impact in related_impact_state:
            #         # Convert String to bool
            #         # if single_impact["state"] == "low":
            #         #     temp_bool = 0
            #         # elif single_impact["state"] == "med":
            #         #     temp_bool = 1
            #         # else:
            #         #     temp_bool = 2
            #         to_add_secondary_imp = RepoObjectiveImpactRelationshipImpactManyToMany(
            #             repo_impact_id=single_impact["imp_id"],
            #             repo_impact_state=int(single_impact["state"])
            #         )
            #         print("ADDING")
            #         print(to_add_secondary_imp)
            #         print(to_add_main)
            #         to_add_main.impacts.append(to_add_secondary_imp)
            #         db.session.add(to_add_secondary_imp)
            #         db.session.flush()
            #
            #     if deconstructedId[0] == "low":
            #         to_add_main.low_prob = request.form[user_input]
            #     elif deconstructedId[0] == "medium":
            #         to_add_main.med_prob = request.form[user_input]
            #     else:
            #         to_add_main.high_prob = request.form[user_input]

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

        # If there are aready values
        does_exist = RepoObjectiveImpactRelationship.query.filter_by(
            repo_objective_id=objective_id,
        )

        if does_exist.count() == 0:
            for to_send in array_impact_calculation:
                to_send.append(34)
                to_send.append(33)
                to_send.append(33)
            # to_score_entry = does_exist.first()
        else:
            custom_it = 0
            does_exist = does_exist.all()
            for to_send in array_impact_calculation:
                to_send.append(does_exist[custom_it].low_prob)
                to_send.append(does_exist[custom_it].med_prob)
                to_send.append(does_exist[custom_it].high_prob)
                custom_it = custom_it + 1

        # existing_values = db.session.query(RepoObjectiveImpactRelationship,
        #                                    RepoObjectiveImpactRelationshipImpactManyToMany) \
        #     .join(RepoObjectiveImpactRelationshipImpactManyToMany) \
        #     .filter(
        #     RepoObjectiveImpactRelationship.repo_objective_id == objective_id,
        # )
        #
        # if existing_values.count() > 0:
        #     joined = existing_values.all()
        #
        #     concatted = {}
        #
        #     for temp_joined in joined:
        #         # print("Single Line")
        #         # print("Inner Line")
        #         if temp_joined[0] not in concatted:
        #             concatted[temp_joined[0]] = []
        #         for inner_joined in temp_joined:
        #             if inner_joined is temp_joined[0]:
        #                 continue
        #             # print(concatted[temp_joined[0]])
        #             if inner_joined.repo_impact_state == 0:
        #                 temp_state = "low"
        #             elif inner_joined.repo_impact_state == 1:
        #                 temp_state = "med"
        #             else:
        #                 temp_state = "high"
        #             inner_joined_arrayed = {"impact": inner_joined.repo_impact,
        #                                     "state": temp_state}
        #             # if type(inner_joined) is RepoAssetThreatConsequenceServiceImpactRelationshipConsequenceManyToMany:
        #             #     # inner_joined_arrayed = ['cons', inner_joined.repo_consequence_id, inner_joined.repo_consequence_state]
        #             #     inner_joined_arrayed = {"consequence": {'id': inner_joined.repo_consequence_id,
        #             #                                             'name': inner_joined.repo_consequence.name,
        #             #                                             'threat_id': inner_joined.repo_consequence.threat_id,
        #             #                                             'materialisation_id': inner_joined.repo_consequence.materialisation_id
        #             #                                             },
        #             #                             "state": inner_joined.repo_consequence_state}
        #             # else:
        #             #     # inner_joined_arrayed = ['serv', inner_joined.repo_service_id, inner_joined.repo_service_state]
        #             #     inner_joined_arrayed = {
        #             #         "service": {'id': inner_joined.repo_service_id, 'name': inner_joined.repo_service.name},
        #             #         "state": inner_joined.repo_service_state}
        #             if inner_joined_arrayed not in concatted[temp_joined[0]]:
        #                 concatted[temp_joined[0]].append(inner_joined_arrayed)
        #     print("------------ RESULTS ARE ----------")
        #     print(concatted.items())
        #     for to_send in array_impact_calculation:
        #         for concatted_entry_key, concatted_entry_value in concatted.items():
        #             # print("------Comparison------")
        #             # print(to_send)
        #             # print(concatted_entry_value)
        #             ddiff = DeepDiff(to_send, concatted_entry_value, ignore_order=True)
        #             # print(ddiff)
        #
        #             if ddiff == {}:
        #                 print("SAMEEEEEEEEEEEEEEE")
        #                 print(to_send)
        #                 print(concatted_entry_value)
        #                 to_send.append(concatted_entry_key.low_prob)
        #                 to_send.append(concatted_entry_key.med_prob)
        #                 to_send.append(concatted_entry_key.high_prob)
        #                 # print(to_send)
        #
        #             # if sorted(concatted_entry_value, key=lambda ele: sorted(ele.items())) == sorted(
        #             #         to_send, key=lambda ele: sorted(ele.items())):
        #         #             print("SSSSSSSSSSSSSSSSSSSSSSSSSSSSSSAAAAAAAAAAAAAAAAAAAAAAAAMMMMMMMMMMMMEEEEEEEEEE")
        #         #     # print(related_mixed_state)
        #         # #     # print(concatted_entry_value)
        #         #  print("STOOOOOOOOOOOOOOOOOOOOOOOOOOOOPPPPPPPPPPPSSSSSSSSSSSSSSSSSSSSSSS")
        #         # #             existing_entry = concatted_entry_key
        #         #         break
        # else:
        #     for to_send in array_impact_calculation:
        #         to_send.append(50)
        #         to_send.append(50)
        #         to_send.append(50)
        #         print(to_send)
        # # for

        for to_send in array_impact_calculation:
            print(to_send)

        return render_template("templates_risk_assessment/repo_risk_configuration_objectives_risk.html",
                               repo_objectives=repo_objectives,
                               objective_id=objective_id,
                               this_objective=this_objective, array_objective_calculation=array_impact_calculation)


@app.route('/repo/risk/configuration/utility/<utility_id>/', methods=['GET', 'POST'])
def repo_risk_configuration_utility_risk(utility_id=1):
    if request.method == 'POST':
        # for user_input in request.form:
        existing_values = RepoUtilityObjectiveRelationship.query.filter_by(repo_utility_id=utility_id)
        if existing_values.count() > 0:
            # This is done in a 'dumb' way where the instances get their values depending on their order
            # This should work unless the database is changed
            existing_values = existing_values.all()

            custom_it = 0
            results = list(request.form.values())
            for existing_value in existing_values:
                print(custom_it)
                print(results)
                existing_value.utility_value = results[custom_it]
                custom_it += 1

            db.session.commit()
        else:
            for user_input in request.form:
                # print(user_input)
                deconstructedId = user_input.split("|")
                deconstructedId.pop(0)
                # print("deconstructedId Mat")
                # print(deconstructedId)
                # print(request.form[user_input])
                to_add_relationship = RepoUtilityObjectiveRelationship(repo_utility_id=utility_id,
                                                                       utility_value=request.form[user_input])
                db.session.add(to_add_relationship)
                db.session.flush()
                for custom_it in range(0, len(deconstructedId), 2):
                    if deconstructedId[custom_it + 1] == 'low':
                        to_add_state = 1
                    elif deconstructedId[custom_it + 1] == 'med':
                        to_add_state = 2
                    else:
                        to_add_state = 3
                    to_add_many_to_many = RepoUtilityObjectiveRelationshipManyToMany(
                        repo_objective_id=deconstructedId[custom_it], repo_this_entry_id=to_add_relationship.id,
                        repo_objective_state=to_add_state)
                    db.session.add(to_add_many_to_many)
        db.session.commit()

        flash('Utlity "{}" Configured Succesfully'.format(utility_id))
        return redirect("/repo/risk/configuration/utility/" + utility_id + "/")
    else:
        try:
            repo_utilities = RepoUtility.query.all()
        except SQLAlchemyError:
            return Response("SQLAlchemyError", 500)

        try:
            this_utility = RepoUtility.query.filter_by(id=int(utility_id)).first()
        except SQLAlchemyError:
            return Response("SQLAlchemyError", 500)

        print(this_utility)
        print("----------")
        try:
            repo_objectives_related = RepoObjective.query.filter(
                RepoObjective.utilities.any(id=int(utility_id))).all()
        except SQLAlchemyError:
            return Response("SQLAlchemyError", 500)

        array_utility_calculation = []
        for repo_objective_related in repo_objectives_related:
            if not array_utility_calculation:
                to_add_low = {"id": repo_objective_related.id, "name": repo_objective_related.name, "state": "low"}
                to_add_med = {"id": repo_objective_related.id, "name": repo_objective_related.name, "state": "med"}
                to_add_high = {"id": repo_objective_related.id, "name": repo_objective_related.name, "state": "high"}

                array_utility_calculation.append([to_add_low])
                array_utility_calculation.append([to_add_med])
                array_utility_calculation.append([to_add_high])
            else:
                temp_array_utility_calculation_1 = deepcopy(array_utility_calculation)
                temp_array_utility_calculation_2 = deepcopy(array_utility_calculation)

                for to_be_added in array_utility_calculation:
                    to_be_added.append(
                        {"id": repo_objective_related.id, "name": repo_objective_related.name, "state": "low"})

                for to_be_added in temp_array_utility_calculation_1:
                    to_be_added.append(
                        {"id": repo_objective_related.id, "name": repo_objective_related.name, "state": "med"})

                for to_be_added in temp_array_utility_calculation_2:
                    to_be_added.append(
                        {"id": repo_objective_related.id, "name": repo_objective_related.name, "state": "high"})

                array_utility_calculation = array_utility_calculation + temp_array_utility_calculation_1 + temp_array_utility_calculation_2

        print("TEST")
        for two in array_utility_calculation:
            print(two)

        # existing_values = db.session.query(RepoUtilityObjectiveRelationship,
        #                                    RepoUtilityObjectiveRelationshipManyToMany).join(
        #     RepoUtilityObjectiveRelationshipManyToMany).filter(
        #     RepoUtilityObjectiveRelationship.repo_utility_id == utility_id,
        # )

        existing_values = RepoUtilityObjectiveRelationship.query.filter_by(repo_utility_id=int(utility_id))
        if existing_values.count() > 0:
            # Add values of utlity nodes if they exist

            # This is for testing it isnt exactly right even if it works
            # THis arranges value in a dumb way
            joined = existing_values.all()
            it = 0
            for to_edit in joined:
                print("NEW TEST")
                print(to_edit)
                print(array_utility_calculation[it])
                array_utility_calculation[it].append({"value": to_edit.utility_value})
                it += 1

        else:
            # Add default values if there are none
            for to_edit in array_utility_calculation:
                to_edit.append({"value": "50"})

        print("TEST3")
        for two in array_utility_calculation:
            print(two)

        repo_utilities = convert_database_items_to_json_table(repo_utilities)
        return render_template("templates_risk_assessment/repo_risk_configuration_utlity_risk.html",
                               this_utility=this_utility,
                               repo_utilities=repo_utilities,
                               array_utility_calculation=array_utility_calculation
                               # repo_objectives=repo_objectives,
                               # objective_id=objective_id,
                               # this_objective=this_objective, array_objective_calculation=array_impact_calculation
                               )


@app.route('/repo/risk/assessment/<threat_id>/asset/<asset_id>/', methods=['GET', 'POST'])
def repo_risk_assessment(threat_id=1, asset_id=-1):
    if request.method == 'POST':
        # new_service_form = FormAddRepoService()
        try:
            this_risk_assessment = RepoRiskAssessment.query.filter_by(repo_threat_id=threat_id, repo_asset_id=asset_id)
        except SQLAlchemyError:
            return Response("SQLAlchemyError", 500)

        try:
            these_alerts = RepoObjectivesOptions.query.all()
        except SQLAlchemyError:
            return Response('SQLAlchemyError', 500)

        if this_risk_assessment.count() == 0:
            # Save the new Valid Risk Assessment
            this_risk_assessment = RepoRiskAssessment(repo_threat_id=threat_id, repo_asset_id=asset_id)
            db.session.add(this_risk_assessment)
            db.session.flush()

            # Save the firs produced report
            risk_assessment_result = start_risk_assessment(threat_id, asset_id)
            # risk_assessment_result = start_risk_assessment_alert(threat_id, asset_id)

            # print(risk_assessment_result)
            # print(type(risk_assessment_result))
            first_risk_assessment_result = risk_assessment_save_report(threat_id, asset_id, risk_assessment_result, "baseline")
            # exposure_inference = ""
            # materialisations_inference = ""
            # consequences_inference = ""
            # services_inference = ""
            # impacts_inference = ""
            # objectives_inference = ""
            # utility_inference = ""
            # alert_triggered = ""
            #
            # for key, value in risk_assessment_result.items():
            #     # print("KEY IS")
            #     # print(key)
            #     temp_key = "".join(i for i in key if not i.isdigit())
            #     temp_digit = "".join(i for i in key if i.isdigit())
            #
            #     if temp_key == "te":
            #         exposure_inference = exposure_inference + str(temp_digit) + "|" + str(
            #             value.values[0]) + "|" + str(
            #             value.values[1]) + "|"
            #     elif temp_key == "mat":
            #         materialisations_inference = materialisations_inference + str(temp_digit) + "|" + str(
            #             value.values[0]) + "|" + str(
            #             value.values[1]) + "|"
            #     elif temp_key == "con":
            #         consequences_inference = consequences_inference + str(temp_digit) + "|" + str(
            #             value.values[0]) + "|" + str(
            #             value.values[1]) + "|"
            #     elif temp_key == "serv":
            #         services_inference = services_inference + str(temp_digit) + "|" + str(
            #             value.values[0]) + "|" + str(
            #             value.values[1]) + "|"
            #     elif temp_key == "imp":
            #         impacts_inference = impacts_inference + str(temp_digit) + "|" + str(value.values[0]) + "|" + str(
            #             value.values[1]) + "|" + str(value.values[2]) + "|"
            #     elif temp_key == "obj":
            #         objectives_inference = objectives_inference + str(temp_digit) + "|" + str(
            #             value.values[0]) + "|" + str(
            #             value.values[1]) + "|" + str(value.values[2]) + "|"
            #     elif temp_key == "util":
            #         print("[[[[[[[[[[[[[[[[[[[]]]]]]]]]]]]]]]]]]]")
            #         print(value)
            #         print("}}}}}}}}}}}}}}}}}}}{{{{{{{{{{{{{{{{{{{")
            #         optimal_value = {}
            #         highest_values = []
            #         for index, row in value.iterrows():
            #             print(type(temp_digit))
            #             if temp_digit == "1":
            #                 if index == ("0", "0"):
            #                     # print(";;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;")
            #                     #  Optimal values is always the same 0, 0, 0,
            #                     optimal_value = {"optimal_scenario": {
            #                         "confidentiality": "low",
            #                         "integrity": "low",
            #                         "availability": "low",
            #                         "probability": row[0]
            #                     }}
            #
            #                     # Sort other values
            #                     highest_values.append({
            #                         "confidentiality": "low",
            #                         "integrity": "low",
            #                         "availability": "low",
            #                         "probability": row[0]
            #                     })
            #                     highest_values.append({
            #                         "confidentiality": "low",
            #                         "integrity": "low",
            #                         "availability": "medium",
            #                         "probability": row[1]
            #                     })
            #                     highest_values.append({
            #                         "confidentiality": "low",
            #                         "integrity": "low",
            #                         "availability": "high",
            #                         "probability": row[2]
            #                     })
            #                     highest_values = sorted(highest_values, key=lambda k: k["probability"], reverse=True)
            #                 else:
            #                     # Check for each value if it is bigger than any saved value in that case save over the old one
            #                     # This way we get the bigger
            #                     # it is iterating over the rows values
            #                     # it2 is iterating over the saved values
            #                     for it in (0, 1, 2):
            #                         for it2 in (0, 1, 2):
            #                             if highest_values[it2]["probability"] < row[it]:
            #                                 print("VALUES TO  UPADTRE ARE---------------------")
            #                                 print(index)
            #                                 print(type(row))
            #                                 print(row)
            #                                 print(row.index[0][1])
            #                                 print(row.index[1][1])
            #                                 print(row.index[2][1])
            #
            #                                 # Create new object to add to the list of highest values
            #                                 to_add = {
            #                                     "confidentiality": "",
            #                                     "integrity": "",
            #                                     "availability": "",
            #                                     "probability": 0
            #                                 }
            #                                 if list(index)[0] == "0":
            #                                     # highest_values[it2]["confidentiality"] = "low"
            #                                     to_add["confidentiality"] = "low"
            #                                 elif list(index)[0] == "1":
            #                                     to_add["confidentiality"] = "medium"
            #                                 elif list(index)[0] == "2":
            #                                     to_add["confidentiality"] = "high"
            #                                 else:
            #                                     print("ERROR")
            #
            #                                 if list(index)[1] == "0":
            #                                     to_add["integrity"] = "low"
            #                                 elif list(index)[1] == "1":
            #                                     to_add["integrity"] = "medium"
            #                                 elif list(index)[1] == "2":
            #                                     to_add["integrity"] = "high"
            #                                 else:
            #                                     print("ERROR")
            #
            #                                 if row.index[it][1] == "0":
            #                                     to_add["availability"] = "low"
            #                                 elif row.index[it][1] == "1":
            #                                     to_add["availability"] = "medium"
            #                                 elif row.index[it][1] == "2":
            #                                     to_add["availability"] = "high"
            #                                 else:
            #                                     print("ERROR")
            #
            #                                 # highest_values[it2]["probability"] = row[it]
            #                                 to_add["probability"] = row[it]
            #
            #                                 # Pop last value and move the values to keep them in ascending order
            #                                 if it2 == 0:
            #                                     highest_values[2] = highest_values[1]
            #                                     highest_values[1] = highest_values[0]
            #                                     highest_values[0] = to_add
            #                                 elif it2 == 1:
            #                                     highest_values[2] = highest_values[1]
            #                                     highest_values[1] = to_add
            #                                 elif it2 == 2:
            #                                     highest_values[2] = to_add
            #                                 else:
            #                                     print("ERROR")
            #
            #                                 break
            #
            #             elif temp_digit == "2":
            #                 if index == ("0"):
            #                     optimal_value = {"optimal_scenario": {
            #                         "monetary": "low",
            #                         "safety": "low",
            #                         "probability": row[0]
            #                     }}
            #
            #                     highest_values.append({
            #                         "monetary": "low",
            #                         "safety": "low",
            #                         "probability": row[0]
            #                     })
            #
            #                     highest_values.append({
            #                         "monetary": "low",
            #                         "safety": "medium",
            #                         "probability": row[1]
            #                     })
            #
            #                     highest_values.append({
            #                         "monetary": "low",
            #                         "safety": "high",
            #                         "probability": row[2]
            #                     })
            #                     highest_values = sorted(highest_values, key=lambda k: k["probability"], reverse=True)
            #                 else:
            #                     # Check for each value if it is bigger than any saved value in that case save over the old one
            #                     # This way we get the bigger
            #                     # it is iterating over the rows values
            #                     # it2 is iterating over the saved values
            #                     for it in (0, 1, 2):
            #                         for it2 in (0, 1, 2):
            #                             if highest_values[it2]["probability"] < row[it]:
            #                                 print("VALUES TO  UPADTRE ARE---------------------")
            #                                 print(index)
            #                                 print(type(row))
            #                                 print(row)
            #                                 print(row.index[0][1])
            #                                 print(row.index[1][1])
            #                                 print(row.index[2][1])
            #
            #                                 # Create new object to add to the list of highest values
            #                                 to_add = {
            #                                     "monetary": "",
            #                                     "safety": "",
            #                                     "probability": 0
            #                                 }
            #
            #                                 if list(index)[0] == "0":
            #                                     # highest_values[it2]["confidentiality"] = "low"
            #                                     to_add["monetary"] = "low"
            #                                 elif list(index)[0] == "1":
            #                                     to_add["monetary"] = "medium"
            #                                 elif list(index)[0] == "2":
            #                                     to_add["monetary"] = "high"
            #                                 else:
            #                                     print("ERROR")
            #
            #                                 if row.index[it][1] == "0":
            #                                     to_add["safety"] = "low"
            #                                 elif row.index[it][1] == "1":
            #                                     to_add["safety"] = "medium"
            #                                 elif row.index[it][1] == "2":
            #                                     to_add["safety"] = "high"
            #                                 else:
            #                                     print("ERROR")
            #
            #                                 # highest_values[it2]["probability"] = row[it]
            #                                 to_add["probability"] = row[it]
            #
            #                                 # Pop last value and move the values to keep them in ascending order
            #                                 if it2 == 0:
            #                                     highest_values[2] = highest_values[1]
            #                                     highest_values[1] = highest_values[0]
            #                                     highest_values[0] = to_add
            #                                 elif it2 == 1:
            #                                     highest_values[2] = highest_values[1]
            #                                     highest_values[1] = to_add
            #                                 elif it2 == 2:
            #                                     highest_values[2] = to_add
            #                                 else:
            #                                     print("ERROR")
            #
            #                                 break
            #             else:
            #                 pass
            #             # print("ROW INDIVIDUALYL IS")
            #             # print(index)
            #             # print(row)
            #             # print(row[0])
            #             # print(row[1])
            #             # print(row[2])
            #
            #         most_likely_values = {"most_probable_scenarios": highest_values}
            #
            #         utility_inference = utility_inference + json.dumps(optimal_value) + "|" + json.dumps(
            #             most_likely_values) + "|"
            #
            #     # Check Objectives for alerts
            #     objectives_to_check = objectives_inference.split("|")
            #     for alert in these_alerts:
            #         # If value is 0 then there is no alert to check
            #         if alert.alert_level != 0:
            #             if alert.objective_fk == 1:
            #                 pass
            #             elif alert.objective_fk == 2:
            #                 pass
            #             elif alert.objective_fk == 3:
            #                 pass
            #             elif alert.objective_fk == 4:
            #                 pass
            #             elif alert.objective_fk == 5:
            #                 pass
            #             else:
            #                 pass
            #
            #     # elif temp_key == "util":
            #     #     materialisations_set_values = str(temp_digit)+ "|" + str(value.values(0)) + "|"
            #     else:
            #         print("Ignore")
            #
            # objectives_to_check = objectives_inference.split("|")
            # print("-------------ALL ALERTS CHECK -----------------------")
            # print(objectives_to_check)
            # for alert in these_alerts:
            #     # If value is 0 then there is no alert to check
            #     # alert.alert_level is wether there is an alert and the value of the alert that its triggered
            #     if alert.alert_level != 0:
            #         # Accessing
            #         alert_it_to_check = 0
            #         objective_name = ""
            #         if alert.objective_fk == 1:
            #             alert_it_to_check = 0
            #             objective_name = "Confidentiality"
            #         elif alert.objective_fk == 2:
            #             alert_it_to_check = 4
            #             objective_name = "Integrity"
            #         elif alert.objective_fk == 3:
            #             alert_it_to_check = 8
            #             objective_name = "Availability"
            #         elif alert.objective_fk == 4:
            #             alert_it_to_check = 12
            #             objective_name = "Monetary"
            #         elif alert.objective_fk == 5:
            #             alert_it_to_check = 16
            #             objective_name = "Safety"
            #
            #         value_to_check_against = 0
            #         if alert.alert_level == 1:
            #             value_to_check_against = 0.01
            #         elif alert.alert_level == 2:
            #             value_to_check_against = 0.1
            #         elif alert.alert_level == 3:
            #             value_to_check_against = 0.2
            #         elif alert.alert_level == 4:
            #             value_to_check_against = 0.4
            #         elif alert.alert_level == 5:
            #             value_to_check_against = 0.7
            #
            #         if json.loads(
            #                 objectives_to_check[alert_it_to_check + alert.objective_level]) > value_to_check_against:
            #             to_add_alert = {
            #                 objective_name: {
            #                     "level": alert.name,
            #                     "threshold": value_to_check_against
            #                 }
            #             }
            #             alert_triggered = alert_triggered + json.dumps(to_add_alert) + "|"
            #         else:
            #             pass
            #
            # first_risk_assessment_result = RepoRiskAssessmentReports(
            #     risk_assessment_id=this_risk_assessment.id,
            #     type="initial",
            #     exposure_inference=exposure_inference,
            #     # responses_set_values = responses_set_values,
            #     materialisations_inference=materialisations_inference,
            #     consequences_inference=consequences_inference,
            #     services_inference=services_inference,
            #     impacts_inference=impacts_inference,
            #     objectives_inference=objectives_inference,
            #     utilities_inference=utility_inference,
            #     alerts_triggered = alert_triggered
            # )
            #
            # db.session.add(first_risk_assessment_result)
            # db.session.commit()
            send_risk_report(first_risk_assessment_result.id, asset_id, threat_id)
        else:
            this_risk_assessment = this_risk_assessment.first()
            risk_assessment_result = start_risk_assessment(threat_id, asset_id)
            # risk_assessment_result = start_risk_assessment_alert(threat_id, asset_id, materialisation_value_increase =10, exposure_value_increase=50)
            # risk_assessment_result = start_risk_assessment_alert(threat_id, asset_id, exposure_value=100, materialisation_value=70, consequence_values=70)
            # risk_assessment_result = start_risk_assessment_alert(threat_id, asset_id, exposure_value=100, materialisation_value=100, consequence_values=100, materialisation_value_increase =10, exposure_value_increase=10)
            flash('New Function run ok'.format(asset_id))

            first_risk_assessment_result = risk_assessment_save_report(threat_id, asset_id, risk_assessment_result, "baseline")
            # return redirect("/repo/risk/assessment/" + threat_id + "/asset/" + asset_id + "/")
            # print(risk_assessment_result)
            # print(type(risk_assessment_result))

            # exposure_inference = ""
            # materialisations_inference = ""
            # consequences_inference = ""
            # services_inference = ""
            # impacts_inference = ""
            # objectives_inference = ""
            # utility_inference = ""
            # alert_triggered = ""
            #
            # print("-------------- All ITEMS ARE ------------------")
            # print(risk_assessment_result.items())
            # for key, value in risk_assessment_result.items():
            #     # print("KEY IS")
            #     # print(key)
            #     temp_key = "".join(i for i in key if not i.isdigit())
            #     temp_digit = "".join(i for i in key if i.isdigit())
            #
            #     if temp_key == "te":
            #         exposure_inference = exposure_inference + str(temp_digit) + "|" + str(
            #             value.values[0]) + "|" + str(
            #             value.values[1]) + "|"
            #     elif temp_key == "mat":
            #         materialisations_inference = materialisations_inference + str(temp_digit) + "|" + str(
            #             value.values[0]) + "|" + str(
            #             value.values[1]) + "|"
            #     elif temp_key == "con":
            #         consequences_inference = consequences_inference + str(temp_digit) + "|" + str(
            #             value.values[0]) + "|" + str(
            #             value.values[1]) + "|"
            #     elif temp_key == "serv":
            #         services_inference = services_inference + str(temp_digit) + "|" + str(
            #             value.values[0]) + "|" + str(
            #             value.values[1]) + "|"
            #     elif temp_key == "imp":
            #         impacts_inference = impacts_inference + str(temp_digit) + "|" + str(value.values[0]) + "|" + str(
            #             value.values[1]) + "|" + str(value.values[2]) + "|"
            #     elif temp_key == "obj":
            #         objectives_inference = objectives_inference + str(temp_digit) + "|" + str(
            #             value.values[0]) + "|" + str(
            #             value.values[1]) + "|" + str(value.values[2]) + "|"
            #     elif temp_key == "util":
            #         print("[[[[[[[[[[[[[[[[[[[]]]]]]]]]]]]]]]]]]]")
            #         print(value)
            #         print("}}}}}}}}}}}}}}}}}}}{{{{{{{{{{{{{{{{{{{")
            #         optimal_value = {}
            #         highest_values = []
            #         for index, row in value.iterrows():
            #             print(type(temp_digit))
            #             if temp_digit == "1":
            #                 if index == ("0","0"):
            #                     # print(";;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;")
            #                     #  Optimal values is always the same 0, 0, 0,
            #                     optimal_value = {"optimal_scenario": {
            #                         "confidentiality": "low",
            #                         "integrity": "low",
            #                         "availability": "low",
            #                         "probability": row[0]
            #                     }}
            #
            #                     # Sort other values
            #                     highest_values.append({
            #                         "confidentiality": "low",
            #                         "integrity": "low",
            #                         "availability": "low",
            #                         "probability": row[0]
            #                     })
            #                     highest_values.append({
            #                         "confidentiality": "low",
            #                         "integrity": "low",
            #                         "availability": "medium",
            #                         "probability": row[1]
            #                     })
            #                     highest_values.append({
            #                         "confidentiality": "low",
            #                         "integrity": "low",
            #                         "availability": "high",
            #                         "probability": row[2]
            #                     })
            #                     highest_values = sorted(highest_values, key=lambda k: k["probability"], reverse=True)
            #                 else:
            #                     # Check for each value if it is bigger than any saved value in that case save over the old one
            #                     # This way we get the bigger
            #                     # it is iterating over the rows values
            #                     # it2 is iterating over the saved values
            #                     for it in (0, 1, 2):
            #                         for it2 in (0, 1, 2):
            #                             if highest_values[it2]["probability"] < row[it]:
            #                                 print("VALUES TO  UPADTRE ARE---------------------")
            #                                 print(index)
            #                                 print(type(row))
            #                                 print(row)
            #                                 print(row.index[0][1])
            #                                 print(row.index[1][1])
            #                                 print(row.index[2][1])
            #
            #                                 # Create new object to add to the list of highest values
            #                                 to_add = {
            #                                     "confidentiality": "",
            #                                     "integrity": "",
            #                                     "availability": "",
            #                                     "probability": 0
            #                                 }
            #                                 if list(index)[0] == "0":
            #                                     # highest_values[it2]["confidentiality"] = "low"
            #                                     to_add["confidentiality"] = "low"
            #                                 elif list(index)[0] == "1":
            #                                     to_add["confidentiality"] = "medium"
            #                                 elif list(index)[0] == "2":
            #                                     to_add["confidentiality"] = "high"
            #                                 else:
            #                                     print("ERROR")
            #
            #                                 if list(index)[1] == "0":
            #                                     to_add["integrity"] = "low"
            #                                 elif list(index)[1] == "1":
            #                                     to_add["integrity"] = "medium"
            #                                 elif list(index)[1] == "2":
            #                                     to_add["integrity"] = "high"
            #                                 else:
            #                                     print("ERROR")
            #
            #                                 if row.index[it][1] == "0":
            #                                     to_add["availability"] = "low"
            #                                 elif row.index[it][1] == "1":
            #                                     to_add["availability"] = "medium"
            #                                 elif row.index[it][1] == "2":
            #                                     to_add["availability"] = "high"
            #                                 else:
            #                                     print("ERROR")
            #
            #                                 # highest_values[it2]["probability"] = row[it]
            #                                 to_add["probability"] = row[it]
            #
            #                                 # Pop last value and move the values to keep them in ascending order
            #                                 if it2 == 0:
            #                                     highest_values[2] = highest_values[1]
            #                                     highest_values[1] = highest_values[0]
            #                                     highest_values[0] = to_add
            #                                 elif it2 == 1:
            #                                     highest_values[2] = highest_values[1]
            #                                     highest_values[1] = to_add
            #                                 elif it2 == 2:
            #                                     highest_values[2] = to_add
            #                                 else:
            #                                     print("ERROR")
            #
            #
            #                                 break
            #
            #             elif temp_digit == "2":
            #                 if index == ("0"):
            #                     optimal_value = {"optimal_scenario": {
            #                         "monetary": "low",
            #                         "safety": "low",
            #                         "probability": row[0]
            #                     }}
            #
            #                     highest_values.append({
            #                         "monetary": "low",
            #                         "safety": "low",
            #                         "probability": row[0]
            #                     })
            #
            #
            #                     highest_values.append({
            #                         "monetary": "low",
            #                         "safety": "medium",
            #                         "probability": row[1]
            #                     })
            #
            #                     highest_values.append({
            #                         "monetary": "low",
            #                         "safety": "high",
            #                         "probability": row[2]
            #                     })
            #                     highest_values = sorted(highest_values, key=lambda k: k["probability"], reverse=True)
            #                 else:
            #                     # Check for each value if it is bigger than any saved value in that case save over the old one
            #                     # This way we get the bigger
            #                     # it is iterating over the rows values
            #                     # it2 is iterating over the saved values
            #                     for it in (0, 1, 2):
            #                         for it2 in (0, 1, 2):
            #                             if highest_values[it2]["probability"] < row[it]:
            #                                 print("VALUES TO  UPADTRE ARE---------------------")
            #                                 print(index)
            #                                 print(type(row))
            #                                 print(row)
            #                                 print(row.index[0][1])
            #                                 print(row.index[1][1])
            #                                 print(row.index[2][1])
            #
            #                                 # Create new object to add to the list of highest values
            #                                 to_add = {
            #                                     "monetary": "",
            #                                     "safety": "",
            #                                     "probability": 0
            #                                 }
            #
            #                                 if list(index)[0] == "0":
            #                                     # highest_values[it2]["confidentiality"] = "low"
            #                                     to_add["monetary"] = "low"
            #                                 elif list(index)[0] == "1":
            #                                     to_add["monetary"] = "medium"
            #                                 elif list(index)[0] == "2":
            #                                     to_add["monetary"] = "high"
            #                                 else:
            #                                     print("ERROR")
            #
            #                                 if row.index[it][1] == "0":
            #                                     to_add["safety"] = "low"
            #                                 elif row.index[it][1] == "1":
            #                                     to_add["safety"] = "medium"
            #                                 elif row.index[it][1] == "2":
            #                                     to_add["safety"] = "high"
            #                                 else:
            #                                     print("ERROR")
            #
            #                                 # highest_values[it2]["probability"] = row[it]
            #                                 to_add["probability"] = row[it]
            #
            #                                 # Pop last value and move the values to keep them in ascending order
            #                                 if it2 == 0:
            #                                     highest_values[2] = highest_values[1]
            #                                     highest_values[1] = highest_values[0]
            #                                     highest_values[0] = to_add
            #                                 elif it2 == 1:
            #                                     highest_values[2] = highest_values[1]
            #                                     highest_values[1] = to_add
            #                                 elif it2 == 2:
            #                                     highest_values[2] = to_add
            #                                 else:
            #                                     print("ERROR")
            #
            #                                 break
            #             else:
            #                 pass
            #             # print("ROW INDIVIDUALYL IS")
            #             # print(index)
            #             # print(row)
            #             # print(row[0])
            #             # print(row[1])
            #             # print(row[2])
            #
            #         most_likely_values = {"most_probable_scenarios": highest_values}
            #
            #         utility_inference = utility_inference + json.dumps(optimal_value) + "|" + json.dumps(most_likely_values) + "|"
            #     #     materialisations_set_values = str(temp_digit)+ "|" + str(value.values(0)) + "|"
            #     else:
            #         print("Ignore", temp_key)
            #
            #
            # # Check Objectives for alerts
            # objectives_to_check = objectives_inference.split("|")
            # print("-------------ALL ALERTS CHECK -----------------------")
            # print(objectives_to_check)
            # for alert in these_alerts:
            #     # If value is 0 then there is no alert to check
            #     # alert.alert_level is wether there is an alert and the value of the alert that its triggered
            #     if alert.alert_level != 0:
            #         # Accessing
            #         alert_it_to_check = 0
            #         objective_name = ""
            #         if alert.objective_fk == 1:
            #             alert_it_to_check = 0
            #             objective_name = "Confidentiality"
            #         elif alert.objective_fk == 2:
            #             alert_it_to_check = 4
            #             objective_name = "Integrity"
            #         elif alert.objective_fk == 3:
            #             alert_it_to_check = 8
            #             objective_name = "Availability"
            #         elif alert.objective_fk == 4:
            #             alert_it_to_check = 12
            #             objective_name = "Monetary"
            #         elif alert.objective_fk == 5:
            #             alert_it_to_check = 16
            #             objective_name = "Safety"
            #
            #         value_to_check_against =0
            #         if alert.alert_level == 1:
            #             value_to_check_against = 0.01
            #         elif alert.alert_level == 2:
            #             value_to_check_against = 0.1
            #         elif alert.alert_level == 3:
            #             value_to_check_against = 0.2
            #         elif alert.alert_level == 4:
            #             value_to_check_against = 0.4
            #         elif alert.alert_level == 5 :
            #             value_to_check_against = 0.7
            #
            #
            #         if json.loads(objectives_to_check[alert_it_to_check + alert.objective_level]) > value_to_check_against:
            #             to_add_alert = {
            #                 objective_name : {
            #                     "level" : alert.name,
            #                     "threshold" : value_to_check_against
            #                 }
            #             }
            #             alert_triggered = alert_triggered + json.dumps(to_add_alert) + "|"
            #         else:
            #             pass
            #
            #
            #
            #
            # # print(utility_inference)
            # first_risk_assessment_result = RepoRiskAssessmentReports(
            #     risk_assessment_id=this_risk_assessment.id,
            #     type="baseline",
            #     exposure_inference=exposure_inference,
            #     # responses_inference=utility_inference,  # TODO ADD Response inference
            #     materialisations_inference=materialisations_inference,
            #     consequences_inference=consequences_inference,
            #     services_inference=services_inference,
            #     impacts_inference=impacts_inference,
            #     objectives_inference=objectives_inference,
            #     utilities_inference=utility_inference,
            #     alerts_triggered =alert_triggered
            # )
            #
            # db.session.add(first_risk_assessment_result)
            # db.session.commit()
            send_risk_report(first_risk_assessment_result.id, asset_id, threat_id)
        flash('Assed "{}" Added Succesfully to risk assessment'.format(asset_id))
        return redirect("/repo/risk/assessment/" + threat_id + "/asset/" + asset_id + "/")
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
        # print(all_assets)
        for related_assessment in related_assessments:
            related_assets.append(related_assessment.asset)
            # print(related_assessment.asset)

        check_threat_exposure_exists = 0
        check_threat_materialisation_exists = 0
        check_asset_impact_exists = 0
        check_objectives_impact_exists = 0
        check_utility_conf_exists = 0
        check_asset_service_exists = 0
        asset_is_related = 0
        asset_threat_impact_count = 0
        objective_impact_count = 0
        utility_count = 0
        if int(asset_id) != -1:
            try:
                this_asset = RepoAsset.query.filter_by(id=asset_id).all()
            except SQLAlchemyError:
                return Response("SQLAlchemyError", 500)

            try:
                threat_exposure_relationship = RepoAssetRepoThreatRelationship.query.filter_by(repo_asset_id=asset_id,
                                                                                               repo_threat_id=threat_id)
            except SQLAlchemyError:
                return Response("SQLAlchemyError", 500)

            if threat_exposure_relationship.count() > 0:
                check_threat_exposure_exists = 1

            try:
                asset_threat_relationship = RepoRiskThreatAssetMaterialisation.query.filter_by(repo_asset_id=asset_id,
                                                                                               repo_threat_id=threat_id)
            except SQLAlchemyError:
                return Response("SQLAlchemyError", 500)

            if asset_threat_relationship.count() > 0:
                check_threat_materialisation_exists = 1

            try:
                asset_threat_impact_relationship = RepoAssetThreatConsequenceServiceImpactRelationship.query.filter_by(
                    repo_asset_id=asset_id,
                    repo_threat_id=threat_id).group_by(
                    RepoAssetThreatConsequenceServiceImpactRelationship.repo_impact_id)
            except SQLAlchemyError:
                return Response("SQLAlchemyError", 500)

            # print("GROUP BY COUNT IS--", asset_threat_impact_relationship.count())
            asset_threat_impact_count = asset_threat_impact_relationship.count()
            if asset_threat_impact_count >= 6:
                check_asset_impact_exists = 1

            try:
                objective_impact_relationship = RepoObjectiveImpactRelationship.query.group_by(
                    RepoObjectiveImpactRelationship.repo_objective_id)
            except SQLAlchemyError:
                return Response("SQLAlchemyError", 500)

            objective_impact_count = objective_impact_relationship.count()
            if objective_impact_count >= 5:
                check_objectives_impact_exists = 1

            try:
                utility_conf = RepoUtilityObjectiveRelationship.query.group_by(
                    RepoUtilityObjectiveRelationship.repo_utility_id)
            except SQLAlchemyError:
                return Response("SQLAlchemyError", 500)

            utility_count = utility_conf.count()
            if utility_count >= 2:
                check_utility_conf_exists = 1

            # Check if asset has been assigned any service
            # print("GROUP BY COUNT IS--", this_asset[0].services)

            if len(this_asset[0].services) > 0:
                check_asset_service_exists = 1
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

        if int(asset_id) != -1:
            for related_asset_each in related_assets:
                if this_asset[0] == related_asset_each:
                    asset_is_related = 1

        # print("---ASET VALUEs--")
        # print(related_assets)
        # print(asset_is_related)
        # array_objective_calculation = [[{}], [{}]                                       ]
        # for

        return render_template("templates_dashboard/repo_risk_assessment.html", repo_threats=repo_threats,
                               threat_id=threat_id, asset_id=asset_id,
                               this_threat=this_threat,
                               related_assets=related_assets,
                               unrelated_assets=unrelated_assets,
                               this_asset=this_asset,
                               check_threat_exposure_exists=check_threat_exposure_exists,
                               check_threat_materialisation_exists=check_threat_materialisation_exists,
                               check_asset_impact_exists=check_asset_impact_exists,
                               check_objectives_impact_exists=check_objectives_impact_exists,
                               check_utility_conf_exists=check_utility_conf_exists,
                               check_asset_service_exists=check_asset_service_exists,
                               asset_is_related=asset_is_related,
                               asset_threat_impact_count=asset_threat_impact_count,
                               objective_impact_count=objective_impact_count,
                               utility_count=utility_count
                               )


@app.route('/repo/risk/reports/', methods=['GET', 'POST'])
def view_repo_risk_reports():
    if request.method == 'POST':
        # flash('Service "{}" Added Succesfully'.format(new_service_form.name.data))
        return redirect("/repo/risk/reports/")
    else:
        try:
            repo_reports = RepoRiskAssessmentReports.query.all()
        except SQLAlchemyError:
            return Response("SQLAlchemyError", 500)
        # print("------------------------------")
        # print(repo_actors, flush=True)
        #
        # print(repo_actors[0].__table__.columns._data.keys(), flush=True)

        json_reports = convert_database_items_to_json_table(repo_reports)
        json_detailed_reports = []
        custom_it = 0
        json_detailed_report_to_add = {}
        for each_report in repo_reports:
            print("Example ARE --------")
            print(json_reports[custom_it])
            #  Add basic info to dashboard
            this_risk_assessment = each_report.risk_assessment
            json_reports[custom_it]["asset_name"] = this_risk_assessment.asset.name
            json_reports[custom_it]["asset_ip"] = this_risk_assessment.asset.ip
            json_reports[custom_it]["threat_name"] = this_risk_assessment.threat.name
            json_reports[custom_it]["date_time"] = json_reports[custom_it]["date_time"].strftime("%m/%d/%Y, %H:%M:%S")
            # print(each_report)

            # Create detailed report jsons
            json_detailed_report_to_add = {}
            json_detailed_report_to_add["type"] = each_report.type
            if each_report.date_time is None:
                json_detailed_report_to_add["date_time"] = None
            else:
                json_detailed_report_to_add["date_time"] = each_report.date_time.strftime("%m/%d/%Y, %H:%M:%S")

            # Get cvalues from database
            materialisations_list = each_report.materialisations_inference.split("|")

            exposure_inference_list = each_report.exposure_inference.split("|")
            consequence_inference_list = each_report.consequences_inference.split("|")
            impact_inference_list = each_report.impacts_inference.split("|")
            services_inference_list = each_report.services_inference.split("|")
            objectives_inference_list = each_report.objectives_inference.split("|")
            utility_inference_list = each_report.utilities_inference.split("|")
            alerts_triggered = each_report.alerts_triggered.split("|")

            materialisations_list.pop()
            exposure_inference_list.pop()
            consequence_inference_list.pop()
            impact_inference_list.pop()
            services_inference_list.pop()
            objectives_inference_list.pop()
            utility_inference_list.pop()
            alerts_triggered.pop()
            print(materialisations_list)
            json_detailed_report_to_add["exposure"] = []
            json_detailed_report_to_add["materialisations"] = []
            json_detailed_report_to_add["consequences"] = []
            json_detailed_report_to_add["services"] = []
            json_detailed_report_to_add["impacts"] = []
            json_detailed_report_to_add["objectives"] = []
            json_detailed_report_to_add["utilities"] = []
            json_detailed_report_to_add["alerts"] = []

            # Exposure
            json_detailed_report_to_add["exposure"].append(
                {"name": exposure_inference_list[0], "occurs": exposure_inference_list[2],
                 "Nothing": exposure_inference_list[1]}
            )

            # Materialisation
            for custom_it_mat in range(0, len(materialisations_list), 3):
                this_mat_name = RepoMaterialisation.query.filter_by(
                    id=materialisations_list[custom_it_mat]).first().name
                json_detailed_report_to_add["materialisations"].append(
                    {"name": this_mat_name, "occurs": materialisations_list[custom_it_mat + 2],
                     "Nothing": materialisations_list[custom_it_mat + 1]})

            # Consequence
            for custom_it_mat in range(0, len(consequence_inference_list), 3):
                # this_cons_name = RepoMaterialisation.query.filter_by(
                #     id=consequence_inference_list[custom_it_mat]).first().name
                json_detailed_report_to_add["consequences"].append(
                    {"name": consequence_inference_list[custom_it_mat], "occurs": consequence_inference_list[custom_it_mat + 2],
                     "Nothing": consequence_inference_list[custom_it_mat + 1]})

            # Service
            for custom_it_mat in range(0, len(services_inference_list), 3):
                # this_cons_name = RepoMaterialisation.query.filter_by(
                #     id=consequence_inference_list[custom_it_mat]).first().name
                json_detailed_report_to_add["services"].append(
                    {"name": services_inference_list[custom_it_mat],
                     "Working": services_inference_list[custom_it_mat + 2],
                     "Not working": services_inference_list[custom_it_mat + 1]})

            # Impact
            for custom_it_mat in range(0, len(impact_inference_list), 4):
                # this_cons_name = RepoMaterialisation.query.filter_by(
                #     id=consequence_inference_list[custom_it_mat]).first().name
                json_detailed_report_to_add["impacts"].append(
                    {"name": impact_inference_list[custom_it_mat],
                     "low": impact_inference_list[custom_it_mat + 1],
                     "medium": impact_inference_list[custom_it_mat + 2],
                     "high": impact_inference_list[custom_it_mat + 3]
                     }
                )

            # Objective
            for custom_it_mat in range(0, len(objectives_inference_list), 4):
                # this_cons_name = RepoMaterialisation.query.filter_by(
                #     id=consequence_inference_list[custom_it_mat]).first().name
                json_detailed_report_to_add["objectives"].append(
                    {"name": objectives_inference_list[custom_it_mat],
                     "low": objectives_inference_list[custom_it_mat + 1],
                     "medium": objectives_inference_list[custom_it_mat + 2],
                     "high": objectives_inference_list[custom_it_mat + 3]
                     }
                )

            # # Utilities
            # for custom_it_mat in range(0, len(objectives_inference_list), 4):
            #     # this_cons_name = RepoMaterialisation.query.filter_by(
            #     #     id=consequence_inference_list[custom_it_mat]).first().name
            #     json_detailed_report_to_add["objectives"].append(
            #         {"name": objectives_inference_list[custom_it_mat],
            #          "low": objectives_inference_list[custom_it_mat + 1],
            #          "medium": objectives_inference_list[custom_it_mat + 2],
            #          "high": objectives_inference_list[custom_it_mat + 3]
            #          }
            #     )
            #
            # # Alerts
            # for custom_it_mat in range(0, len(objectives_inference_list), 4):
            #     # this_cons_name = RepoMaterialisation.query.filter_by(
            #     #     id=consequence_inference_list[custom_it_mat]).first().name
            #     json_detailed_report_to_add["objectives"].append(
            #         {"name": objectives_inference_list[custom_it_mat],
            #          "low": objectives_inference_list[custom_it_mat + 1],
            #          "medium": objectives_inference_list[custom_it_mat + 2],
            #          "high": objectives_inference_list[custom_it_mat + 3]
            #          }
            #     )

            json_reports[custom_it]["detailed"] = json_detailed_report_to_add
            custom_it = custom_it + 1

            # print("--=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-")
            # print(json_reports)
            # to_test_report = json.dumps(json_reports)
            # print(to_test_report)
            # {
            #     "type": "Initial",
            #     "dateTime": "12/04/2021 12:00:00",
            #     "threat": [{"name": "Ransomware"}],
            #     "asset": [{"name": "Asset 1"}],
            #     "vulnerabilities": [{"name": "Asset 1"}],
            #     "response": [{}],
            #     "confidentiality": [{}],
            #     "integrity": [{}],
            #     "availability": [{}],
            #     "monetary": [{}],
            #     "safety": [{}],
            #     "CIA Utility": [{}],
            #     "Evaluation Utility": [{}],
            #
            # }

        print(json_reports)
        json_reports = json.dumps(json_reports)
        # json_reports = json.dumps(json_reports)

        # print("Proper is  --------")
        # print(repo_reports)
        new_service_form = FormAddRepoService()
        return render_template("templates_asset_repo/view_repo_reports.html", repo_reports=json_reports,
                               json_detailed_report_to_add=json_detailed_report_to_add,
                               new_service_form=new_service_form)
