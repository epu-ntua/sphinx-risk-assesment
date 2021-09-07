from flask import render_template, request, redirect, jsonify, Response, flash
from multiprocessing import Process
from app.producer import *
from app.globals import *
from app.utils import *
from app.forms import *
from app import app
from app.utils.utils_database import *
from sqlalchemy.exc import SQLAlchemyError
from copy import deepcopy
from deepdiff import DeepDiff


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
        if existing_exposure_item.count() is not 0:
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

            if existing_exposure_item.count() is 0:
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
        return render_template("templates_risk_assessment/repo_risk_configuration_threat_asset.html",
                               threat_id=threat_id, asset_id=asset_id,
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
                                                                'materialisation_id': inner_joined.repo_consequence.materialisation_id
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

        return render_template("templates_risk_assessment/repo_risk_configuration_impacts_risk.html",
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
            joined = db.session.query(RepoObjectiveImpactRelationship, RepoObjectiveImpactRelationshipImpactManyToMany) \
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
                        repo_impact_state=int(single_impact["state"])
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

        existing_values = db.session.query(RepoObjectiveImpactRelationship,
                                           RepoObjectiveImpactRelationshipImpactManyToMany) \
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

        return render_template("templates_risk_assessment/repo_risk_configuration_objectives_risk.html",
                               repo_objectives=repo_objectives,
                               objective_id=objective_id,
                               this_objective=this_objective, array_objective_calculation=array_impact_calculation)


@app.route('/repo/risk/configuration/utility/<utility_id>/', methods=['GET', 'POST'])
def repo_risk_configuration_utility_risk(utility_id=1):
    if request.method == 'POST':
        # for user_input in request.form:
        for user_input in request.form:
            print(user_input)
            deconstructedId = user_input.split("|")
            deconstructedId.pop(0)
            print("deconstructedId Mat")
            print(deconstructedId)
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
                to_add_low = {"id": repo_objective_related.id, "name": repo_objective_related.name, "state": "low",
                              "value": "50"}
                to_add_med = {"id": repo_objective_related.id, "name": repo_objective_related.name, "state": "med",
                              "value": "50"}
                to_add_high = {"id": repo_objective_related.id, "name": repo_objective_related.name, "state": "high",
                               "value": "50"}

                array_utility_calculation.append([to_add_low])
                array_utility_calculation.append([to_add_med])
                array_utility_calculation.append([to_add_high])
            else:
                temp_array_utility_calculation_1 = deepcopy(array_utility_calculation)
                temp_array_utility_calculation_2 = deepcopy(array_utility_calculation)

                for to_be_added in array_utility_calculation:
                    to_be_added.append(
                        {"id": repo_objective_related.id, "name": repo_objective_related.name, "state": "low",
                         "value": "50"})

                for to_be_added in temp_array_utility_calculation_1:
                    to_be_added.append(
                        {"id": repo_objective_related.id, "name": repo_objective_related.name, "state": "med",
                         "value": "50"})

                for to_be_added in temp_array_utility_calculation_2:
                    to_be_added.append(
                        {"id": repo_objective_related.id, "name": repo_objective_related.name, "state": "high",
                         "value": "50"})

                array_utility_calculation = array_utility_calculation + temp_array_utility_calculation_1 + temp_array_utility_calculation_2

        print("TEST")
        for two in array_utility_calculation:
            print(two)

        # existing_values = db.session.query(RepoUtilityObjectiveRelationship,
        #                                    RepoUtilityObjectiveRelationshipManyToMany).join(
        #     RepoUtilityObjectiveRelationshipManyToMany).filter(
        #     RepoUtilityObjectiveRelationship.repo_utility_id == utility_id,
        # )

        existing_values = RepoUtilityObjectiveRelationship.query
        if existing_values.count() > 0:
            # for to_edit in array_utility_calculation:
            #     value_to_edit = db.session.query(RepoUtilityObjectiveRelationship,
            #                                      RepoUtilityObjectiveRelationshipManyToMany).join(
            #         RepoUtilityObjectiveRelationshipManyToMany).filter(
            #         RepoUtilityObjectiveRelationship.repo_utility_id == utility_id,
            #     ).all()
            # for value in value_to_edit:
            #     print(value)

            # This is for testing it isnt exactly right even if it works
            # THis arranges value in a dumb way
            joined = existing_values.all()
            it = 0
            for to_edit in joined:
                print("NEW TEST")
                print(to_edit)
                print(array_utility_calculation[it])
                array_utility_calculation[it]["value"] = to_edit.utility_value
            # for utility_calculation in array_utility_calculation:
            #     try:
            #         repo_utlity_objective_entries = RepoUtilityObjectiveRelationship.query.filter(
            #             RepoObjective.utilities.any(id=int(utility_id))).all()
            #     except SQLAlchemyError:
            #         return Response("SQLAlchemyError", 500)

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

        if this_risk_assessment.count() == 0:
            this_risk_assessment = RepoRiskAssessment(repo_threat_id=threat_id, repo_asset_id=asset_id)
            db.session.add(this_risk_assessment)
            db.session.commit()

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

        return render_template("templates_dashboard/repo_risk_assessment.html", repo_threats=repo_threats,
                               threat_id=threat_id, asset_id=asset_id,
                               this_threat=this_threat,
                               related_assets=related_assets,
                               unrelated_assets=unrelated_assets,
                               this_asset=this_asset)


@app.route('/repo/risk/reports/', methods=['GET', 'POST'])
def view_repo_risk_reports():
    if request.method == 'POST':
        # flash('Service "{}" Added Succesfully'.format(new_service_form.name.data))
        return redirect("/repo/risk/reports/")
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
        repo_reports = [{"id": 1, "datetime": "12/04/2021 12:00:00", "threat": "Ransomware", "assetName": "Asset 1",
                         "assetIp": "192.168.1.1", "type": "Initial"},
                        {"id": 2, "datetime": "13/04/2021 12:00:00", "threat": "Hijacking", "assetName": "Asset 1",
                         "assetIp": "192.168.1.1", "type": "Initial"},
                        {"id": 3, "datetime": "14/04/2021 12:00:00", "threat": "Ransomware", "assetName": "Asset 1",
                         "assetIp": "192.168.1.1", "type": "Incident"},
                        {"id": 4, "datetime": "21/04/2021 12:00:00", "threat": "Hijacking", "assetName": "Asset 1",
                         "assetIp": "192.168.1.1", "type": "Configuration Change"},
                        ]
        print("Example ARE --------")
        print(json_services)
        print("Proper is  --------")
        print(repo_reports)
        new_service_form = FormAddRepoService()
        return render_template("templates_asset_repo/view_repo_reports.html", repo_reports=repo_reports,
                               new_service_form=new_service_form)
