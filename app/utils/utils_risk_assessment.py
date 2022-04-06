from app.models import *
import json
import os
import pyAgrum as gum
import pycid
from sqlalchemy.exc import SQLAlchemyError
from copy import deepcopy
from app.utils.utils_risk_profiles import get_threat_exposure_value
from flask import Response
# Function to calculate the risk exposure with range 0.0 -1.0, needs updating currently
# OBSOLETE WILL BE REMOVED AT NEXT UPDATE
# Replaced by get_threat_exposure_value(asset_id, threat_id)
def calculate_exposure(skill, motive, source, actor, opportunity):
    # print("---------Exposure Values---------")
    # print(skill)
    # print(motive)
    # print(source)
    # print(actor)
    # print(opportunity)
    exposure = (skill + motive + source + actor + opportunity) / 5
    exposure = exposure / 100
    return exposure


def risk_assessment_save_report(threat_id, asset_id, risk_assessment_result, report_type):
    try:
        this_risk_assessment = RepoRiskAssessment.query.filter_by(repo_threat_id=threat_id, repo_asset_id=asset_id).first()
    except SQLAlchemyError:
        return Response("SQLAlchemyError", 500)

    try:
        these_alerts = RepoObjectivesOptions.query.all()
    except SQLAlchemyError:
        return Response('SQLAlchemyError', 500)

    exposure_inference = ""
    materialisations_inference = ""
    consequences_inference = ""
    services_inference = ""
    impacts_inference = ""
    objectives_inference = ""
    utility_inference = ""
    alert_triggered = ""

    # print("-------------- All ITEMS ARE ------------------")
    # print(risk_assessment_result.items())
    for key, value in risk_assessment_result.items():
        # print("KEY IS")
        # print(key)
        temp_key = "".join(i for i in key if not i.isdigit())
        temp_digit = "".join(i for i in key if i.isdigit())

        if temp_key == "te":
            exposure_inference = exposure_inference + str(temp_digit) + "|" + str(
                value.values[0]) + "|" + str(
                value.values[1]) + "|"
        elif temp_key == "mat":
            materialisations_inference = materialisations_inference + str(temp_digit) + "|" + str(
                value.values[0]) + "|" + str(
                value.values[1]) + "|"
        elif temp_key == "con":
            consequences_inference = consequences_inference + str(temp_digit) + "|" + str(
                value.values[0]) + "|" + str(
                value.values[1]) + "|"
        elif temp_key == "serv":
            services_inference = services_inference + str(temp_digit) + "|" + str(
                value.values[0]) + "|" + str(
                value.values[1]) + "|"
        elif temp_key == "imp":
            impacts_inference = impacts_inference + str(temp_digit) + "|" + str(value.values[0]) + "|" + str(
                value.values[1]) + "|" + str(value.values[2]) + "|"
        elif temp_key == "obj":
            objectives_inference = objectives_inference + str(temp_digit) + "|" + str(
                value.values[0]) + "|" + str(
                value.values[1]) + "|" + str(value.values[2]) + "|"
        elif temp_key == "util":
            # print("[[[[[[[[[[[[[[[[[[[]]]]]]]]]]]]]]]]]]]")
            # print(value)
            # print("}}}}}}}}}}}}}}}}}}}{{{{{{{{{{{{{{{{{{{")
            optimal_value = {}
            highest_values = []
            for index, row in value.iterrows():
                # print(type(temp_digit))
                if temp_digit == "1":
                    if index == ("0", "0"):
                        # print(";;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;")
                        #  Optimal values is always the same 0, 0, 0,
                        optimal_value = {"optimal_scenario": {
                            "confidentiality": "low",
                            "integrity": "low",
                            "availability": "low",
                            "probability": row[0]
                        }}

                        # Sort other values
                        highest_values.append({
                            "confidentiality": "low",
                            "integrity": "low",
                            "availability": "low",
                            "probability": row[0]
                        })
                        highest_values.append({
                            "confidentiality": "low",
                            "integrity": "low",
                            "availability": "medium",
                            "probability": row[1]
                        })
                        highest_values.append({
                            "confidentiality": "low",
                            "integrity": "low",
                            "availability": "high",
                            "probability": row[2]
                        })
                        highest_values = sorted(highest_values, key=lambda k: k["probability"], reverse=True)
                    else:
                        # Check for each value if it is bigger than any saved value in that case save over the old one
                        # This way we get the bigger
                        # it is iterating over the rows values
                        # it2 is iterating over the saved values
                        for it in (0, 1, 2):
                            for it2 in (0, 1, 2):
                                if highest_values[it2]["probability"] < row[it]:
                                    # print("VALUES TO  UPADTRE ARE---------------------")
                                    # print(index)
                                    # print(type(row))
                                    # print(row)
                                    # print(row.index[0][1])
                                    # print(row.index[1][1])
                                    # print(row.index[2][1])

                                    # Create new object to add to the list of highest values
                                    to_add = {
                                        "confidentiality": "",
                                        "integrity": "",
                                        "availability": "",
                                        "probability": 0
                                    }
                                    if list(index)[0] == "0":
                                        # highest_values[it2]["confidentiality"] = "low"
                                        to_add["confidentiality"] = "low"
                                    elif list(index)[0] == "1":
                                        to_add["confidentiality"] = "medium"
                                    elif list(index)[0] == "2":
                                        to_add["confidentiality"] = "high"
                                    else:
                                        print("ERROR")

                                    if list(index)[1] == "0":
                                        to_add["integrity"] = "low"
                                    elif list(index)[1] == "1":
                                        to_add["integrity"] = "medium"
                                    elif list(index)[1] == "2":
                                        to_add["integrity"] = "high"
                                    else:
                                        print("ERROR")

                                    if row.index[it][1] == "0":
                                        to_add["availability"] = "low"
                                    elif row.index[it][1] == "1":
                                        to_add["availability"] = "medium"
                                    elif row.index[it][1] == "2":
                                        to_add["availability"] = "high"
                                    else:
                                        print("ERROR")

                                    # highest_values[it2]["probability"] = row[it]
                                    to_add["probability"] = row[it]

                                    # Pop last value and move the values to keep them in ascending order
                                    if it2 == 0:
                                        highest_values[2] = highest_values[1]
                                        highest_values[1] = highest_values[0]
                                        highest_values[0] = to_add
                                    elif it2 == 1:
                                        highest_values[2] = highest_values[1]
                                        highest_values[1] = to_add
                                    elif it2 == 2:
                                        highest_values[2] = to_add
                                    else:
                                        print("ERROR")

                                    break

                elif temp_digit == "2":
                    if index == ("0"):
                        optimal_value = {"optimal_scenario": {
                            "monetary": "low",
                            "safety": "low",
                            "probability": row[0]
                        }}

                        highest_values.append({
                            "monetary": "low",
                            "safety": "low",
                            "probability": row[0]
                        })

                        highest_values.append({
                            "monetary": "low",
                            "safety": "medium",
                            "probability": row[1]
                        })

                        highest_values.append({
                            "monetary": "low",
                            "safety": "high",
                            "probability": row[2]
                        })
                        highest_values = sorted(highest_values, key=lambda k: k["probability"], reverse=True)
                    else:
                        # Check for each value if it is bigger than any saved value in that case save over the old one
                        # This way we get the bigger
                        # it is iterating over the rows values
                        # it2 is iterating over the saved values
                        for it in (0, 1, 2):
                            for it2 in (0, 1, 2):
                                if highest_values[it2]["probability"] < row[it]:
                                    # print("VALUES TO  UPADTRE ARE---------------------")
                                    # print(index)
                                    # print(type(row))
                                    # print(row)
                                    # print(row.index[0][1])
                                    # print(row.index[1][1])
                                    # print(row.index[2][1])

                                    # Create new object to add to the list of highest values
                                    to_add = {
                                        "monetary": "",
                                        "safety": "",
                                        "probability": 0
                                    }

                                    if list(index)[0] == "0":
                                        # highest_values[it2]["confidentiality"] = "low"
                                        to_add["monetary"] = "low"
                                    elif list(index)[0] == "1":
                                        to_add["monetary"] = "medium"
                                    elif list(index)[0] == "2":
                                        to_add["monetary"] = "high"
                                    else:
                                        print("ERROR")

                                    if row.index[it][1] == "0":
                                        to_add["safety"] = "low"
                                    elif row.index[it][1] == "1":
                                        to_add["safety"] = "medium"
                                    elif row.index[it][1] == "2":
                                        to_add["safety"] = "high"
                                    else:
                                        print("ERROR")

                                    # highest_values[it2]["probability"] = row[it]
                                    to_add["probability"] = row[it]

                                    # Pop last value and move the values to keep them in ascending order
                                    if it2 == 0:
                                        highest_values[2] = highest_values[1]
                                        highest_values[1] = highest_values[0]
                                        highest_values[0] = to_add
                                    elif it2 == 1:
                                        highest_values[2] = highest_values[1]
                                        highest_values[1] = to_add
                                    elif it2 == 2:
                                        highest_values[2] = to_add
                                    else:
                                        print("ERROR")

                                    break
                else:
                    pass
                # print("ROW INDIVIDUALYL IS")
                # print(index)
                # print(row)
                # print(row[0])
                # print(row[1])
                # print(row[2])

            most_likely_values = {"most_probable_scenarios": highest_values}

            utility_inference = utility_inference + json.dumps(optimal_value) + "|" + json.dumps(
                most_likely_values) + "|"
        #     materialisations_set_values = str(temp_digit)+ "|" + str(value.values(0)) + "|"
        else:
            print("Ignore", temp_key)

    # Check Objectives for alerts
    objectives_to_check = objectives_inference.split("|")
    # print("-------------ALL ALERTS CHECK -----------------------")
    # print(objectives_to_check)
    for alert in these_alerts:
        # If value is 0 then there is no alert to check
        # alert.alert_level is wether there is an alert and the value of the alert that its triggered
        if alert.alert_level != 0:
            # Accessing
            alert_it_to_check = 0
            objective_name = ""
            if alert.objective_fk == 1:
                alert_it_to_check = 0
                objective_name = "Confidentiality"
            elif alert.objective_fk == 2:
                alert_it_to_check = 4
                objective_name = "Integrity"
            elif alert.objective_fk == 3:
                alert_it_to_check = 8
                objective_name = "Availability"
            elif alert.objective_fk == 4:
                alert_it_to_check = 12
                objective_name = "Monetary"
            elif alert.objective_fk == 5:
                alert_it_to_check = 16
                objective_name = "Safety"

            value_to_check_against = 0
            if alert.alert_level == 1:
                value_to_check_against = 0.01
            elif alert.alert_level == 2:
                value_to_check_against = 0.1
            elif alert.alert_level == 3:
                value_to_check_against = 0.2
            elif alert.alert_level == 4:
                value_to_check_against = 0.4
            elif alert.alert_level == 5:
                value_to_check_against = 0.7

            if json.loads(objectives_to_check[alert_it_to_check + alert.objective_level]) > value_to_check_against:
                to_add_alert = {
                    objective_name: {
                        "level": alert.name,
                        "threshold": value_to_check_against
                    }
                }
                alert_triggered = alert_triggered + json.dumps(to_add_alert) + "|"
            else:
                pass

    # print(utility_inference)
    first_risk_assessment_result = RepoRiskAssessmentReports(
        risk_assessment_id=this_risk_assessment.id,
        type=report_type,
        exposure_inference=exposure_inference,
        # responses_inference=utility_inference,  # TODO ADD Response inference
        materialisations_inference=materialisations_inference,
        consequences_inference=consequences_inference,
        services_inference=services_inference,
        impacts_inference=impacts_inference,
        objectives_inference=objectives_inference,
        utilities_inference=utility_inference,
        alerts_triggered=alert_triggered
    )

    db.session.add(first_risk_assessment_result)
    db.session.commit()
    return first_risk_assessment_result

def start_risk_assessment(threat_id, asset_id):
    diag = gum.InfluenceDiagram()
    try:
        this_risk_assessment = RepoRiskAssessment.query.filter_by(repo_threat_id=threat_id,
                                                                  repo_asset_id=asset_id).first()
    except SQLAlchemyError:
        return "SQLAlchemyError"
    # Node creation
    this_asset = this_risk_assessment.asset
    this_threat = this_risk_assessment.threat

    # Node creation threat exposure
    exposureNodeId = "te" + str(this_threat.id)
    diag.add(gum.LabelizedVariable(exposureNodeId, this_threat.name, 2))

    # Node creation responses
    try:
        these_responses = RepoResponse.query.filter_by(threat_id=threat_id).all()
    except SQLAlchemyError:
        return "SQLAlchemyError"

    nodeId = "re"
    diag.addDecisionNode(gum.LabelizedVariable(nodeId, "Responses", len(these_responses)))

    # Node creation materialisations
    try:
        these_materialisations = RepoMaterialisation.query.filter_by(threat_id=threat_id).all()
    except SQLAlchemyError:
        return "SQLAlchemyError"

    for materialisation in these_materialisations:
        nodeId = "mat" + str(materialisation.id)
        diag.add(gum.LabelizedVariable(nodeId, materialisation.name, 2))

    # Node creation consequences
    try:
        these_consequences = RepoConsequence.query.filter_by(threat_id=threat_id).all()
    except SQLAlchemyError:
        return "SQLAlchemyError"

    for consequence in these_consequences:
        nodeId = "con" + str(consequence.id)
        diag.add(gum.LabelizedVariable(nodeId, consequence.name, 2))

    # Node creation assets
    try:
        these_services = RepoService.query.filter(RepoService.assets.any(id=asset_id)).all()
    except SQLAlchemyError:
        return "SQLAlchemyError"

    # Node creation services
    for service in these_services:
        nodeId = "serv" + str(service.id)
        diag.add(gum.LabelizedVariable(nodeId, service.name, 2))

    # Node creation impacts
    try:
        these_impacts = RepoImpact.query.all()
    except SQLAlchemyError:
        return "SQLAlchemyError"

    for impact in these_impacts:
        nodeId = "imp" + str(impact.id)
        diag.add(gum.LabelizedVariable(nodeId, impact.name, 3))

    # Node creation objectives
    try:
        these_objectives = RepoObjective.query.all()
    except SQLAlchemyError:
        return "SQLAlchemyError"

    for objective in these_objectives:
        nodeId = "obj" + str(objective.id)
        diag.add(gum.LabelizedVariable(nodeId, objective.name, 3))

    # Node creation utilities
    try:
        these_utils = RepoUtility.query.all()
    except SQLAlchemyError:
        return "SQLAlchemyError"

    for utility in these_utils:
        # print("Util" + str(utility.name))
        nodeId = "util" + str(utility.id)
        diag.addUtilityNode(gum.LabelizedVariable(nodeId, str(utility.name), 1))

    # Node Linking
    # Link Exposure and response to materialisation
    for materialisation in these_materialisations:
        nodeId = "mat" + str(materialisation.id)
        diag.addArc(exposureNodeId, nodeId)

    # for response in these_responses:
    for materialisation in these_materialisations:
        nodeId = "re"
        nodeMatId = "mat" + str(materialisation.id)
        diag.addArc(nodeId, nodeMatId)

    # Link Mat and Re to Cons
    for consequence in these_consequences:
        nodeConsId = "con" + str(consequence.id)
        nodeMatId = "mat" + str(consequence.materialisation_id)
        nodeReId = "re"

        diag.addArc(nodeReId, nodeConsId)
        diag.addArc(nodeMatId, nodeConsId)

    # Link cons and service in impacts
    for service in these_services:
        nodeServId = "serv" + str(service.id)
        try:
            these_related_impacts = RepoImpact.query.filter(RepoImpact.services.any(id=service.id)).all()
        except SQLAlchemyError:
            return "SQLAlchemyError"

        for impact in these_related_impacts:
            nodeImpactId = "imp" + str(impact.id)
            diag.addArc(nodeServId, nodeImpactId)
    #
    for consequence in these_consequences:
        nodeConsId = "con" + str(consequence.id)
        try:
            these_related_impacts = RepoImpact.query.filter(RepoImpact.consequences.any(id=consequence.id)).all()
        except SQLAlchemyError:
            return "SQLAlchemyError"

        # for service in these_services:
        #     nodeServId = "serv" + str(service.id)
        #     diag.addArc(nodeConsId, nodeServId)

            # ie.addEvidence(nodeServId, 0)

        for impact in these_related_impacts:
            nodeImpactId = "imp" + str(impact.id)
            diag.addArc(nodeConsId, nodeImpactId)

    # Link objective to imp
    for impact in these_impacts:
        nodeImpactId = "imp" + str(impact.id)
        try:
            these_related_objectives = RepoObjective.query.filter(RepoObjective.impacts.any(id=impact.id))
        except SQLAlchemyError:
            return "SQLAlchemyError"

        for objective in these_related_objectives:
            nodeObjectiveId = "obj" + str(objective.id)
            diag.addArc(nodeImpactId, nodeObjectiveId)

    # Link Utility to Objectives
    for objective in these_objectives:
        nodeObjectiveId = "obj" + str(objective.id)
        try:
            these_related_utilities = RepoUtility.query.filter(RepoUtility.objectives.any(id=objective.id))
        except SQLAlchemyError:
            return "SQLAlchemyError"

        for utility in these_related_utilities:
            nodeUtilId = "util" + str(utility.id)
            diag.addArc(nodeObjectiveId, nodeUtilId)

    # Node Value Filling
    # Exposure Node Values
    try:
        this_exposure = RepoAssetRepoThreatRelationship.query.filter_by(repo_threat_id=threat_id, repo_asset_id=asset_id).first()
    except SQLAlchemyError:
        return "SQLAlchemyError"

    exposure = get_threat_exposure_value(asset_id, threat_id)
    # exposure = calculate_exposure(this_exposure.risk_skill_level, this_exposure.risk_motive, this_exposure.risk_source,
    #                               this_exposure.risk_actor, this_exposure.risk_opportunity)

    # print("-------------------------------------- EXPOSURE IS ----------------------------------------------", exposure)
    diag.cpt(exposureNodeId).fillWith([1 - exposure, exposure])
    # diag.cpt("te1").fillWith([1, 0])

    # Materialisation Node Values
    for materialisation in these_materialisations:
        # print("----- Matinfo ------")
        # print(nodeImpactId)
        # print(nodeObjectiveId)
        nodeMatId = "mat" + str(materialisation.id)
        nodeReId = "re"
        try:
            these_materialisation_values = RepoRiskThreatAssetMaterialisation.query.filter_by(repo_asset_id=asset_id,
                                                                                              repo_threat_id=threat_id,
                                                                                              repo_materialisation_id=materialisation.id).all()
        except SQLAlchemyError:
            return "SQLAlchemyError"
        for node_value in these_materialisation_values:
            if node_value.threat_occurrence is True:
                occurance_bool_num = 1
            else:
                occurance_bool_num = 0

            for it in range(0, len(these_responses), 1):
                if these_responses[it].id == node_value.repo_response_id:
                    response_bool_num = it

            # if node_value.repo_response_id % 2 == 0:
            #     response_bool_num = 1
            # else:
            #     response_bool_num = 0

            diag.cpt(nodeMatId)[{exposureNodeId: occurance_bool_num, nodeReId: response_bool_num}] = [
                1 - (node_value.prob / 100),
                node_value.prob / 100]

        # print(these_materialisation_values)

    # Consequence Node Values
    for consequence in these_consequences:
        # print("----- Matinfo ------")
        # print(nodeImpactId)
        # print(nodeObjectiveId)
        nodeConsId = "con" + str(consequence.id)
        nodeReId = "re"
        try:
            these_cosnequence_values = RepoRiskThreatAssetConsequence.query.filter_by(repo_asset_id=asset_id,
                                                                                      repo_threat_id=threat_id,
                                                                                      repo_consequence_id=consequence.id).all()
        except SQLAlchemyError:
            return "SQLAlchemyError"

        for node_value in these_cosnequence_values:
            if node_value.threat_occurrence is True:
                occurance_bool_num = 1
            else:
                occurance_bool_num = 0

            # response shouldnt work like that this needs a bit of a rework
            if node_value.repo_response_id % 2 == 0:
                response_bool_num = 1
            else:
                response_bool_num = 0

            for it in range(0, len(these_responses), 1):
                if these_responses[it].id == node_value.repo_response_id:
                    response_bool_num = it

            nodeMatId = "mat" + str(node_value.repo_consequence.materialisation_id)
            diag.cpt(nodeConsId)[{nodeMatId: occurance_bool_num, nodeReId: response_bool_num}] = [1 - (node_value.prob / 100),node_value.prob / 100]
        # print(these_cosnequence_values)

    # Service node values
    for service in these_services:
        nodeServId = "serv" + str(service.id)
        diag.cpt(nodeServId).fillWith([0.6, 0.4])

    # Impact Node Values
    for impact in these_impacts:
        asset_threat_impact_values = RepoAssetThreatConsequenceServiceImpactRelationship.query.filter_by(
            repo_asset_id=asset_id,
            repo_threat_id=threat_id,
            repo_impact_id=impact.id
            # repo_objective_id=objective.id,
        )

        # print("--------------COUNT IS---------------")
        # print(asset_threat_impact_values.count())
        if asset_threat_impact_values.count() > 0:
            for asset_threat_impact_value in asset_threat_impact_values:
                nodeImpactId = "imp" + str(impact.id)

                impact_node_value = []

                impact_node_id = {}
                #
                # print("JSON LOADS IS")
                # print(json.loads(asset_threat_impact_value.consequences_state))
                # print(json.loads(asset_threat_impact_value.services_state))
                # Convert state of objective to correct one for the
                consequence_state = json.loads(asset_threat_impact_value.consequences_state)
                service_state = json.loads(asset_threat_impact_value.services_state)
                for json_dict in consequence_state:
                    # print("JSON_DICT")
                    # print(json_dict)
                    nodeConsId = "con" + str(json_dict['cons_id'])
                    if json_dict['state'] == 'False':
                        state_to_add = 0
                    elif json_dict['state'] == 'True':
                        state_to_add = 1

                    impact_node_id[nodeConsId] = state_to_add

                for json_dict in service_state:
                    nodeServId = "serv" + str(json_dict['serv_id'])
                    if json_dict['state'] == 'False':
                        state_to_add = 0
                    elif json_dict['state'] == 'True':
                        state_to_add = 1

                    impact_node_id[nodeServId] = state_to_add

                impact_node_value.append(asset_threat_impact_value.low_prob / 100)
                # objective_node_value.append(1 - concatted_entry_key.low_prob)
                impact_node_value.append(asset_threat_impact_value.med_prob / 100)
                # objective_node_value.append(1 - concatted_entry_key.med_prob)
                impact_node_value.append(asset_threat_impact_value.high_prob / 100)
                # objective_node_value.append(1 - concatted_entry_key.high_prob)

                # print("-------- TO FIX ERROR --------")
                # print(impact_node_id)
                # print(impact_node_value)
                # print(nodeImpactId)
                # diag.cpt("imp1")[{'con3': 1, 'serv2': 0}] = [50,50,50]
                # diag.cpt(nodeImpactId)[impact_node_id] = [50,50]
                diag.cpt(nodeImpactId)[impact_node_id] = impact_node_value
        else:
            nodeImpactId = "imp" + str(impact.id)
            # print(nodeImpactId)
            diag.saveBIFXML(os.path.join("out", "GiraDynamicTEST.bifxml"))
            diag.cpt(nodeImpactId).fillWith([1, 0, 0])

    # Objective  Node Values
    objective_it = 0
    for objective in these_objectives:
        objective_impact_values = RepoObjectiveImpactRelationship.query.filter_by(
            repo_objective_id=objective.id,
        )
        for objective_impact_value in objective_impact_values:
            nodeObjectiveId = "obj" + str(objective.id)

            objective_node_value = []
            objective_node_id = {}

            # print("JSON LOADS IS")
            # print(json.loads(objective_impact_value.impacts_state))
            # Convert state of objective to correct one for the
            objective_state = json.loads(objective_impact_value.impacts_state)
            for json_dict in objective_state:
                nodeImpactId = "imp" + str(json_dict['imp_id'])
                objective_node_id[nodeImpactId] = json_dict['state']

            objective_node_value.append(objective_impact_value.low_prob / 100)
            # objective_node_value.append(1 - concatted_entry_key.low_prob)
            objective_node_value.append(objective_impact_value.med_prob / 100)
            # objective_node_value.append(1 - concatted_entry_key.med_prob)
            objective_node_value.append(objective_impact_value.high_prob / 100)
            # objective_node_value.append(1 - concatted_entry_key.high_prob)

            # print("-------- TO LEARN ERROR --------")
            # print(objective_node_id)
            # print(objective_node_value)

            diag.cpt(nodeObjectiveId)[objective_node_id] = objective_node_value

    # Utility Node Values
    for utility in these_utils:
        nodeUtilId = "util" + str(utility.id)
        utility_objective_values = RepoUtilityObjectiveRelationship.query.filter_by(
            repo_utility_id=utility.id,
        )
        for utility_objective_value in utility_objective_values:
            # Get Related Objectives
            utility_objective_states = RepoUtilityObjectiveRelationshipManyToMany.query.filter_by(
                repo_this_entry_id=utility_objective_value.id).all()

            utility_node_value = []
            utility_node_id = {}

            for utility_objective_state in utility_objective_states:
                nodeObjectiveId = "obj" + str(utility_objective_state.repo_objective_id)
                # print("<><><><><><><><><><><><><><><>><")
                # print(nodeObjectiveId)
                utility_node_id[nodeObjectiveId] = str(utility_objective_state.repo_objective_state - 1)

            utility_node_value.append(utility_objective_value.utility_value)

            # print("------ Error -------")
            # print(nodeUtilId)
            # print(utility_node_id)
            # print(utility_node_value)
            # print(utility_objective_value.utility_value)
            diag.utility(nodeUtilId)[utility_node_id] = utility_node_value

    # #Add decision ndoe values
    # for service in these_services:
    #     nodeServId = "serv" + str(service.id)
    #     diag.cpt()

    # Print Diagram
    diag.saveBIFXML(os.path.join("out", "GiraDynamic.bifxml"))
    # diag.saveBIF(os.path.join("out", "GiraDynamic.bif"))

    # print("------- Topological Order -------")
    # print(diag.topologicalOrder())


    ie = gum.ShaferShenoyLIMIDInference(diag)

    # print("------- Is Solvable -------")
    # print(ie.isSolvable())
    # print("------- Is Something -------")
    # diag.cpt("re").fillWith([0.6, 0.4])
    # print()

    no_forgetting_array = []

    no_forgetting_array.append("re")

    # for service in these_services:
    #     nodeServId = "serv" + str(service.id)
    #     ie.addEvidence(nodeServId, 0)
    #     no_forgetting_array.append(nodeServId)

    # for response in these_responses:

    # ie.addNoForgettingAssumption(no_forgetting_array)

    # print("Is this solvable =" + str(ie.isSolvable()))
    # ie.addEvidence('te1', 1)
    ie.addEvidence('re', 1)

    # TODO Disable everything here after finishing the testing and create a new function for the actual alert
    # ------------- Testing AREA -------------
    # ie.addEvidence('mat1', [0, 1])

    # ie.addEvidence('con24', [0, 1])
    # ie.addEvidence('con2', [1, 0])
    # ie.addEvidence('con3', [0, 1])

    # ie.addEvidence('con5', [0, 1])
    # ie.addEvidence('obj5', [1, 0 ,0])
    # ie.addEvidence('obj2', [1, 0 ,0])

    # ie.addEvidence('mat7', [0, 1])
    # ie.addEvidence('con24', [0, 1])
    # ie.addEvidence('con33', [1, 0])

    # --------------------------

    ie.makeInference()
    # print("---optimal decision---")
    # print(ie.optimalDecision("re"))
    # # print(ie.optimalDecision(nodeServId))
    # print("--- maximum utility---")
    #
    # print(ie.MEU())

    # print("-------- INFERENCE RESULTS ----------")
    # print(ie.posterior('obj1'))
    # print(ie.posterior('obj2'))
    # print(ie.posterior('obj3'))
    # print(ie.posterior('obj4'))
    # print(ie.posterior('obj5'))
    #
    # print(type(ie.posterior('obj1').topandas()))
    #
    #

    # return ie.posterior('obj1').topandas()

    results = {}
    # Threat Exposure Posterior
    to_result_exposure = ie.posterior("te" + str(this_threat.id)).topandas()
    results["te" + str(this_threat.id)] = to_result_exposure
    # Materialisation Posterior
    for materialisation in these_materialisations:
        nodeMatId = "mat" + str(materialisation.id)
        to_result_materialisation = ie.posterior(nodeMatId).topandas()
        results[nodeMatId] = to_result_materialisation
    # Consequence Posterior
    for consequence in these_consequences:
        nodeConsId = "con" + str(consequence.id)
        to_result_consequence = ie.posterior(nodeConsId).topandas()
        results[nodeConsId] = to_result_consequence
    # Service Posterior
    for service in these_services:
        nodeServId = "serv" + str(service.id)
        to_result_service = ie.posterior(nodeServId).topandas()
        results[nodeServId] = to_result_service
    # Impact Posterior
    for impact in these_impacts:
        nodeImpId = "imp" + str(impact.id)
        to_result_impact = ie.posterior(nodeImpId).topandas()
        results[nodeImpId] = to_result_impact
    # Objective Posterior
    for objective in these_objectives:
        nodeObjId = "obj" + str(objective.id)
        to_result_objective = ie.posterior(nodeObjId).topandas()
        results[nodeObjId] = to_result_objective
    # Util Posterior
    for utility in these_utils:
        nodeUtilId = "util" + str(utility.id)
        to_result_util = ie.posterior(nodeUtilId).topandas()
        # print("--------- UTILITY " + nodeUtilId + "----------")
        # print(ie.posterior(nodeUtilId))
        results[nodeUtilId] = to_result_util

    # print(ie.posteriorUtility("util2"))
    #
    # print("----------EXPOSURE POSTERIOR LIST -----------")
    # print(ie.posterior("te" + str(this_threat.id)).tolist())
    return results
    # Print Graph
    # with open(os.path.join("out", "GiraDynamic.bifxml"), "r") as out:
    #     print(out.read())
    # try:
    #     mat_nodes = RepoRiskThreatAssetMaterialisation.query.filter_by(repo_asset_id=asset_id,
    #                                                                                       repo_threat_id=threat_id,
    #                                                                                       repo_materialisation_id=
    #                                                                                       deconstructedId[1],
    #                                                                                       repo_response_id=
    #                                                                                       deconstructedId[2],
    #                                                                                       threat_occurrence=to_add_threat_occurence_bool).first()
    # except SQLAlchemyError:
    #     return "SQLAlchemyError"
    #


def start_risk_assessment_alert(threat_id, asset_id, exposure_value = None, materialisation_value=None, consequence_values=None, materialisation_value_increase=None, exposure_value_increase=None):
    # Preset Values should have values from 1 - 100
    # Value Increases are counted as percent from the previous value, for example materialisation_value_incrtease= 10 , means 10% increase from the materialisaiton value produced by the first run of risk inference
    diag = gum.InfluenceDiagram()
    try:
        this_risk_assessment = RepoRiskAssessment.query.filter_by(repo_threat_id=threat_id,
                                                                  repo_asset_id=asset_id).first()
    except SQLAlchemyError:
        return "SQLAlchemyError"
    # Node creation
    this_asset = this_risk_assessment.asset
    this_threat = this_risk_assessment.threat

    # Node creation threat exposure
    exposureNodeId = "te" + str(this_threat.id)
    diag.add(gum.LabelizedVariable(exposureNodeId, this_threat.name, 2))

    # Node creation responses
    try:
        these_responses = RepoResponse.query.filter_by(threat_id=threat_id).all()
    except SQLAlchemyError:
        return "SQLAlchemyError"

    nodeId = "re"
    diag.addDecisionNode(gum.LabelizedVariable(nodeId, "Responses", len(these_responses)))

    # Node creation materialisations
    try:
        these_materialisations = RepoMaterialisation.query.filter_by(threat_id=threat_id).all()
    except SQLAlchemyError:
        return "SQLAlchemyError"

    for materialisation in these_materialisations:
        nodeId = "mat" + str(materialisation.id)
        diag.add(gum.LabelizedVariable(nodeId, materialisation.name, 2))

    # Node creation consequences
    try:
        these_consequences = RepoConsequence.query.filter_by(threat_id=threat_id).all()
    except SQLAlchemyError:
        return "SQLAlchemyError"

    for consequence in these_consequences:
        nodeId = "con" + str(consequence.id)
        diag.add(gum.LabelizedVariable(nodeId, consequence.name, 2))

    # Node creation assets
    try:
        these_services = RepoService.query.filter(RepoService.assets.any(id=asset_id)).all()
    except SQLAlchemyError:
        return "SQLAlchemyError"

    # Node creation services
    for service in these_services:
        nodeId = "serv" + str(service.id)
        diag.add(gum.LabelizedVariable(nodeId, service.name, 2))

    # Node creation impacts
    try:
        these_impacts = RepoImpact.query.all()
    except SQLAlchemyError:
        return "SQLAlchemyError"

    for impact in these_impacts:
        nodeId = "imp" + str(impact.id)
        diag.add(gum.LabelizedVariable(nodeId, impact.name, 3))

    # Node creation objectives
    try:
        these_objectives = RepoObjective.query.all()
    except SQLAlchemyError:
        return "SQLAlchemyError"

    for objective in these_objectives:
        nodeId = "obj" + str(objective.id)
        diag.add(gum.LabelizedVariable(nodeId, objective.name, 3))

    # Node creation utilities
    try:
        these_utils = RepoUtility.query.all()
    except SQLAlchemyError:
        return "SQLAlchemyError"

    for utility in these_utils:
        # print("Util" + str(utility.name))
        nodeId = "util" + str(utility.id)
        diag.addUtilityNode(gum.LabelizedVariable(nodeId, str(utility.name), 1))

    # Node Linking
    # Link Exposure and response to materialisation
    for materialisation in these_materialisations:
        nodeId = "mat" + str(materialisation.id)
        diag.addArc(exposureNodeId, nodeId)

    # for response in these_responses:
    for materialisation in these_materialisations:
        nodeId = "re"
        nodeMatId = "mat" + str(materialisation.id)
        diag.addArc(nodeId, nodeMatId)

    # Link Mat and Re to Cons
    for consequence in these_consequences:
        nodeConsId = "con" + str(consequence.id)
        nodeMatId = "mat" + str(consequence.materialisation_id)
        nodeReId = "re"

        diag.addArc(nodeReId, nodeConsId)
        diag.addArc(nodeMatId, nodeConsId)

    # Link cons and service in impacts
    for service in these_services:
        nodeServId = "serv" + str(service.id)
        try:
            these_related_impacts = RepoImpact.query.filter(RepoImpact.services.any(id=service.id)).all()
        except SQLAlchemyError:
            return "SQLAlchemyError"

        for impact in these_related_impacts:
            nodeImpactId = "imp" + str(impact.id)
            diag.addArc(nodeServId, nodeImpactId)
    #
    for consequence in these_consequences:
        nodeConsId = "con" + str(consequence.id)
        try:
            these_related_impacts = RepoImpact.query.filter(RepoImpact.consequences.any(id=consequence.id)).all()
        except SQLAlchemyError:
            return "SQLAlchemyError"

        # for service in these_services:
        #     nodeServId = "serv" + str(service.id)
        #     diag.addArc(nodeConsId, nodeServId)

            # ie.addEvidence(nodeServId, 0)

        for impact in these_related_impacts:
            nodeImpactId = "imp" + str(impact.id)
            diag.addArc(nodeConsId, nodeImpactId)

    # Link objective to imp
    for impact in these_impacts:
        nodeImpactId = "imp" + str(impact.id)
        try:
            these_related_objectives = RepoObjective.query.filter(RepoObjective.impacts.any(id=impact.id))
        except SQLAlchemyError:
            return "SQLAlchemyError"

        for objective in these_related_objectives:
            nodeObjectiveId = "obj" + str(objective.id)
            diag.addArc(nodeImpactId, nodeObjectiveId)

    # Link Utility to Objectives
    for objective in these_objectives:
        nodeObjectiveId = "obj" + str(objective.id)
        try:
            these_related_utilities = RepoUtility.query.filter(RepoUtility.objectives.any(id=objective.id))
        except SQLAlchemyError:
            return "SQLAlchemyError"

        for utility in these_related_utilities:
            nodeUtilId = "util" + str(utility.id)
            diag.addArc(nodeObjectiveId, nodeUtilId)

    # Node Value Filling
    # Exposure Node Values
    try:
        this_exposure = RepoAssetRepoThreatRelationship.query.filter_by(repo_threat_id=threat_id, repo_asset_id=asset_id).first()
    except SQLAlchemyError:
        return "SQLAlchemyError"

    exposure = get_threat_exposure_value(asset_id, threat_id)
    # exposure = calculate_exposure(this_exposure.risk_skill_level, this_exposure.risk_motive, this_exposure.risk_source,
    #                               this_exposure.risk_actor, this_exposure.risk_opportunity)

    # print("-------------------------------------- EXPOSURE IS ----------------------------------------------", exposure)
    diag.cpt(exposureNodeId).fillWith([1 - exposure, exposure])
    # diag.cpt("te1").fillWith([1, 0])

    # Materialisation Node Values
    for materialisation in these_materialisations:
        # print("----- Matinfo ------")
        # print(nodeImpactId)
        # print(nodeObjectiveId)
        nodeMatId = "mat" + str(materialisation.id)
        nodeReId = "re"
        try:
            these_materialisation_values = RepoRiskThreatAssetMaterialisation.query.filter_by(repo_asset_id=asset_id,
                                                                                              repo_threat_id=threat_id,
                                                                                              repo_materialisation_id=materialisation.id).all()
        except SQLAlchemyError:
            return "SQLAlchemyError"
        for node_value in these_materialisation_values:
            if node_value.threat_occurrence is True:
                occurance_bool_num = 1
            else:
                occurance_bool_num = 0

            for it in range(0, len(these_responses), 1):
                if these_responses[it].id == node_value.repo_response_id:
                    response_bool_num = it

            # if node_value.repo_response_id % 2 == 0:
            #     response_bool_num = 1
            # else:
            #     response_bool_num = 0

            diag.cpt(nodeMatId)[{exposureNodeId: occurance_bool_num, nodeReId: response_bool_num}] = [
                1 - (node_value.prob / 100),
                node_value.prob / 100]

        # print(these_materialisation_values)

    # Consequence Node Values
    for consequence in these_consequences:
        # print("----- Matinfo ------")
        # print(nodeImpactId)
        # print(nodeObjectiveId)
        nodeConsId = "con" + str(consequence.id)
        nodeReId = "re"
        try:
            these_cosnequence_values = RepoRiskThreatAssetConsequence.query.filter_by(repo_asset_id=asset_id,
                                                                                      repo_threat_id=threat_id,
                                                                                      repo_consequence_id=consequence.id).all()
        except SQLAlchemyError:
            return "SQLAlchemyError"

        for node_value in these_cosnequence_values:
            if node_value.threat_occurrence is True:
                occurance_bool_num = 1
            else:
                occurance_bool_num = 0

            # response shouldnt work like that this needs a bit of a rework
            if node_value.repo_response_id % 2 == 0:
                response_bool_num = 1
            else:
                response_bool_num = 0

            for it in range(0, len(these_responses), 1):
                if these_responses[it].id == node_value.repo_response_id:
                    response_bool_num = it

            nodeMatId = "mat" + str(node_value.repo_consequence.materialisation_id)
            diag.cpt(nodeConsId)[{nodeMatId: occurance_bool_num, nodeReId: response_bool_num}] = [ 1 - (node_value.prob / 100), node_value.prob / 100]
        # print(these_cosnequence_values)

    # Service node values
    for service in these_services:
        nodeServId = "serv" + str(service.id)
        # Setting the value of ServId probablistically
        diag.cpt(nodeServId).fillWith([0, 1])

    # Impact Node Values
    for impact in these_impacts:
        asset_threat_impact_values = RepoAssetThreatConsequenceServiceImpactRelationship.query.filter_by(
            repo_asset_id=asset_id,
            repo_threat_id=threat_id,
            repo_impact_id=impact.id
            # repo_objective_id=objective.id,
        )

        # print("--------------COUNT IS---------------")
        # print(asset_threat_impact_values.count())
        if asset_threat_impact_values.count() > 0:
            for asset_threat_impact_value in asset_threat_impact_values:
                nodeImpactId = "imp" + str(impact.id)

                impact_node_value = []

                impact_node_id = {}
                #
                # print("JSON LOADS IS")
                # print(json.loads(asset_threat_impact_value.consequences_state))
                # print(json.loads(asset_threat_impact_value.services_state))
                # Convert state of objective to correct one for the
                consequence_state = json.loads(asset_threat_impact_value.consequences_state)
                service_state = json.loads(asset_threat_impact_value.services_state)
                for json_dict in consequence_state:
                    # print("JSON_DICT")
                    # print(json_dict)
                    nodeConsId = "con" + str(json_dict['cons_id'])
                    if json_dict['state'] == 'False':
                        state_to_add = 0
                    elif json_dict['state'] == 'True':
                        state_to_add = 1

                    impact_node_id[nodeConsId] = state_to_add

                for json_dict in service_state:
                    nodeServId = "serv" + str(json_dict['serv_id'])
                    if json_dict['state'] == 'False':
                        state_to_add = 0
                    elif json_dict['state'] == 'True':
                        state_to_add = 1

                    impact_node_id[nodeServId] = state_to_add

                impact_node_value.append(asset_threat_impact_value.low_prob / 100)
                # objective_node_value.append(1 - concatted_entry_key.low_prob)
                impact_node_value.append(asset_threat_impact_value.med_prob / 100)
                # objective_node_value.append(1 - concatted_entry_key.med_prob)
                impact_node_value.append(asset_threat_impact_value.high_prob / 100)
                # objective_node_value.append(1 - concatted_entry_key.high_prob)

                # print("-------- TO FIX ERROR --------")
                # print(impact_node_id)
                # print(impact_node_value)
                # print(nodeImpactId)
                # diag.cpt("imp1")[{'con3': 1, 'serv2': 0}] = [50,50,50]
                # diag.cpt(nodeImpactId)[impact_node_id] = [50,50]
                diag.cpt(nodeImpactId)[impact_node_id] = impact_node_value
        else:
            nodeImpactId = "imp" + str(impact.id)
            # print(nodeImpactId)
            diag.saveBIFXML(os.path.join("out", "GiraDynamicTEST.bifxml"))
            diag.cpt(nodeImpactId).fillWith([1, 0, 0])

    # Objective  Node Values
    objective_it = 0
    for objective in these_objectives:
        objective_impact_values = RepoObjectiveImpactRelationship.query.filter_by(
            repo_objective_id=objective.id,
        )
        for objective_impact_value in objective_impact_values:
            nodeObjectiveId = "obj" + str(objective.id)

            objective_node_value = []
            objective_node_id = {}

            # print("JSON LOADS IS")
            # print(json.loads(objective_impact_value.impacts_state))
            # Convert state of objective to correct one for the
            objective_state = json.loads(objective_impact_value.impacts_state)
            for json_dict in objective_state:
                nodeImpactId = "imp" + str(json_dict['imp_id'])
                objective_node_id[nodeImpactId] = json_dict['state']

            objective_node_value.append(objective_impact_value.low_prob / 100)
            # objective_node_value.append(1 - concatted_entry_key.low_prob)
            objective_node_value.append(objective_impact_value.med_prob / 100)
            # objective_node_value.append(1 - concatted_entry_key.med_prob)
            objective_node_value.append(objective_impact_value.high_prob / 100)
            # objective_node_value.append(1 - concatted_entry_key.high_prob)

            # print("-------- TO LEARN ERROR --------")
            # print(objective_node_id)
            # print(objective_node_value)

            diag.cpt(nodeObjectiveId)[objective_node_id] = objective_node_value

    # Utility Node Values
    for utility in these_utils:
        nodeUtilId = "util" + str(utility.id)
        utility_objective_values = RepoUtilityObjectiveRelationship.query.filter_by(
            repo_utility_id=utility.id,
        )
        for utility_objective_value in utility_objective_values:
            # Get Related Objectives
            utility_objective_states = RepoUtilityObjectiveRelationshipManyToMany.query.filter_by(
                repo_this_entry_id=utility_objective_value.id).all()

            utility_node_value = []
            utility_node_id = {}

            for utility_objective_state in utility_objective_states:
                nodeObjectiveId = "obj" + str(utility_objective_state.repo_objective_id)
                # print("<><><><><><><><><><><><><><><>><")
                # print(nodeObjectiveId)
                utility_node_id[nodeObjectiveId] = str(utility_objective_state.repo_objective_state - 1)

            utility_node_value.append(utility_objective_value.utility_value)

            # print("------ Error -------")
            # print(nodeUtilId)
            # print(utility_node_id)
            # print(utility_node_value)
            # print(utility_objective_value.utility_value)
            diag.utility(nodeUtilId)[utility_node_id] = utility_node_value

    # #Add decision ndoe values
    # for service in these_services:
    #     nodeServId = "serv" + str(service.id)
    #     diag.cpt()

    # Print Diagram
    diag.saveBIFXML(os.path.join("out", "GiraDynamic.bifxml"))
    # diag.saveBIF(os.path.join("out", "GiraDynamic.bif"))

    # print("------- Topological Order -------")
    # print(diag.topologicalOrder())


    ie = gum.ShaferShenoyLIMIDInference(diag)

    # print("------- Is Solvable -------")
    # print(ie.isSolvable())
    # print("------- Is Something -------")


    no_forgetting_array = []

    no_forgetting_array.append("re")

    # ------------- Setting Evidence -------------
    # print("SETTING EVIDENCE")
    # Setup value increase
    # Run an initial inference to get the value that will be added after wards
    if materialisation_value_increase is not None or exposure_value_increase is not None:
        temp_ie = gum.ShaferShenoyLIMIDInference(diag)
        temp_ie.makeInference()
        if exposure_value_increase is not None:
            temp_list = temp_ie.posterior("te" + str(this_threat.id)).tolist()
            # print(temp_list)
            exposure_value_to_increase = temp_list[1]*exposure_value_increase/100
            exposure_new_evidence = temp_list[1] + exposure_value_to_increase
            if exposure_new_evidence > 1:
                exposure_new_evidence = 1

            exposureNodeId = "te" + str(this_threat.id)
            ie.addEvidence(exposureNodeId, [1-exposure_new_evidence, exposure_new_evidence])
            # print("==========PREVIOUS EXP VALUE================")
            # print(exposure_value_increase)
            # print(exposure_new_evidence)
            # print(1-exposure_new_evidence)

        if materialisation_value_increase is not None:
            temp_list = temp_ie.posterior(nodeMatId).tolist()
            # print(temp_list)
            # print(temp_ie.posterior(nodeMatId).topandas())
            materialisation_value_to_increase = temp_list[1]*materialisation_value_increase/100
            materialisation_new_evidence = temp_list[1] + materialisation_value_to_increase
            if materialisation_new_evidence > 1:
                materialisation_new_evidence = 1

            for materialisation in these_materialisations:
                nodeMatId = "mat" + str(materialisation.id)
                # ie.addEvidence(nodeMatId, [1-0.3330799999999999, 0.3330799999999999])
                ie.addEvidence(nodeMatId, [1-materialisation_new_evidence, materialisation_new_evidence])

            # print("==========PREVIOUS MAT VALUE================")
            # print(materialisation_value_to_increase)
            # print(materialisation_new_evidence)
            # print(1-materialisation_new_evidence)



    # Exposure is left as is
    if exposure_value is not None:
        exposureNodeId = "te" + str(this_threat.id)
        ie.addEvidence(exposureNodeId, [1 - exposure_value/100 , exposure_value/100 ])

    # Materialisation is getting values from materialisation values
    if materialisation_value is not None:
        for materialisation in these_materialisations:
            nodeMatId = "mat" + str(materialisation.id)
            ie.addEvidence(nodeMatId, [1 - materialisation_value/100, materialisation_value/100])

    # Response is always negative when a threat occurs
    ie.addEvidence('re', [1, 0])

    # Consequences depend on type of threat
    # Find which threat we are handling now
    if consequence_values is not None:
        # print("CONSEQUENCES ERROR")
        if threat_id == "1":
            ie.addEvidence( "con" + str(these_consequences[0].id), [1 -consequence_values/100,consequence_values/100]) # Disrupt Operations
            ie.addEvidence( "con" + str(these_consequences[1].id), [1 -consequence_values/100,consequence_values/100]) # Unauthorised Control
            ie.addEvidence( "con" + str(these_consequences[2].id), [1 -consequence_values/100,consequence_values/100]) # Unauthorised disclosure of data
            ie.addEvidence( "con" + str(these_consequences[3].id), [1 -consequence_values/100,consequence_values/100]) # Unauthorised modification of data
            ie.addEvidence( "con" + str(these_consequences[4].id), [1 -consequence_values/100,consequence_values/100]) # Infrastructure malfunction
        elif threat_id == "2":
            ie.addEvidence("con" + str(these_consequences[0].id), [1 -consequence_values/100,consequence_values/100])  # Disrupt Operations
            ie.addEvidence("con" + str(these_consequences[1].id), [1 -consequence_values/100,consequence_values/100])  # Unauthorised Control
            ie.addEvidence("con" + str(these_consequences[2].id), [1 -consequence_values/100,consequence_values/100])  # Unauthorised disclosure of data
            ie.addEvidence("con" + str(these_consequences[3].id), [1 -consequence_values/100,consequence_values/100])  # Unauthorised modification of data
            ie.addEvidence("con" + str(these_consequences[4].id), [1 -consequence_values/100,consequence_values/100])  # Infrastructure malfunction
        elif threat_id == "3":
            ie.addEvidence("con" + str(these_consequences[0].id), [1 -consequence_values/100,consequence_values/100])  # Disrupt Operations
            ie.addEvidence("con" + str(these_consequences[1].id), [1 -consequence_values/100,consequence_values/100])  # Unauthorised modification of data
        elif threat_id == "4":
            ie.addEvidence("con" + str(these_consequences[0].id), [1 -consequence_values/100,consequence_values/100])  # Disrupt Operations
            ie.addEvidence("con" + str(these_consequences[1].id), [1 -consequence_values/100,consequence_values/100])  # Unauthorised modification of data
        elif threat_id == "5":
            ie.addEvidence("con" + str(these_consequences[0].id), [1 -consequence_values/100,consequence_values/100])  # Unauthorised disclosure of data
        elif threat_id == "6":
            ie.addEvidence("con" + str(these_consequences[0].id), [1 -consequence_values/100,consequence_values/100])  # Unauthorised disclosure of data
            ie.addEvidence("con" + str(these_consequences[1].id), [1 -consequence_values/100,consequence_values/100])  # Unauthorised modification of data
        elif threat_id == "7":
            ie.addEvidence("con" + str(these_consequences[0].id), [1 -consequence_values/100,consequence_values/100])  # Unauthorised modification of data
        elif threat_id == "8":
            ie.addEvidence("con" + str(these_consequences[0].id), [1 -consequence_values/100,consequence_values/100])  # Disrupt Operations
            ie.addEvidence("con" + str(these_consequences[1].id), [1 -consequence_values/100,consequence_values/100])  # Unauthorised Control
            ie.addEvidence("con" + str(these_consequences[2].id), [1 -consequence_values/100,consequence_values/100])  # Unauthorised disclosure of data
            ie.addEvidence("con" + str(these_consequences[3].id), [1 -consequence_values/100,consequence_values/100])  # Unauthorised modification of data
            ie.addEvidence("con" + str(these_consequences[4].id), [1 -consequence_values/100,consequence_values/100])  # Infrastructure malfunction
        elif threat_id == "9":
            ie.addEvidence("con" + str(these_consequences[0].id), [1 -consequence_values/100,consequence_values/100])  # Unauthorised disclosure of data
            ie.addEvidence("con" + str(these_consequences[1].id), [1 -consequence_values/100,consequence_values/100])  # Unauthorised modification of data
        elif threat_id == "10":
            # The order is different on purpose, this is how it is in the fixtures
            ie.addEvidence("con" + str(these_consequences[1].id), [1 -consequence_values/100,consequence_values/100])  # Unauthorised Control
            ie.addEvidence("con" + str(these_consequences[2].id), [1 -consequence_values/100,consequence_values/100])  # Disrupt Operations
            ie.addEvidence("con" + str(these_consequences[3].id), [1 -consequence_values/100,consequence_values/100])  # Unauthorised disclosure of data
            ie.addEvidence("con" + str(these_consequences[4].id), [1 -consequence_values/100,consequence_values/100])  # Unauthorised modification of data
            ie.addEvidence("con" + str(these_consequences[5].id), [1 -consequence_values/100,consequence_values/100])  # Infrastructure malfunction
        elif threat_id == "11":
            # The order is different on purpose, this is how it is in the fixtures
            ie.addEvidence("con" + str(these_consequences[1].id), [1 -consequence_values/100,consequence_values/100])  # Disrupt Operations
            ie.addEvidence("con" + str(these_consequences[2].id), [1 -consequence_values/100,consequence_values/100])  # Unauthorised Control
            ie.addEvidence("con" + str(these_consequences[3].id), [1 -consequence_values/100,consequence_values/100])  # Unauthorised disclosure of data
            ie.addEvidence("con" + str(these_consequences[4].id), [1 -consequence_values/100,consequence_values/100])  # Unauthorised modification of data
            ie.addEvidence("con" + str(these_consequences[5].id), [1 -consequence_values/100,consequence_values/100])  # Infrastructure malfunction
        elif threat_id == "12":
            # The order is different on purpose, this is how it is in the fixtures
            ie.addEvidence("con" + str(these_consequences[1].id),[1-consequence_values/ 100 , consequence_values / 100])  # Unauthorised Control
            ie.addEvidence("con" + str(these_consequences[2].id),[1-consequence_values/100 , consequence_values / 100])  # Disrupt Operations
            ie.addEvidence("con" + str(these_consequences[3].id),[1-consequence_values/100, consequence_values / 100])  # Unauthorised disclosure of data
            ie.addEvidence("con" + str(these_consequences[4].id), [1-consequence_values/100,consequence_values / 100])  # Unauthorised modification of data
            ie.addEvidence("con" + str(these_consequences[5].id),[1-consequence_values/100, consequence_values / 100])  # Infrastructure malfunction
        else:
            # print("-------SKIPPED------")
            pass

    # Impact and Obj nodes are left as is

    # --------------------------

    # -Make Inference-
    ie.makeInference()

    # print("---optimal decision---")
    # print(ie.optimalDecision("re"))
    # # print(ie.optimalDecision(nodeServId))
    # print("--- maximum utility---")
    #
    # print(ie.MEU())

    # print("-------- INFERENCE RESULTS ----------")
    # print(ie.posterior('obj1'))
    # print(ie.posterior('obj2'))
    # print(ie.posterior('obj3'))
    # print(ie.posterior('obj4'))
    # print(ie.posterior('obj5'))
    #
    # print(type(ie.posterior('obj1').topandas()))
    #
    #

    # return ie.posterior('obj1').topandas()

    results = {}
    # Threat Exposure Posterior
    to_result_exposure = ie.posterior("te" + str(this_threat.id)).topandas()
    results["te" + str(this_threat.id)] = to_result_exposure
    # Materialisation Posterior
    for materialisation in these_materialisations:
        nodeMatId = "mat" + str(materialisation.id)
        to_result_materialisation = ie.posterior(nodeMatId).topandas()
        results[nodeMatId] = to_result_materialisation
    # Consequence Posterior
    for consequence in these_consequences:
        nodeConsId = "con" + str(consequence.id)
        to_result_consequence = ie.posterior(nodeConsId).topandas()
        results[nodeConsId] = to_result_consequence
    # Service Posterior
    for service in these_services:
        nodeServId = "serv" + str(service.id)
        to_result_service = ie.posterior(nodeServId).topandas()
        results[nodeServId] = to_result_service
    # Impact Posterior
    for impact in these_impacts:
        nodeImpId = "imp" + str(impact.id)
        to_result_impact = ie.posterior(nodeImpId).topandas()
        results[nodeImpId] = to_result_impact
    # Objective Posterior
    for objective in these_objectives:
        nodeObjId = "obj" + str(objective.id)
        to_result_objective = ie.posterior(nodeObjId).topandas()
        results[nodeObjId] = to_result_objective
    # Util Posterior
    for utility in these_utils:
        nodeUtilId = "util" + str(utility.id)
        to_result_util = ie.posterior(nodeUtilId).topandas()
        # print("--------- UTILITY " + nodeUtilId + "----------")
        # print(ie.posterior(nodeUtilId))
        results[nodeUtilId] = to_result_util

    return results



def risk_assessment_manual(threat_id, asset_id, exposures_set, materialisations_set, responses_set, consequences_set,
                           services_set, impacts_set, objectives_set):
    """ Set Array are all the same: [{"id": "id_value", "value" : "value_value" }]
        where id is the current nodes id and values whether it occurs/doesn't occur or is automatic
    """
    diag = gum.InfluenceDiagram()
    try:
        this_risk_assessment = RepoRiskAssessment.query.filter_by(repo_threat_id=threat_id,
                                                                  repo_asset_id=asset_id).first()
    except SQLAlchemyError:
        return "SQLAlchemyError"
    # Node creation
    this_asset = this_risk_assessment.asset
    this_threat = this_risk_assessment.threat

    # Node creation threat exposure
    exposureNodeId = "te" + str(this_threat.id)
    diag.add(gum.LabelizedVariable(exposureNodeId, this_threat.name, 2))

    # Node creation responses
    try:
        these_responses = RepoResponse.query.filter_by(threat_id=threat_id).all()
    except SQLAlchemyError:
        return "SQLAlchemyError"

    nodeId = "re"
    diag.addDecisionNode(gum.LabelizedVariable(nodeId, "Responses", len(these_responses)))

    # Node creation materialisations
    try:
        these_materialisations = RepoMaterialisation.query.filter_by(threat_id=threat_id).all()
    except SQLAlchemyError:
        return "SQLAlchemyError"

    for materialisation in these_materialisations:
        nodeId = "mat" + str(materialisation.id)
        diag.add(gum.LabelizedVariable(nodeId, materialisation.name, 2))

    # Node creation consequences
    try:
        these_consequences = RepoConsequence.query.filter_by(threat_id=threat_id).all()
    except SQLAlchemyError:
        return "SQLAlchemyError"

    for consequence in these_consequences:
        nodeId = "con" + str(consequence.id)
        diag.add(gum.LabelizedVariable(nodeId, consequence.name, 2))

    # Node creation assets
    try:
        these_services = RepoService.query.filter(RepoService.assets.any(id=asset_id)).all()
    except SQLAlchemyError:
        return "SQLAlchemyError"

    for service in these_services:
        nodeId = "serv" + str(service.id)
        diag.addDecisionNode(gum.LabelizedVariable(nodeId, service.name, 2))

    # Node creation impacts
    try:
        these_impacts = RepoImpact.query.all()
    except SQLAlchemyError:
        return "SQLAlchemyError"

    for impact in these_impacts:
        nodeId = "imp" + str(impact.id)
        diag.add(gum.LabelizedVariable(nodeId, impact.name, 3))

    # Node creation objectives
    try:
        these_objectives = RepoObjective.query.all()
    except SQLAlchemyError:
        return "SQLAlchemyError"

    for objective in these_objectives:
        nodeId = "obj" + str(objective.id)
        diag.add(gum.LabelizedVariable(nodeId, objective.name, 3))

    # Node creation utilities
    try:
        these_utils = RepoUtility.query.all()
    except SQLAlchemyError:
        return "SQLAlchemyError"

    for utility in these_utils:
        # print("Util" + str(utility.name))
        nodeId = "util" + str(utility.id)
        diag.addUtilityNode(gum.LabelizedVariable(nodeId, str(utility.name), 1))

    # Node Linking
    # Link Exposure and response to materialisation
    for materialisation in these_materialisations:
        nodeId = "mat" + str(materialisation.id)
        diag.addArc(exposureNodeId, nodeId)

    # for response in these_responses:
    for materialisation in these_materialisations:
        nodeId = "re"
        nodeMatId = "mat" + str(materialisation.id)
        diag.addArc(nodeId, nodeMatId)

    # Link Mat and Re to Cons
    for consequence in these_consequences:
        nodeConsId = "con" + str(consequence.id)
        nodeMatId = "mat" + str(consequence.materialisation_id)
        nodeReId = "re"

        diag.addArc(nodeReId, nodeConsId)
        diag.addArc(nodeMatId, nodeConsId)

    # Link cons and service in impacts
    for service in these_services:
        nodeServId = "serv" + str(service.id)
        try:
            these_related_impacts = RepoImpact.query.filter(RepoImpact.services.any(id=service.id)).all()
        except SQLAlchemyError:
            return "SQLAlchemyError"

        for impact in these_related_impacts:
            nodeImpactId = "imp" + str(impact.id)
            diag.addArc(nodeServId, nodeImpactId)
    #
    for consequence in these_consequences:
        nodeConsId = "con" + str(consequence.id)
        try:
            these_related_impacts = RepoImpact.query.filter(RepoImpact.consequences.any(id=consequence.id)).all()
        except SQLAlchemyError:
            return "SQLAlchemyError"

        for impact in these_related_impacts:
            nodeImpactId = "imp" + str(impact.id)
            diag.addArc(nodeConsId, nodeImpactId)

    # Link objective to imp
    for impact in these_impacts:
        nodeImpactId = "imp" + str(impact.id)
        try:
            these_related_objectives = RepoObjective.query.filter(RepoObjective.impacts.any(id=impact.id))
        except SQLAlchemyError:
            return "SQLAlchemyError"

        for objective in these_related_objectives:
            nodeObjectiveId = "obj" + str(objective.id)
            diag.addArc(nodeImpactId, nodeObjectiveId)

    # Link Utility to Objectives
    for objective in these_objectives:
        nodeObjectiveId = "obj" + str(objective.id)
        try:
            these_related_utilities = RepoUtility.query.filter(RepoUtility.objectives.any(id=objective.id))
        except SQLAlchemyError:
            return "SQLAlchemyError"

        for utility in these_related_utilities:
            nodeUtilId = "util" + str(utility.id)
            diag.addArc(nodeObjectiveId, nodeUtilId)

    # Node Value Filling
    # Exposure Node Values
    try:
        this_exposure = RepoAssetRepoThreatRelationship.query.filter_by(repo_threat_id=threat_id, repo_asset_id=asset_id).first()
    except SQLAlchemyError:
        return "SQLAlchemyError"

    exposure = get_threat_exposure_value(asset_id, threat_id)
    # exposure = calculate_exposure(this_exposure.risk_skill_level, this_exposure.risk_motive, this_exposure.risk_source,
    #                               this_exposure.risk_actor, this_exposure.risk_opportunity)

    diag.cpt("te1").fillWith([1 - exposure, exposure])

    # Materialisation Node Values
    for materialisation in these_materialisations:
        # print("----- Matinfo ------")
        # print(nodeImpactId)
        # print(nodeObjectiveId)
        nodeMatId = "mat" + str(materialisation.id)
        nodeReId = "re"
        try:
            these_materialisation_values = RepoRiskThreatAssetMaterialisation.query.filter_by(repo_asset_id=asset_id,
                                                                                              repo_threat_id=threat_id,
                                                                                              repo_materialisation_id=materialisation.id).all()
        except SQLAlchemyError:
            return "SQLAlchemyError"
        for node_value in these_materialisation_values:
            if node_value.threat_occurrence is True:
                occurance_bool_num = 1
            else:
                occurance_bool_num = 0

            for it in range(0, len(these_responses), 1):
                if these_responses[it].id == node_value.repo_response_id:
                    response_bool_num = it

            # if node_value.repo_response_id % 2 == 0:
            #     response_bool_num = 1
            # else:
            #     response_bool_num = 0

            diag.cpt(nodeMatId)[{exposureNodeId: occurance_bool_num, nodeReId: response_bool_num}] = [
                1 - (node_value.prob / 100),
                node_value.prob / 100]

        # print(these_materialisation_values)

    # Consequence Node Values
    for consequence in these_consequences:
        # print("----- Matinfo ------")
        # print(nodeImpactId)
        # print(nodeObjectiveId)
        nodeConsId = "con" + str(consequence.id)
        nodeReId = "re"
        try:
            these_cosnequence_values = RepoRiskThreatAssetConsequence.query.filter_by(repo_asset_id=asset_id,
                                                                                      repo_threat_id=threat_id,
                                                                                      repo_consequence_id=consequence.id).all()
        except SQLAlchemyError:
            return "SQLAlchemyError"

        for node_value in these_cosnequence_values:
            if node_value.threat_occurrence is True:
                occurance_bool_num = 1
            else:
                occurance_bool_num = 0

            # response shouldnt work like that this needs a bit of a rework
            if node_value.repo_response_id % 2 == 0:
                response_bool_num = 1
            else:
                response_bool_num = 0

            for it in range(0, len(these_responses), 1):
                if these_responses[it].id == node_value.repo_response_id:
                    response_bool_num = it

            nodeMatId = "mat" + str(node_value.repo_consequence.materialisation_id)
            diag.cpt(nodeConsId)[{nodeMatId: occurance_bool_num, nodeReId: response_bool_num}] = [ 1 - (node_value.prob / 100),node_value.prob / 100]
        # print(these_cosnequence_values)

    # Impact Node Values
    for impact in these_impacts:
        asset_threat_impact_values = RepoAssetThreatConsequenceServiceImpactRelationship.query.filter_by(
            repo_asset_id=asset_id,
            repo_threat_id=threat_id,
            repo_impact_id=impact.id
            # repo_objective_id=objective.id,
        )
        for asset_threat_impact_value in asset_threat_impact_values:
            nodeImpactId = "imp" + str(impact.id)

            impact_node_value = []

            impact_node_id = {}
            #
            # print("JSON LOADS IS")
            # print(json.loads(asset_threat_impact_value.consequences_state))
            # print(json.loads(asset_threat_impact_value.services_state))
            # Convert state of objective to correct one for the
            consequence_state = json.loads(asset_threat_impact_value.consequences_state)
            service_state = json.loads(asset_threat_impact_value.services_state)
            for json_dict in consequence_state:
                # print("JSON_DICT")
                # print(json_dict)
                nodeConsId = "con" + str(json_dict['cons_id'])
                if json_dict['state'] == 'False':
                    state_to_add = 0
                elif json_dict['state'] == 'True':
                    state_to_add = 1

                impact_node_id[nodeConsId] = state_to_add

            for json_dict in service_state:
                nodeServId = "serv" + str(json_dict['serv_id'])
                if json_dict['state'] == 'False':
                    state_to_add = 0
                elif json_dict['state'] == 'True':
                    state_to_add = 1

                impact_node_id[nodeServId] = state_to_add

            impact_node_value.append(asset_threat_impact_value.low_prob)
            # objective_node_value.append(1 - concatted_entry_key.low_prob)
            impact_node_value.append(asset_threat_impact_value.med_prob)
            # objective_node_value.append(1 - concatted_entry_key.med_prob)
            impact_node_value.append(asset_threat_impact_value.high_prob)
            # objective_node_value.append(1 - concatted_entry_key.high_prob)

            # print("-------- TO FIX ERROR --------")
            # print(impact_node_id)
            # print(impact_node_value)
            # print(nodeImpactId)
            # diag.cpt("imp1")[{'con3': 1, 'serv2': 0}] = [50,50,50]
            # diag.cpt(nodeImpactId)[impact_node_id] = [50,50]
            diag.cpt(nodeImpactId)[impact_node_id] = impact_node_value

    # Objective  Node Values
    objective_it = 0
    for objective in these_objectives:
        objective_impact_values = RepoObjectiveImpactRelationship.query.filter_by(
            repo_objective_id=objective.id,
        )
        for objective_impact_value in objective_impact_values:
            nodeObjectiveId = "obj" + str(objective.id)

            objective_node_value = []
            objective_node_id = {}

            # print("JSON LOADS IS")
            # print(json.loads(objective_impact_value.impacts_state))
            # Convert state of objective to correct one for the
            objective_state = json.loads(objective_impact_value.impacts_state)
            for json_dict in objective_state:
                nodeImpactId = "imp" + str(json_dict['imp_id'])
                objective_node_id[nodeImpactId] = json_dict['state']

            objective_node_value.append(objective_impact_value.low_prob)
            # objective_node_value.append(1 - concatted_entry_key.low_prob)
            objective_node_value.append(objective_impact_value.med_prob)
            # objective_node_value.append(1 - concatted_entry_key.med_prob)
            objective_node_value.append(objective_impact_value.high_prob)
            # objective_node_value.append(1 - concatted_entry_key.high_prob)

            # print("-------- TO LEARN ERROR --------")
            # print(objective_node_id)
            # print(objective_node_value)

            diag.cpt(nodeObjectiveId)[objective_node_id] = objective_node_value

    # Utility Node Values
    for utility in these_utils:
        nodeUtilId = "util" + str(utility.id)
        utility_objective_values = RepoUtilityObjectiveRelationship.query.filter_by(
            repo_utility_id=utility.id,
        )
        for utility_objective_value in utility_objective_values:
            # Get Related Objectives
            utility_objective_states = RepoUtilityObjectiveRelationshipManyToMany.query.filter_by(
                repo_this_entry_id=utility_objective_value.id).all()

            utility_node_value = []
            utility_node_id = {}

            for utility_objective_state in utility_objective_states:
                nodeObjectiveId = "obj" + str(utility_objective_state.repo_objective_id)
                utility_node_id[nodeObjectiveId] = str(utility_objective_state.repo_objective_state - 1)

            utility_node_value.append(utility_objective_value.utility_value)

            # print("------ Error -------")
            # print(nodeUtilId)
            # print(utility_node_id)
            # print(utility_node_value)
            # print(utility_objective_value.utility_value)
            diag.utility(nodeUtilId)[utility_node_id] = utility_node_value

    # Print Diagram
    diag.saveBIFXML(os.path.join("out", "GiraDynamic.bifxml"))

    ie = gum.ShaferShenoyLIMIDInference(diag)

    no_forgetting_array = []

    no_forgetting_array.append("re")

    for service in these_services:
        nodeServId = "serv" + str(service.id)
        no_forgetting_array.append(nodeServId)

    # for response in these_responses:

    ie.addNoForgettingAssumption(no_forgetting_array)

    # print("Is this solvable =" + str(ie.isSolvable()))
    # ie.addEvidence('te1', 1)
    # ie.addEvidence('re', 0)

    # ie.makeInference()

    # --------- Set Manual Values ---------
    for exposure_set in exposures_set:
        if exposure_set["value"] != "automatic":
            if exposure_set["value"] == "occurs":
                value_to_add = 1
            elif exposure_set["value"] == "nothing":
                value_to_add = 0
            else:
                # print("Error passing values to risk assessment")
                continue

            nodeTeId = "te" + str(exposure_set["id"])
            ie.addEvidence(nodeTeId, value_to_add)

    # Responses NOT WORKING CURRENTLY DISABLED CAUSING ERRORS
    for response_set_set in responses_set:
        if response_set_set["value"] != "automatic":
            if response_set_set["value"] == "occurs":
                value_to_add = 1
            elif response_set_set["value"] == "nothing":
                value_to_add = 0
            else:
                # print("Error passing values to risk assessment")
                continue

            # print("Responses are set")
            nodeResId = "re" + str(response_set_set["id"])
            # ie.addEvidence(nodeResId, value_to_add)

    for materialisation_set in materialisations_set:
        if materialisation_set["value"] != "automatic":
            if materialisation_set["value"] == "occurs":
                value_to_add = 1
            elif materialisation_set["value"] == "nothing":
                value_to_add = 0
            else:
                # print("Error passing values to risk assessment")
                continue

            # print("Materialisations are set")
            nodeMatId = "mat" + str(materialisation_set["id"])
            ie.addEvidence(nodeMatId, value_to_add)

    for consequence_set in consequences_set:
        if consequence_set["value"] != "automatic":
            if consequence_set["value"] == "occurs":
                value_to_add = 1
            elif consequence_set["value"] == "nothing":
                value_to_add = 0
            else:
                # print("Error passing values to risk assessment")
                continue

            nodeConsId = "con" + str(consequence_set["id"])
            ie.addEvidence(nodeConsId, value_to_add)

    for service_set in services_set:
        if service_set["value"] != "automatic":
            if service_set["value"] == "occurs":
                value_to_add = 1
            elif service_set["value"] == "nothing":
                value_to_add = 0
            else:
                # print("Error passing values to risk assessment")
                continue

            nodeServId = "serv" + str(service_set["id"])
            ie.addEvidence(nodeServId, value_to_add)

    for impact_set in impacts_set:
        if impact_set["value"] != "automatic":
            if impact_set["value"] == "occurs":
                value_to_add = 1
            elif impact_set["value"] == "nothing":
                value_to_add = 0
            else:
                # print("Error passing values to risk assessment")
                continue

            nodeImpId = "imp" + str(impact_set["id"])
            ie.addEvidence(nodeImpId, value_to_add)

    for objective_set in objectives_set:
        if objective_set["value"] != "automatic":
            if objective_set["value"] == "occurs":
                value_to_add = 1
            elif objective_set["value"] == "nothing":
                value_to_add = 0
            else:
                # print("Error passing values to risk assessment")
                continue

            nodeObjId = "obj" + str(objective_set["id"])
            ie.addEvidence(nodeObjId, value_to_add)

    # print("-------- INFERENCE RESULTS ----------")
    # print(ie.posterior('obj1'))
    # print(ie.posterior('obj2'))
    # print(ie.posterior('obj3'))
    # print(ie.posterior('obj4'))
    # print(ie.posterior('obj5'))
    #
    # print(type(ie.posterior('obj1').topandas()))
    #
    #

    # return ie.posterior('obj1').topandas()
    ie.makeInference()

    results = {}
    # Threat Exposure Posterior
    to_result_exposure = ie.posterior("te" + str(this_threat.id)).topandas()
    results["te" + str(this_threat.id)] = to_result_exposure
    # Materialisation Posterior
    for materialisation in these_materialisations:
        nodeMatId = "mat" + str(materialisation.id)
        to_result_materialisation = ie.posterior(nodeMatId).topandas()
        results[nodeMatId] = to_result_materialisation
    # Consequence Posterior
    for consequence in these_consequences:
        nodeConsId = "con" + str(consequence.id)
        to_result_consequence = ie.posterior(nodeConsId).topandas()
        results[nodeConsId] = to_result_consequence
    # Service Posterior
    for service in these_services:
        nodeServId = "serv" + str(service.id)
        to_result_service = ie.posterior(nodeServId).topandas()
        results[nodeServId] = to_result_service
    # Impact Posterior
    for impact in these_impacts:
        nodeImpId = "imp" + str(impact.id)
        to_result_impact = ie.posterior(nodeImpId).topandas()
        results[nodeImpId] = to_result_impact
    # Objective Posterior
    for objective in these_objectives:
        nodeObjId = "obj" + str(objective.id)
        to_result_objective = ie.posterior(nodeObjId).topandas()
        results[nodeObjId] = to_result_objective
    # Util Posterior
    for utility in these_utils:
        nodeUtilId = "util" + str(utility.id)
        to_result_util = ie.posterior(nodeObjId).topandas()
        results[nodeObjId] = to_result_util

    return results
    # Print Graph
    # with open(os.path.join("out", "GiraDynamic.bifxml"), "r") as out:
    #     print(out.read())
    # try:
    #     mat_nodes = RepoRiskThreatAssetMaterialisation.query.filter_by(repo_asset_id=asset_id,
    #                                                                                       repo_threat_id=threat_id,
    #                                                                                       repo_materialisation_id=
    #                                                                                       deconstructedId[1],
    #                                                                                       repo_response_id=
    #                                                                                       deconstructedId[2],
    #                                                                                       threat_occurrence=to_add_threat_occurence_bool).first()
    # except SQLAlchemyError:
    #     return "SQLAlchemyError"
    #


# def security_event_risk_assessment(threat_id, asset_id):
# def start_risk_assessment_pycid(threat_id, asset_id):
#     # diag = gum.InfluenceDiagram()
#     all_nodes = []
#     utility_nodes = []
#     decision_nodes = []
#     try:
#         this_risk_assessment = RepoRiskAssessment.query.filter_by(repo_threat_id=threat_id,
#                                                                   repo_asset_id=asset_id).first()
#     except SQLAlchemyError:
#         return "SQLAlchemyError"
#     # Node creation
#     this_asset = this_risk_assessment.asset
#     this_threat = this_risk_assessment.threat
#
#     # Node creation threat exposure
#     exposureNodeId = "te" + str(this_threat.id)
#     # all_nodes_array.append(exposureNodeId)
#     # diag.add(gum.LabelizedVariable(exposureNodeId, this_threat.name, 2))
#
#     # Node creation responses
#     try:
#         these_responses = RepoResponse.query.filter_by(threat_id=threat_id).all()
#     except SQLAlchemyError:
#         return "SQLAlchemyError"
#
#     nodeId = "re"
#     decision_nodes.append(nodeId)
#     # diag.addDecisionNode(gum.LabelizedVariable(nodeId, "Responses", len(these_responses)))
#
#     # Node creation materialisations
#     try:
#         these_materialisations = RepoMaterialisation.query.filter_by(threat_id=threat_id).all()
#     except SQLAlchemyError:
#         return "SQLAlchemyError"
#
#     for materialisation in these_materialisations:
#         nodeId = "mat" + str(materialisation.id)
#         # diag.add(gum.LabelizedVariable(nodeId, materialisation.name, 2))
#
#     # Node creation consequences
#     try:
#         these_consequences = RepoConsequence.query.filter_by(threat_id=threat_id).all()
#     except SQLAlchemyError:
#         return "SQLAlchemyError"
#
#     for consequence in these_consequences:
#         nodeId = "con" + str(consequence.id)
#         # diag.add(gum.LabelizedVariable(nodeId, consequence.name, 2))
#
#     # Node creation assets
#     try:
#         these_services = RepoService.query.filter(RepoService.assets.any(id=asset_id)).all()
#     except SQLAlchemyError:
#         return "SQLAlchemyError"
#
#     # Node creation services
#     for service in these_services:
#         nodeId = "serv" + str(service.id)
#         # diag.add(gum.LabelizedVariable(nodeId, service.name, 2))
#
#     # Node creation impacts
#     try:
#         these_impacts = RepoImpact.query.all()
#     except SQLAlchemyError:
#         return "SQLAlchemyError"
#
#     for impact in these_impacts:
#         nodeId = "imp" + str(impact.id)
#         # diag.add(gum.LabelizedVariable(nodeId, impact.name, 3))
#
#     # Node creation objectives
#     try:
#         these_objectives = RepoObjective.query.all()
#     except SQLAlchemyError:
#         return "SQLAlchemyError"
#
#     for objective in these_objectives:
#         nodeId = "obj" + str(objective.id)
#         # diag.add(gum.LabelizedVariable(nodeId, objective.name, 3))
#
#     # Node creation utilities
#     try:
#         these_utils = RepoUtility.query.all()
#     except SQLAlchemyError:
#         return "SQLAlchemyError"
#
#     for utility in these_utils:
#         # print("Util" + str(utility.name))
#         nodeId = "util" + str(utility.id)
#         utility_nodes.append(nodeId)
#         # diag.addUtilityNode(gum.LabelizedVariable(nodeId, str(utility.name), 1))
#
#     # Node Linking
#     # Link Exposure and response to materialisation
#     for materialisation in these_materialisations:
#         nodeId = "mat" + str(materialisation.id)
#         all_nodes.append((exposureNodeId, nodeId))
#         # diag.addArc(exposureNodeId, nodeId)
#
#     # for response in these_responses:
#     for materialisation in these_materialisations:
#         nodeId = "re"
#         nodeMatId = "mat" + str(materialisation.id)
#         all_nodes.append((nodeId, nodeMatId))
#
#         # diag.addArc(nodeId, nodeMatId)
#
#     # Link Mat and Re to Cons
#     for consequence in these_consequences:
#         nodeConsId = "con" + str(consequence.id)
#         nodeMatId = "mat" + str(consequence.materialisation_id)
#         nodeReId = "re"
#
#         all_nodes.append((nodeReId, nodeConsId))
#         all_nodes.append((nodeMatId, nodeConsId))
#
#         # diag.addArc(nodeReId, nodeConsId)
#         # diag.addArc(nodeMatId, nodeConsId)
#
#     # Link cons and service in impacts
#     for service in these_services:
#         nodeServId = "serv" + str(service.id)
#         try:
#             these_related_impacts = RepoImpact.query.filter(RepoImpact.services.any(id=service.id)).all()
#         except SQLAlchemyError:
#             return "SQLAlchemyError"
#
#         for impact in these_related_impacts:
#             nodeImpactId = "imp" + str(impact.id)
#
#             all_nodes.append((nodeServId, nodeImpactId))
#             # diag.addArc(nodeServId, nodeImpactId)
#     #
#     for consequence in these_consequences:
#         nodeConsId = "con" + str(consequence.id)
#         try:
#             these_related_impacts = RepoImpact.query.filter(RepoImpact.consequences.any(id=consequence.id)).all()
#         except SQLAlchemyError:
#             return "SQLAlchemyError"
#
#         # for service in these_services:
#         #     nodeServId = "serv" + str(service.id)
#         #     diag.addArc(nodeConsId, nodeServId)
#
#             # ie.addEvidence(nodeServId, 0)
#
#         for impact in these_related_impacts:
#             nodeImpactId = "imp" + str(impact.id)
#             all_nodes.append((nodeConsId, nodeImpactId))
#
#             # diag.addArc(nodeConsId, nodeImpactId)
#
#     # Link objective to imp
#     for impact in these_impacts:
#         nodeImpactId = "imp" + str(impact.id)
#         try:
#             these_related_objectives = RepoObjective.query.filter(RepoObjective.impacts.any(id=impact.id))
#         except SQLAlchemyError:
#             return "SQLAlchemyError"
#
#         for objective in these_related_objectives:
#             nodeObjectiveId = "obj" + str(objective.id)
#             all_nodes.append((nodeImpactId, nodeObjectiveId))
#
#             # diag.addArc(nodeImpactId, nodeObjectiveId)
#
#     # Link Utility to Objectives
#     for objective in these_objectives:
#         nodeObjectiveId = "obj" + str(objective.id)
#         try:
#             these_related_utilities = RepoUtility.query.filter(RepoUtility.objectives.any(id=objective.id))
#         except SQLAlchemyError:
#             return "SQLAlchemyError"
#
#         for utility in these_related_utilities:
#             nodeUtilId = "util" + str(utility.id)
#             all_nodes.append((nodeObjectiveId, nodeUtilId))
#
#
#             # diag.addArc(nodeObjectiveId, nodeUtilId)
#
#     # Make the diagram
#     cid = pycid.CID(all_nodes,
#                     decisions=decision_nodes,
#                     utilities=utility_nodes)
#
#     attributes_to_add = { "re": [0,1]}
#     cid.model.update(
#         **attributes_to_add
#     )
#     # Node Value Filling
#     # Exposure Node Values
#     try:
#         this_exposure = RepoAssetRepoThreatRelationship.query.filter_by(repo_threat_id=threat_id, repo_asset_id=asset_id).first()
#     except SQLAlchemyError:
#         return "SQLAlchemyError"
#
#     exposure = calculate_exposure(this_exposure.risk_skill_level, this_exposure.risk_motive, this_exposure.risk_source,
#                                   this_exposure.risk_actor, this_exposure.risk_opportunity)
#
#     print("-------------------------------------- EXPOSURE IS ----------------------------------------------", exposure)
#     # attributes_to_add = {"te1": [1 - exposure, exposure]}
#     cid.model["te1"] = {0: 1-exposure, 1: exposure}
#     # diag.cpt("te1").fillWith([1 - exposure, exposure])
#
#     # Materialisation Node Values
#     for materialisation in these_materialisations:
#         # print("----- Matinfo ------")
#         # print(nodeImpactId)
#         # print(nodeObjectiveId)
#         nodeMatId = "mat" + str(materialisation.id)
#         nodeReId = "re"
#         try:
#             these_materialisation_values = RepoRiskThreatAssetMaterialisation.query.filter_by(repo_asset_id=asset_id,
#                                                                                               repo_threat_id=threat_id,
#                                                                                               repo_materialisation_id=materialisation.id).all()
#         except SQLAlchemyError:
#             return "SQLAlchemyError"
#
#         mat_nodes_values = {}
#         for node_value in these_materialisation_values:
#             if node_value.threat_occurrence is True:
#                 occurance_bool_num = 1
#             else:
#                 occurance_bool_num = 0
#
#             for it in range(0, len(these_responses), 1):
#                 if these_responses[it].id == node_value.repo_response_id:
#                     response_bool_num = it
#
#             # Create dict key with the name of the node and current state as key in this format
#             # all_keys + all_values
#
#             mat_nodes_values[exposureNodeId+nodeReId+str(occurance_bool_num)+str(response_bool_num)] = node_value.prob / 100
#             print("MatnodesValues are: ")
#             print(mat_nodes_values)
#             print(''.join(mat_nodes_values.keys()) )
#             # print(''.join(mat_nodes_values.keys() + ''.join(mat_nodes_values.values())) )
#             # cid.model[nodeMatId] = lambda *arg, **kwargs: print(kwargs)
#             mat_nodes_current_it = ""
#             # cid.model[nodeMatId] = lambda *arg, **kwargs: print(''.join(kwargs.keys() ))
#             # cid.model[nodeMatId] = lambda *arg, **kwargs: print(''.join(kwargs.keys() ))
#         # cid.model[nodeMatId] = lambda *arg, **kwargs: (print(mat_nodes_values[''.join(kwargs.keys()) + ''.join(str(x) for x in kwargs.values())]))
#         cid.model[nodeMatId] = lambda *arg, **kwargs: (pycid.bernoulli(mat_nodes_values[''.join(kwargs.keys()) + ''.join(str(x) for x in kwargs.values())]))
#         # print(these_materialisation_values)
#
#     # Consequence Node Values
#     for consequence in these_consequences:
#         # print("----- Matinfo ------")
#         # print(nodeImpactId)
#         # print(nodeObjectiveId)
#         nodeConsId = "con" + str(consequence.id)
#         nodeReId = "re"
#         try:
#             these_cosnequence_values = RepoRiskThreatAssetConsequence.query.filter_by(repo_asset_id=asset_id,
#                                                                                       repo_threat_id=threat_id,
#                                                                                       repo_consequence_id=consequence.id).all()
#         except SQLAlchemyError:
#             return "SQLAlchemyError"
#
#         cons_nodes_values = {}
#         for node_value in these_cosnequence_values:
#             if node_value.threat_occurrence is True:
#                 occurance_bool_num = 1
#             else:
#                 occurance_bool_num = 0
#
#             # response shouldnt work like that this needs a bit of a rework
#             if node_value.repo_response_id % 2 == 0:
#                 response_bool_num = 1
#             else:
#                 response_bool_num = 0
#
#             for it in range(0, len(these_responses), 1):
#                 if these_responses[it].id == node_value.repo_response_id:
#                     response_bool_num = it
#
#             nodeMatId = "mat" + str(node_value.repo_consequence.materialisation_id)
#             # Adding both values in dict name
#             cons_nodes_values[nodeMatId + nodeReId + str(response_bool_num) + str(occurance_bool_num)] = node_value.prob/100
#             cons_nodes_values[nodeReId + nodeMatId + str(occurance_bool_num) + str(response_bool_num)] = node_value.prob/100
#             # print(cons_nodes_values)
#
#         # cid.model[nodeConsId] = lambda *arg, **kwargs: (
#         #     pycid.bernoulli(cons_nodes_values[''.join(kwargs.keys()) + ''.join(str(x) for x in kwargs.values())]))
#
#         print("CONS_NODES_VALUES")
#         print(cons_nodes_values)
#         cid.model[nodeConsId] = lambda zero=0, one=0, *arg, **kwargs: {0:cons_nodes_values[''.join(kwargs.keys()) + ''.join(str(x) for x in kwargs.values())],
#                                                         1:1-cons_nodes_values[''.join(kwargs.keys()) + ''.join(str(x) for x in kwargs.values())]
#                                                         }
#
#
#             # pycid.bernoulli(cons_nodes_values[''.join(kwargs.keys()) + ''.join(str(x) for x in kwargs.values())]))
#             # diag.cpt(nodeConsId)[{nodeMatId: occurance_bool_num, nodeReId: response_bool_num}] = [node_value.prob / 100,
#             #                                                                                       1 - (
#             #                                                                                               node_value.prob / 100)]
#         # print(these_cosnequence_values)
#
#     # Service node values
#     for service in these_services:
#         nodeServId = "serv" + str(service.id)
#         cid.model[nodeServId] = {0: 0.6, 1: 0.4}
#         # diag.cpt(nodeServId).fillWith([0.6, 0.4])
#
#     # Impact Node Values
#     for impact in these_impacts:
#         asset_threat_impact_values = RepoAssetThreatConsequenceServiceImpactRelationship.query.filter_by(
#             repo_asset_id=asset_id,
#             repo_threat_id=threat_id,
#             repo_impact_id=impact.id
#             # repo_objective_id=objective.id,
#         )
#
#         imp_nodes_values = {}
#         for asset_threat_impact_value in asset_threat_impact_values:
#             nodeImpactId = "imp" + str(impact.id)
#
#             impact_node_value = []
#
#             impact_node_id = {}
#             impact_node_id_reverse = {}
#             #
#             # print("JSON LOADS IS")
#             # print(json.loads(asset_threat_impact_value.consequences_state))
#             # print(json.loads(asset_threat_impact_value.services_state))
#             # Convert state of objective to correct one for the
#             consequence_state = json.loads(asset_threat_impact_value.consequences_state)
#             service_state = json.loads(asset_threat_impact_value.services_state)
#             for json_dict in service_state:
#                 nodeServId = "serv" + str(json_dict['serv_id'])
#                 if json_dict['state'] == 'False':
#                     state_to_add = 0
#                 elif json_dict['state'] == 'True':
#                     state_to_add = 1
#
#                 impact_node_id[nodeServId] = state_to_add
#
#             for json_dict in consequence_state:
#                 # print("JSON_DICT")
#                 # print(json_dict)
#                 nodeConsId = "con" + str(json_dict['cons_id'])
#                 if json_dict['state'] == 'False':
#                     state_to_add = 0
#                 elif json_dict['state'] == 'True':
#                     state_to_add = 1
#
#                 impact_node_id[nodeConsId] = state_to_add
#                 impact_node_id_reverse[nodeConsId] = state_to_add
#
#             for json_dict in service_state:
#                 nodeServId = "serv" + str(json_dict['serv_id'])
#                 if json_dict['state'] == 'False':
#                     state_to_add = 0
#                 elif json_dict['state'] == 'True':
#                     state_to_add = 1
#
#                 impact_node_id_reverse[nodeServId] = state_to_add
#
#             impact_node_value.append(asset_threat_impact_value.low_prob / 100)
#             # objective_node_value.append(1 - concatted_entry_key.low_prob)
#             impact_node_value.append(asset_threat_impact_value.med_prob / 100)
#             # objective_node_value.append(1 - concatted_entry_key.med_prob)
#             impact_node_value.append(asset_threat_impact_value.high_prob / 100)
#             # objective_node_value.append(1 - concatted_entry_key.high_prob)
#
#             # print("-------- TO FIX ERROR --------")
#             # print(impact_node_id)
#             # print(impact_node_value)
#             # print(nodeImpactId)
#             # diag.cpt("imp1")[{'con3': 1, 'serv2': 0}] = [50,50,50]
#             # diag.cpt(nodeImpactId)[impact_node_id] = [50,50]
#             # print("IMP NODE ID")
#             # print(impact_node_id)
#             # print("IMP NODE VALUE")
#             # print(impact_node_value)
#             imp_nodes_values[''.join(impact_node_id.keys()) + ''.join(str(x) for x in impact_node_id.values())] = impact_node_value
#             imp_nodes_values[''.join(impact_node_id_reverse.keys()) + ''.join(str(x) for x in impact_node_id_reverse.values())] = impact_node_value
#             # cid.model[nodeImpactId] =  lambda *arg, **kwargs: print(kwargs)
#         # print(imp_nodes_values)
#
#         print("IMP_NODES_VALUES")
#         print(imp_nodes_values)
#         cid.model[nodeImpactId] = lambda *arg, **kwargs: { 0:imp_nodes_values[''.join(kwargs.keys()) + ''.join(str(x) for x in kwargs.values())][0] , 1:imp_nodes_values[''.join(kwargs.keys()) + ''.join(str(x) for x in kwargs.values())][1] , 2:imp_nodes_values[''.join(kwargs.keys()) + ''.join(str(x) for x in kwargs.values())][2] }
#    #          # diag.cpt(nodeImpactId)[impact_node_id] = impact_node_value
#     #
#     # Objective  Node Values
#     objective_it = 0
#     for objective in these_objectives:
#         objective_impact_values = RepoObjectiveImpactRelationship.query.filter_by(
#             repo_objective_id=objective.id,
#         )
#
#         obj_nodes_values = {}
#         for objective_impact_value in objective_impact_values:
#             nodeObjectiveId = "obj" + str(objective.id)
#
#             objective_node_value = []
#             objective_node_id = {}
#
#             # print("JSON LOADS IS")
#             # print(json.loads(objective_impact_value.impacts_state))
#             # Convert state of objective to correct one for the
#             objective_state = json.loads(objective_impact_value.impacts_state)
#             for json_dict in objective_state:
#                 nodeImpactId = "imp" + str(json_dict['imp_id'])
#                 objective_node_id[nodeImpactId] = json_dict['state']
#
#             objective_node_value.append(objective_impact_value.low_prob / 100)
#             # objective_node_value.append(1 - concatted_entry_key.low_prob)
#             objective_node_value.append(objective_impact_value.med_prob / 100)
#             # objective_node_value.append(1 - concatted_entry_key.med_prob)
#             objective_node_value.append(objective_impact_value.high_prob / 100)
#             # objective_node_value.append(1 - concatted_entry_key.high_prob)
#
#             # print("-------- TO LEARN ERROR --------")
#             # print(objective_node_id)
#             # print(objective_node_value)
#             obj_nodes_values[''.join(objective_node_id.keys()) + ''.join(str(x) for x in objective_node_id.values())] = objective_node_value
#
#             # diag.cpt(nodeObjectiveId)[objective_node_id] = objective_node_value
#         print("IMP_NODES_VALUES")
#         print(obj_nodes_values)
#         def test(*arg, **kwargs):
#             print("------- KWARGS ARE ----------")
#             print(kwargs)
#             to_return = {0: obj_nodes_values[''.join(kwargs.keys()) + ''.join(str(x) for x in kwargs.values())][0],
#              1: obj_nodes_values[''.join(kwargs.keys()) + ''.join(str(x) for x in kwargs.values())][1],
#              2: obj_nodes_values[''.join(kwargs.keys()) + ''.join(str(x) for x in kwargs.values())][2]}
#
#             return to_return
#         # cid.model[nodeObjectiveId] = lambda *arg, **kwargs: {0:obj_nodes_values[''.join(kwargs.keys()) + ''.join(str(x) for x in kwargs.values())][0] , 1:obj_nodes_values[''.join(kwargs.keys()) + ''.join(str(x) for x in kwargs.values())][1] , 2:obj_nodes_values[''.join(kwargs.keys()) + ''.join(str(x) for x in kwargs.values())][2] }
#         cid.model[nodeObjectiveId] = test()
#     # # Utility Node Values
#     # for utility in these_utils:
#     #     nodeUtilId = "util" + str(utility.id)
#     #     utility_objective_values = RepoUtilityObjectiveRelationship.query.filter_by(
#     #         repo_utility_id=utility.id,
#     #     )
#     #     for utility_objective_value in utility_objective_values:
#     #         # Get Related Objectives
#     #         utility_objective_states = RepoUtilityObjectiveRelationshipManyToMany.query.filter_by(
#     #             repo_this_entry_id=utility_objective_value.id).all()
#     #
#     #         utility_node_value = []
#     #         utility_node_id = {}
#     #
#     #         for utility_objective_state in utility_objective_states:
#     #             nodeObjectiveId = "obj" + str(utility_objective_state.repo_objective_id)
#     #             utility_node_id[nodeObjectiveId] = str(utility_objective_state.repo_objective_state - 1)
#     #
#     #         utility_node_value.append(utility_objective_value.utility_value)
#     #
#     #         # print("------ Error -------")
#     #         # print(nodeUtilId)
#     #         # print(utility_node_id)
#     #         # print(utility_node_value)
#     #         # print(utility_objective_value.utility_value)
#     #         diag.utility(nodeUtilId)[utility_node_id] = utility_node_value
#
#     # #Add decision ndoe values
#     # for service in these_services:
#     #     nodeServId = "serv" + str(service.id)
#     #     diag.cpt()
#
#     # Print Diagram
#     # diag.saveBIFXML(os.path.join("out", "GiraDynamic.bifxml"))
#     # diag.saveBIF(os.path.join("out", "GiraDynamic.bif"))
#
#     print("------- Topological Order -------")
#     # print(diag.topologicalOrder())
#     cid.draw()
#     print(cid.draw())
#     # cons_nodes_values = {}
#     cid.solve()
#
#     # ie = gum.ShaferShenoyLIMIDInference(diag)
#     #
#     # print("------- Is Solvable -------")
#     # print(ie.isSolvable())
#     # print("------- Is Something -------")
#     # # diag.cpt("re").fillWith([0.6, 0.4])
#     # # print()
#     #
#     # no_forgetting_array = []
#     #
#     # no_forgetting_array.append("re")
#     #
#     # # for service in these_services:
#     # #     nodeServId = "serv" + str(service.id)
#     # #     ie.addEvidence(nodeServId, 0)
#     # #     no_forgetting_array.append(nodeServId)
#     #
#     # # for response in these_responses:
#     #
#     # # ie.addNoForgettingAssumption(no_forgetting_array)
#     #
#     # # print("Is this solvable =" + str(ie.isSolvable()))
#     # # ie.addEvidence('te1', 1)
#     # ie.addEvidence('re', 1)
#     #
#     # ie.makeInference()
#     # print("---optimal decision---")
#     # print(ie.optimalDecision("re"))
#     # # print(ie.optimalDecision(nodeServId))
#     # print("--- maximum utility---")
#     #
#     # print(ie.MEU())
#     #
#     # # print("-------- INFERENCE RESULTS ----------")
#     # # print(ie.posterior('obj1'))
#     # # print(ie.posterior('obj2'))
#     # # print(ie.posterior('obj3'))
#     # # print(ie.posterior('obj4'))
#     # # print(ie.posterior('obj5'))
#     # #
#     # # print(type(ie.posterior('obj1').topandas()))
#     # #
#     # #
#     #
#     # # return ie.posterior('obj1').topandas()
#     #
#     # results = {}
#     # # Threat Exposure Posterior
#     # to_result_exposure = ie.posterior("te" + str(this_threat.id)).topandas()
#     # results["te" + str(this_threat.id)] = to_result_exposure
#     # # Materialisation Posterior
#     # for materialisation in these_materialisations:
#     #     nodeMatId = "mat" + str(materialisation.id)
#     #     to_result_materialisation = ie.posterior(nodeMatId).topandas()
#     #     results[nodeMatId] = to_result_materialisation
#     # # Consequence Posterior
#     # for consequence in these_consequences:
#     #     nodeConsId = "con" + str(consequence.id)
#     #     to_result_consequence = ie.posterior(nodeConsId).topandas()
#     #     results[nodeConsId] = to_result_consequence
#     # # Service Posterior
#     # for service in these_services:
#     #     nodeServId = "serv" + str(service.id)
#     #     to_result_service = ie.posterior(nodeServId).topandas()
#     #     results[nodeServId] = to_result_service
#     # # Impact Posterior
#     # for impact in these_impacts:
#     #     nodeImpId = "imp" + str(impact.id)
#     #     to_result_impact = ie.posterior(nodeImpId).topandas()
#     #     results[nodeImpId] = to_result_impact
#     # # Objective Posterior
#     # for objective in these_objectives:
#     #     nodeObjId = "obj" + str(objective.id)
#     #     to_result_objective = ie.posterior(nodeObjId).topandas()
#     #     results[nodeObjId] = to_result_objective
#     # # Util Posterior
#     # for utility in these_utils:
#     #     nodeUtilId = "util" + str(utility.id)
#     #     to_result_util = ie.posterior(nodeUtilId).topandas()
#     #     results[nodeUtilId] = to_result_util
#
#     # return results
#     return
#
#
#     # Print Graph
#     # with open(os.path.join("out", "GiraDynamic.bifxml"), "r") as out:
#     #     print(out.read())
#     # try:
#     #     mat_nodes = RepoRiskThreatAssetMaterialisation.query.filter_by(repo_asset_id=asset_id,
#     #                                                                                       repo_threat_id=threat_id,
#     #                                                                                       repo_materialisation_id=
#     #                                                                                       deconstructedId[1],
#     #                                                                                       repo_response_id=
#     #                                                                                       deconstructedId[2],
#     #                                                                                       threat_occurrence=to_add_threat_occurence_bool).first()
#     # except SQLAlchemyError:
#     #     return "SQLAlchemyError"
#     #