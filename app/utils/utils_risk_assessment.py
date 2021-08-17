from app.models import *
import json
import os
import pyAgrum as gum
from sqlalchemy.exc import SQLAlchemyError
from copy import deepcopy

def start_risk_assessment(threat_id, asset_id):
    diag = gum.InfluenceDiagram()
    try:
        this_risk_assessment = RepoRiskAssessment.query.filter_by(repo_threat_id=threat_id,
                                                                  repo_asset_id=asset_id).first()
    except SQLAlchemyError:
        return "SQLAlchemyError"
    ## Node creation
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
    diag.addDecisionNode(gum.LabelizedVariable(nodeId, these_responses[1].name, 2))

    # for response in these_responses:
    #     nodeId = "re" + str(response.id)
    #     diag.addDecisionNode(gum.LabelizedVariable(nodeId, response.name, 2))

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

    ##Node Linking
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

    ## Node Value Filling
    # Exposure Node Values
    diag.cpt("te1").fillWith([0.7, 0.5])

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

            # response shouldnt work like that this needs a bit of a rework
            if node_value.repo_response_id % 2 == 0:
                response_bool_num = 1
            else:
                response_bool_num = 0

            diag.cpt(nodeMatId)[{exposureNodeId: occurance_bool_num, nodeReId: response_bool_num}] = [node_value.prob,
                                                                                                      1 - node_value.prob]

        print(these_materialisation_values)

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

            nodeMatId = "mat" + str(node_value.repo_consequence.materialisation_id)
            diag.cpt(nodeConsId)[{nodeMatId: occurance_bool_num, nodeReId: response_bool_num}] = [node_value.prob,
                                                                                                  1 - node_value.prob]
        print(these_cosnequence_values)

    # Impact Node Values
    for impact in these_impacts:
        nodeImpactId = "imp" + str(impact.id)

        array_impact_calculation = []

        print("Related services are")
        print(these_services)

        print("Related Consequence are")
        print(these_consequences)

        for repo_temp_service in these_services:
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

        for repo_temp_consequence in these_consequences:
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

        joined = db.session.query(RepoAssetThreatConsequenceServiceImpactRelationship,
                                  RepoAssetThreatConsequenceServiceImpactRelationshipConsequenceManyToMany,
                                  RepoAssetThreatConsequenceServiceImpactRelationshipServiceManyToMany).join(
            RepoAssetThreatConsequenceServiceImpactRelationshipConsequenceManyToMany,
            RepoAssetThreatConsequenceServiceImpactRelationshipServiceManyToMany).filter(
            RepoAssetThreatConsequenceServiceImpactRelationship.repo_threat_id == threat_id,
            RepoAssetThreatConsequenceServiceImpactRelationship.repo_impact_id == impact.id,
            RepoAssetThreatConsequenceServiceImpactRelationship.repo_asset_id == asset_id,
        ).all()

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
        # print("------------ RESULTS ARE ----------")
        # print(concatted.items())

        for concatted_entry_key, concatted_entry_value in concatted.items():
            # print("------Comparison------")
            # print(concatted_entry_key)
            # print(concatted_entry_value)
            impact_node_value = []
            impact_node_id = {}

            for temp_entry in concatted_entry_value:
                # state_int = 0
                if temp_entry['state'] is False:
                    state_int = 0
                else:
                    state_int = 1

                if 'consequence' in temp_entry:
                    nodeTempImpactId = "con" + str(temp_entry['consequence']['id'])
                else:
                    nodeTempImpactId = "serv" + str(temp_entry['service']['id'])

                impact_node_id[nodeTempImpactId] = state_int

            # print()
            impact_node_value.append(concatted_entry_key.low_prob)
            # objective_node_value.append(1 - concatted_entry_key.low_prob)
            impact_node_value.append(concatted_entry_key.med_prob)
            # objective_node_value.append(1 - concatted_entry_key.med_prob)
            impact_node_value.append(concatted_entry_key.high_prob)
            # objective_node_value.append(1 - concatted_entry_key.high_prob)

            print("---------- TO ADD ERROR ----------------")
            print(impact_node_id)
            print(impact_node_value)
            print(nodeImpactId)
            diag.cpt(nodeImpactId)[impact_node_id] = impact_node_value

    # Objective  Node Values
    for objective in these_objectives:
        nodeObjectiveId = "obj" + str(objective.id)

        joined = db.session.query(RepoObjectiveImpactRelationship,
                                  RepoObjectiveImpactRelationshipImpactManyToMany) \
            .join(RepoObjectiveImpactRelationshipImpactManyToMany) \
            .filter(
            RepoObjectiveImpactRelationship.repo_objective_id == objective.id,
        ).all()

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

                if inner_joined_arrayed not in concatted[temp_joined[0]]:
                    concatted[temp_joined[0]].append(inner_joined_arrayed)

        for concatted_entry_key, concatted_entry_value in concatted.items():
            # print("------Comparison------")
            # print(concatted_entry_key)
            # print(concatted_entry_value)
            objective_node_value = []
            objective_node_id = {}

            for temp_entry in concatted_entry_value:
                # state_int = 0
                if temp_entry['state'] == 'low':
                    state_int = 0
                if temp_entry['state'] == 'med':
                    state_int = 1
                if temp_entry['state'] == 'high':
                    state_int = 2

                nodeImpactId = "imp" + str(temp_entry['impact'].id)

                objective_node_id[nodeImpactId] = state_int

            # print()
            objective_node_value.append(concatted_entry_key.low_prob)
            # objective_node_value.append(1 - concatted_entry_key.low_prob)
            objective_node_value.append(concatted_entry_key.med_prob)
            # objective_node_value.append(1 - concatted_entry_key.med_prob)
            objective_node_value.append(concatted_entry_key.high_prob)
            # objective_node_value.append(1 - concatted_entry_key.high_prob)

            diag.cpt(nodeObjectiveId)[objective_node_id] = objective_node_value

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

    print("Is this solvable =" + str(ie.isSolvable()))
    ie.addEvidence('te1', 1)
    ie.addEvidence('re', 0)

    ie.makeInference()

    print("-------- INFERENCE RESULTS ----------")
    print(ie.posterior('obj1'))
    print(ie.posterior('obj2'))
    print(ie.posterior('obj3'))
    print(ie.posterior('obj4'))
    print(ie.posterior('obj5'))
    # Print Graph
    # with open(os.path.join("out", "GiraDynamic.bifxml"), "r") as out:
    # print(out.read())
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