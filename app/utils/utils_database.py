from app.models import *
import json
import os

def convert_database_items_to_json_table(items):
    """ Converts sqlalchemy entries to json ,
    Needs to be in an array to work"""
    if items:
        # print(items)
        columns = items[0].__table__.columns._data.keys()
        json_ready = []
        temp_json = {}
        # print(columns, flush=True)
        for item in items:
            # print(item)
            for column in columns:
                temp_json[column] = getattr(item, column)
            json_ready.append(temp_json.copy())
            # print(json_ready)

        return json_ready
    else:
        return []


def import_fixture_from_file(file_name):
    '''Function to imports Json from app/fixtures'''
    with open(os.path.join(os.getcwd(), "app", "fixtures", file_name + ".json"), encoding='utf-8') as json_file:
        return json.load(json_file)


def rcra_db_init():
    """Function is run in the _init_ file when server starts to initialise static table data"""
    # print("Initiating Tamarin SSH Forward", flush=True)
    # # bash_com = './docker/expect.sh tamarin-prover ssh -4 -fN -o "StrictHostKeyChecking no" -L 0.0.0.0:3005:localhost:3001 tamarin-prover@tamarin'
    # bash_com = 'ssh -4 -fN -o "StrictHostKeyChecking no" -L 0.0.0.0:3005:localhost:3001 tamarin-prover@tamarin'
    # cmd = ['./docker/expect.sh', 'tamarin-prover', 'ssh', '-N','-4', '-o', "StrictHostKeyChecking no", '-L',
    #      '0.0.0.0:3005:localhost:3001', 'tamarin-prover@tamarin']
    # process = subprocess.Popen(
    #     cmd, stdout=subprocess.PIPE)
    # output, error = process.communicate()
    # print(output)

    # process = subprocess.run(cmd, capture_output=True, text=True, input="tamarin_prover")
    # output, error = process.communicate()
    # print(output)

    print("Initiating Database", flush=True)
    if RepoService.query.count() is not 0:
        print(RepoService.query.count())
        return "Already exists"

    # Adding Services
    to_add_services = import_fixture_from_file("repo_service")

    for service_json in to_add_services:
        print(service_json)
        to_add_service = RepoService(**service_json)
        db.session.add(to_add_service)

    # Adding Threats
    to_add_threats = import_fixture_from_file("repo_threat")

    for threat_json in to_add_threats:
        to_add_threat = RepoThreat(**threat_json)
        db.session.add(to_add_threat)

    # Adding Impacts
    to_add_impacts = import_fixture_from_file("repo_impact")

    for impact_json in to_add_impacts:
        to_add_impact = RepoImpact(**impact_json)
        db.session.add(to_add_impact)

    # Adding Objectives
    to_add_objectives = import_fixture_from_file("repo_objective")

    for objective_json in to_add_objectives:
        to_add_objective = RepoObjective(**objective_json)
        db.session.add(to_add_objective)

    to_add_objective_options = import_fixture_from_file("repo_objectives_option")

    for objectives_option_json in to_add_objective_options:
        to_add_objectives_option = RepoObjectivesOptions(**objectives_option_json)
        db.session.add(to_add_objectives_option)

    # Adding Utility Nodes
    to_add_utilities = import_fixture_from_file("repo_utility")

    for utility_json in to_add_utilities:
        to_add_utility = RepoUtility(**utility_json)
        db.session.add(to_add_utility)

    # Adding Utility Nodes - Objective Relation
    db.session.flush()
    to_add_utility_objective_relations = import_fixture_from_file("repo_utility_objective_relation")

    for utility_objective_relation_json in to_add_utility_objective_relations:
        utility_to_link = RepoUtility.query.filter_by(id=utility_objective_relation_json["repo_utility_id"]).first()
        objective_to_link = RepoObjective.query.filter_by(id=utility_objective_relation_json["repo_objective_id"]).first()
        # print("gehajedadaw")
        # print(utility_objective_relation_json["repo_objective_id"])
        utility_to_link.objectives.append(objective_to_link)

    # Adding Objective Impact Relationship
    db.session.flush()
    to_add_objective_impact_relationship = import_fixture_from_file("repo_objective_repo_impact_association_table")
    for objective_impact_relation_json in to_add_objective_impact_relationship:
        objective_to_link = RepoObjective.query.filter_by(
            id=objective_impact_relation_json["repo_objective_id"]).first()
        impact_to_link = RepoImpact.query.filter_by(id=objective_impact_relation_json["repo_impact_id"]).first()
        objective_to_link.impacts.append(impact_to_link)

    # Adding Service Impact Relationship
    db.session.flush()
    to_add_service_impact_relationship = import_fixture_from_file("repo_service_repo_impact_association_table")
    for service_impact_relation_json in to_add_service_impact_relationship:
        service_to_link = RepoService.query.filter_by(
            id=service_impact_relation_json["repo_service_id"]).first()
        impact_to_link = RepoImpact.query.filter_by(id=service_impact_relation_json["repo_impact_id"]).first()
        service_to_link.impacts.append(impact_to_link)


    # Adding Repo Consequence
    to_add_consequences = import_fixture_from_file("repo_consequence")
    for consequence_json in to_add_consequences:
        to_add_consequence = RepoConsequence(**consequence_json)
        db.session.add(to_add_consequence)

    # Adding Repo Materialisation
    to_add_materialisations = import_fixture_from_file("repo_materialisation")
    for materialisation_json in to_add_materialisations:
        to_add_materialisation = RepoMaterialisation(**materialisation_json)
        db.session.add(to_add_materialisation)

    # Adding Repo Response
    to_add_responses = import_fixture_from_file("repo_response")
    for response_json in to_add_responses:
        to_add_response = RepoResponse(**response_json)
        db.session.add(to_add_response)

    # Adding Repo Consequence Impact Relationship
    db.session.flush()
    to_add_consequence_impact_relations = import_fixture_from_file("repo_consequence_impact_relationship")
    for consequence_impact_relation_json in to_add_consequence_impact_relations:
        consequence_to_link = RepoConsequence.query.filter_by(id=consequence_impact_relation_json["repo_consequence_id"]).first()
        impact_to_link = RepoImpact.query.filter_by(id=consequence_impact_relation_json["repo_impact_id"]).first()
        consequence_to_link.impacts.append(impact_to_link)

    # Adding Repo Assets Type
    to_add_assets_type = import_fixture_from_file("repo_assets_type")
    for assets_type_json in to_add_assets_type:
        to_add_asset_type = RepoAssetsType(**assets_type_json)
        db.session.add(to_add_asset_type)

    # Adding Repo Assets Variety
    to_add_assets_varieties = import_fixture_from_file("repo_assets_variety")
    for asset_variety_json in to_add_assets_varieties:
        to_add_assets_variety = RepoAssetsVariety(**asset_variety_json)
        db.session.add(to_add_assets_variety)

    # Adding Repo Net Group
    to_add_net_groups = import_fixture_from_file("repo_net_group")
    for net_group_json in to_add_net_groups:
        to_add_net_group = RepoNetGroup(**net_group_json)
        db.session.add(to_add_net_group)

    db.session.commit()
