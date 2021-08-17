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

    db.session.commit()