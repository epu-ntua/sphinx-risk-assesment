from flask import render_template, request, redirect, jsonify, Response, flash
from multiprocessing import Process
from app.producer import *
from app.globals import *
from app.utils import *
from app.forms import *
from app import app
import ast
from app.utils.utils_database import *


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
    return render_template('templates_supporting/entry_page.html')


@app.route('/setup-database/', methods=['GET'])
def setup_database():
    rcra_db_init()
    return Response(status=200)


@app.route('/asset/reputation/', methods=['POST'])
def asset_reputation():
    result = request.json
    print("----- RESULT IS -----")
    print(result)
    print(type(result))
    for asset_reputation_entry in result:
        to_add_asset_reputation = RepoAssetReputation(
            source_hospital_id= asset_reputation_entry["Source_hospital_id"],
        global_asset_id = asset_reputation_entry["Asset_ID"],
        global_asset_type = asset_reputation_entry["Asset_Type"],
        global_asset_ip = asset_reputation_entry["Asset_IP"],
        first_update = str(asset_reputation_entry["first_update"]),
        last_update = str(asset_reputation_entry["last_update"]),
        asset_value = asset_reputation_entry["Asset_Value"],
        count = asset_reputation_entry["count"],
        reputation = asset_reputation_entry["reputation"],
        reputation_speed =asset_reputation_entry["reputation_speed"],
        weighted_importance = asset_reputation_entry["weighted_importance"],
        )

        db.session.add(to_add_asset_reputation)
        db.session.commit()
    return Response(status=200)


@app.errorhandler(404)
def not_found_error(error):
    return render_template('templates_supporting/404.html', port=serverPort), 404


@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('templates_supporting/500.html', port=serverPort), 500
