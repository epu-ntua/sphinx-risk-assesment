from flask import render_template, request, redirect, jsonify, Response, flash
from multiprocessing import Process

from sqlalchemy.exc import SQLAlchemyError

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
    reputation_report = json.load(result)
    SendKafkaReport(reputation_report, "rcra-asset-reputation")

    for asset_reputation_entry in reputation_report:
        to_add_asset_reputation = RepoAssetReputation(
            source_hospital_id=asset_reputation_entry["source_hospital_id"],
            global_asset_id=asset_reputation_entry["asset_id"],
            global_asset_type=asset_reputation_entry["asset_type"],
            global_asset_ip=asset_reputation_entry["asset_ip"],
            first_update=str(asset_reputation_entry["first_update"]),
            last_update=str(asset_reputation_entry["last_update"]),
            asset_value=asset_reputation_entry["asset_value"],
            count=asset_reputation_entry["count"],
            reputation=asset_reputation_entry["reputation"],
            reputation_speed=asset_reputation_entry["reputation_speed"],
            weighted_importance=asset_reputation_entry["weighted_importance"],
        )

        db.session.add(to_add_asset_reputation)
        try:
            db.session.commit()
        except SQLAlchemyError:
            continue
    return Response(status=200)

@app.route('/asset/metrics/', methods=['POST'])
def threat_metrics_reputation():
    result = request.json
    threat_metrics_report = json.load(result)
    SendKafkaReport(threat_metrics_report, "rcra-threat-metrics")

    for threat_metrics_entry in threat_metrics_report:
        # TODO waiting for TIAR asset_id
        threat = threat_metrics_entry["threat_description"]
        asset_type = threat_metrics_entry["asset_type"]
        if (threat is None) or (asset_type is None):
            continue
        if db.session.query(RepoThreatMetricsReputation.id).filter(threat_description=threat, asset_type=asset_type).first() is not None:
            db_threat_metrics_record = db.session.query(RepoThreatMetricsReputation).filter_by(threat_description=threat, asset_type=asset_type).one()
            xx = db_threat_metrics_record.threat_type_in_this_asset_type_hospital
        else:
            db_threat_metrics_record = RepoThreatMetricsReputation(threat_description=threat, asset_type=asset_type)
        db_threat_metrics_record.threat_timestamp = threat_metrics_entry["threat_timestamp"] if threat_metrics_entry["threat_timestamp"] is not None else ""
        db_threat_metrics_record.threat_id = threat_metrics_entry["threat_id"] if threat_metrics_entry["threat_id"] is not None else ""
        db_threat_metrics_record.threat_type_in_this_asset_type_hospital = threat_metrics_entry["perc_threat_type_in_this_asset_type_hospital"] if float(threat_metrics_entry["perc_threat_type_in_this_asset_type_hospital"]) else ""
        db_threat_metrics_record.threats_in_this_asset_type = threat_metrics_entry["perc_threats_in_this_asset_type"] if float(threat_metrics_entry["perc_threats_in_this_asset_type"]) else ""
        db_threat_metrics_record.threat_description_global = threat_metrics_entry["perc_threat_description_global"] if float(threat_metrics_entry["perc_threat_description_global"]) else ""
        db.session.add(db_threat_metrics_record)
        try:
            db.session.commit()
            if xx != threat_metrics_entry["perc_threat_type_in_this_asset_type_hospital"]:
                pass
                # TODO call RISK assessment
        except SQLAlchemyError:
            continue


    return Response(status=200)

@app.errorhandler(404)
def not_found_error(error):
    return render_template('templates_supporting/404.html', port=serverPort), 404


@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('templates_supporting/500.html', port=serverPort), 500
