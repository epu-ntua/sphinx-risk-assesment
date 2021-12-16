import requests
from flask import Response
from sqlalchemy.exc import SQLAlchemyError

from app.models import *
import json
import os
import stix2
import stix2validator
import app.utils.stix2_custom as stix2_custom
from app.producer import SendKafkaReport
from app.globals import GLOBAL_IP



import mlflow
import os
import click
from mlflow.tracking import MlflowClient
from flask import request
from dotenv import load_dotenv
load_dotenv()


def get_mlflow_experiment(ip="5010", experiment="asset.variety.Server"):
    url = "http://mlflow_code:"+ip+"/invocations"
    current_dict = os.getcwd()
    dict_to_load = os.path.join(current_dict, "mlflow_info", experiment, "model", "input_example.json")
    print("--------SENDING---------")
    print(url)
    print(dict_to_load)
    f = open(dict_to_load)
    payload = json.dumps(json.load(f))
    headers = {
        'Content-Type': 'application/json'
    }
    print("--------SENDING---------")
    print(url)
    print(payload)
    response = requests.request("POST", url, headers=headers, data=payload)
    return response

def print_run_info(runs):
    for r in runs:
        print("run_id: {}".format(r.info.run_id))
        # print("lifecycle_stage: {}".format(r.info.lifecycle_stage))
        # print("metrics: {}".format(r.data.metrics))

        # Exclude mlflow system tags
        # tags = {k: v for k, v in r.data.tags.items() if not k.startswith("mlflow.")}
        # print("tags: {}".format(tags))

# @click.command()
# @click.option("--experiments", "-e",
#               type=str,
#               multiple=True,
#               help="The experiment name for which you need to download the example file. (Repeat prefix for multiple arguments)"
#               )
# @click.option("--root-dir", "-d",
#               type=str,
#               multiple=False,
#               default='.',
#               help="The local (root) directory to use for downloading the files"
#               )
def get_ml_flow_info(experiments, root_dir):
    # Search all runs under experiment id and order them by
    # descending value of the metric 'm'
    # root_dir = "./download_examples"
    if not os.path.exists(root_dir):
        os.mkdir(root_dir)

    # This may need change, when run in kubernetes
    client = MlflowClient(tracking_uri='http://mlflow_server:5000')
    for name in experiments:
        e = client.get_experiment_by_name(name)
        print(e.experiment_id, e.name)
        # define / create local directory to store example
        local_dir = os.path.join(root_dir, e.name)
        if not os.path.exists(local_dir):
            os.mkdir(local_dir)
        runs = client.search_runs(e.experiment_id)
        print_run_info(runs)
        print("--")
        # download last run artifacts
        local_path = client.download_artifacts(runs[0].info.run_id, "model/input_example.json", local_dir)
        print("Artifacts downloaded in: {}".format(local_dir))
        print("Artifacts: {}".format(local_dir))


def send_alert_new_asset(asset_obj):
    now = datetime.now()

    print("1")
    try:
        asset_vulnerabilities_count = VulnerabilityReportVulnerabilitiesLink.query.join(RepoAsset).filter(
            RepoAsset.id == asset_obj.id).count()
    except SQLAlchemyError:
        return Response("SQLAlchemyError", 500)
    print("2")
    alert_to_send = {
        "alert_type": "new_asset_detected",
        "date_time": now.strftime("%m/%d/%Y, %H:%M:%S"),
        "asset": {
            "asset_ip": asset_obj.ip if asset_obj.ip else "",
            "asset_common_id": asset_obj.common_id if asset_obj.common_id else "",
            "asset_vulnerabilities": str(asset_vulnerabilities_count),
        },
        "asset_url": GLOBAL_IP + "repo/assets/" + str(asset_obj.id) + "/"
    }

    print("Alerts is --------", alert_to_send, flush=True)
    return alert_to_send


def send_alert_old_asset(asset_obj):
    now = datetime.now()

    try:
        asset_vulnerabilities_count = VulnerabilityReportVulnerabilitiesLink.query.join(RepoAsset).filter(
            RepoAsset.id == asset_obj.id).count()
    except SQLAlchemyError:
        return Response("SQLAlchemyError", 500)

    alert_to_send = {
        "alert_type": "old_asset_detected",
        "date_time": now.strftime("%m/%d/%Y, %H:%M:%S"),
        "asset": {
            "asset_ip": asset_obj.ip if asset_obj.ip else "",
            "asset_common_id": asset_obj.common_id if asset_obj.common_id else "",
            "asset_vulnerabilities": str(asset_vulnerabilities_count),
            "last_touched": asset_obj.last_touch_date if asset_obj.last_touch_date else ""
        },
        "asset_url": GLOBAL_IP + "repo/assets/" + str(asset_obj.id) + "/"
    }

    print("Alerts is --------", alert_to_send, flush=True)
    return alert_to_send


def send_alert_info_update_needed(asset_obj=None, threat_obj=None, threat_exposure_info=-1,
                                  threat_materialisation_info=-1, threat_impact_info=-1, objective_info=-1,
                                  utility_info=-1):
    now = datetime.now()

    pages_to_send = []
    # Add exposure info in alert
    if threat_exposure_info != -1:
        pages_to_send.append(
            GLOBAL_IP + "repo/risk/configuration/threat/exposure/" + str(threat_obj.id) + "/asset/" + str(asset_obj.id) + "/")

    # Add mat and cons info in alert
    if threat_materialisation_info != -1:
        pages_to_send.append(
            GLOBAL_IP + "repo/risk/configuration/threat/" + str(threat_obj.id) + "/asset/" + str(asset_obj.id) + "/")

    # Add impact info in alert
    if threat_impact_info != -1:
        pages_to_send.append(
            GLOBAL_IP + "repo/risk/configuration/impact/1/threat" + str(threat_obj.id) + "/asset/" + str(asset_obj.id) + "/")
        pages_to_send.append(
            GLOBAL_IP + "repo/risk/configuration/impact/2/threat" + str(threat_obj.id) + "/asset/" + str(asset_obj.id) + "/")
        pages_to_send.append(
            GLOBAL_IP + "repo/risk/configuration/impact/3/threat" + str(threat_obj.id) + "/asset/" + str(asset_obj.id) + "/")
        pages_to_send.append(
            GLOBAL_IP + "repo/risk/configuration/impact/4/threat" + str(threat_obj.id) + "/asset/" + str(asset_obj.id) + "/")
        pages_to_send.append(
            GLOBAL_IP + "repo/risk/configuration/impact/5/threat" + str(threat_obj.id) + "/asset/" + str(asset_obj.id) + "/")

    # Add Objective info in alert
    if objective_info != -1:
        pages_to_send.append(GLOBAL_IP + "repo/risk/configuration/objective/1/")
        pages_to_send.append(GLOBAL_IP + "repo/risk/configuration/objective/2/")
        pages_to_send.append(GLOBAL_IP + "repo/risk/configuration/objective/3/")
        pages_to_send.append(GLOBAL_IP + "repo/risk/configuration/objective/4/")
        pages_to_send.append(GLOBAL_IP + "repo/risk/configuration/objective/5/")

    # Add Utility info in alert
    if utility_info != -1:
        pages_to_send.append(GLOBAL_IP + "/repo/risk/configuration/utility/1/")
        pages_to_send.append(GLOBAL_IP + "/repo/risk/configuration/utility/2/")

    alert_to_send = {
        "alert_type": "new_asset_detected",
        "date_time": now.strftime("%m/%d/%Y, %H:%M:%S"),
        "asset": {
            "asset_ip": asset_obj.ip if asset_obj.ip else "",
            "asset_common_id": asset_obj.common_id if asset_obj.common_id else "",
        },
        "threat": threat_obj.name,
        "pages_update_url": pages_to_send
    }

    print("Alerts is --------", alert_to_send, flush=True)
    return alert_to_send


def send_risk_report(report_id, asset_id, threat_id):
    try:
        this_asset = RepoAsset.query.filter_by(id=asset_id).first()
    except SQLAlchemyError:
        return Response("SQLAlchemyError", 500)

    try:
        this_risk_assessment_report = RepoRiskAssessmentReports.query.filter_by(id=report_id).first()
    except SQLAlchemyError:
        return "SQLAlchemyError"

    try:
        this_threat = RepoThreat.query.filter_by(id=threat_id).first()
    except SQLAlchemyError:
        return Response("SQLAlchemyError", 500)

    try:
        this_threat_asset_exposure = RepoAssetRepoThreatRelationship.query.filter_by(repo_asset_id=asset_id,
                                                                                     repo_threat_id=threat_id).first()
    except SQLAlchemyError:
        return Response("SQLAlchemyError", 500)

    report_to_send = {}
    report_to_send["report_info"] = {
        "date_time": this_risk_assessment_report.date_time,
        "type": this_risk_assessment_report.type}

    report_to_send["assset"] = {
        "id": this_asset.id,
        "name": this_asset.name,
        "asset_reputation": 0,  # placeholder
        "ip": this_asset.ip,
        "mac": this_asset.mac_address,
        "last_touched": this_asset.last_touch_date,
        # "type": this_asset.type, #aSSETS DONT HAVE TYPE SHOULD BE ADDED
        # "related_services": SHould this be added?
    }

    report_to_send["threat"] = {
        "name": this_threat.name,
        "probability": this_threat.prob,
        "capec_info": {
            "capec_id": "",
            "name": "",
            "abstraction": "",
            "likelihood": "",
            "typical_severity": ""
        },
        "threat_asset_info": {
            "skill_level": this_threat_asset_exposure.risk_skill_level,
            "motive": this_threat_asset_exposure.risk_motive,
            "source": this_threat_asset_exposure.risk_source,
            "actor": this_threat_asset_exposure.risk_actor,
            "opportunity": this_threat_asset_exposure.risk_opportunity,
        }
    }

    objectives_inference_values = this_risk_assessment_report.objectives_inference.split("|")
    static_info_to_add = {}
    # Load static info to the report
    # exposure_set = []
    # materialisations_set = []
    # responses_set = []
    # consequences_set = []
    # services_set = []
    # impacts_set = []
    # objectives_set = []
    if this_risk_assessment_report.exposure_set:
        exposure_to_add = {}
        exposure_set = this_risk_assessment_report.exposure_set.split("|")
        for it in range(0, len(exposure_set) - 1, 2):
            exposure_to_add[this_threat.name] = exposure_set[it + 1]

        static_info_to_add["exposure"] = exposure_to_add

    if this_risk_assessment_report.materialisations_set:
        materialisation_to_add = {}
        materialisations_set = this_risk_assessment_report.materialisations_set.split("|")
        for it in range(0, len(materialisations_set) - 1, 2):
            try:
                this_materialisation = RepoMaterialisation.query.filter_by(id=materialisations_set[it]).first()
            except SQLAlchemyError:
                return Response("SQLAlchemyError", 500)

            materialisation_to_add[this_materialisation.name] = materialisations_set[it + 1]
        static_info_to_add["materialisations"] = materialisation_to_add

    # Need to add the other static info
    report_to_send["risk"] = {
        "static_info": static_info_to_add,
        "objectives": {
            "confidentiality": {
                "low": str(objectives_inference_values[1]),
                "medium": str(objectives_inference_values[2]),
                "high": str(objectives_inference_values[3])
            },
            "integrity": {
                "low": str(objectives_inference_values[5]),
                "medium": str(objectives_inference_values[6]),
                "high": str(objectives_inference_values[7])
            },
            "availability": {
                "low": str(objectives_inference_values[9]),
                "medium": str(objectives_inference_values[10]),
                "high": str(objectives_inference_values[11])
            },
            "monetary": {
                "low": str(objectives_inference_values[13]),
                "medium": str(objectives_inference_values[14]),
                "high": str(objectives_inference_values[15])
            },
            "safety": {
                "low": str(objectives_inference_values[17]),
                "medium": str(objectives_inference_values[18]),
                "high": str(objectives_inference_values[19])
            },
            "utilities": {
                "CIA": {

                },
                "Evaluation": {

                }
            },
            "alerts": {}
        }
    }

    print("----- THE REPORT IS -----")
    print(report_to_send)
    print(json.dumps(report_to_send))
    report_to_send = json.dumps(report_to_send)
    # print(report_to_send)
    # SendKafkaReport(report_to_send, "rcra-report-topic")


def sendDSSScore():
    asset = stix2.IPv4Address(
        # type="ipv4-addr",
        value="10.0.255.106"
    )
    attack = stix2.AttackPattern(
        # type="attack-pattern",
        name="Spear Phishing as Practiced by Adversary X",
        description="A particular form of spear phishing where the attacker claims that the target had won a contest, including personal details, to get them to click on a link.",
    )

    relationship = stix2.Relationship(
        # type="relationship",
        relationship_type="targets",
        source_ref=attack.id,
        target_ref=asset.id
    )

    scoring = {
        "score": "1",
        "impact": "high",
        "probability": "low"
    }
    rcra = stix2_custom.RCRAObjective(
        x_rcra_scoring=json.dumps(scoring)

    )

    bundle = stix2.Bundle(asset, attack, relationship, rcra)
    print(bundle, flush=True)
    stix2validator.validate_instance(bundle)
    SendKafkaReport(str(bundle), "rcra-report-topic")

    return 0


def sendDSSScoreTest():
    asset = stix2.IPv4Address(
        # type="ipv4-addr",
        value="10.0.255.106"
    )
    attack = stix2.AttackPattern(
        # type="attack-pattern",
        name="Spear Phishing as Practiced by Adversary X",
        description="A particular form of spear phishing where the attacker claims that the target had won a contest, including personal details, to get them to click on a link.",
    )

    relationship = stix2.Relationship(
        # type="relationship",
        relationship_type="targets",
        source_ref=attack.id,
        target_ref=asset.id
    )

    scoring = {
        "score": "20",
        "impact": "high",
        "probability": "low"
    }
    rcra = stix2_custom.RCRAObjective(
        x_rcra_scoring=json.dumps(scoring)

    )

    bundle = stix2.Bundle(asset, attack, relationship, rcra)
    print(bundle, flush=True)
    stix2validator.validate_instance(bundle)
    SendKafkaReport(str(bundle), "rcra-report-topic-test")

    return 0


def send_dss_alert():
    asset = stix2.IPv4Address(
        # type="ipv4-addr",
        value="10.0.255.106"
    )
    attack = stix2.AttackPattern(
        # type="attack-pattern",
        name="Spear Phishing as Practiced by Adversary X",
        description="A particular form of spear phishing where the attacker claims that the target had won a contest, including personal details, to get them to click on a link.",
    )

    relationship = stix2.Relationship(
        # type="relationship",
        relationship_type="targets",
        source_ref=attack.id,
        target_ref=asset.id
    )

    # scoring = {
    #     "score": "1",
    #     "impact": "high",
    #     "probability": "low"
    # }
    # rcra = stix2_custom.RCRAObjective(
    #     x_rcra_scoring=json.dumps(scoring)
    #
    # )

    bundle = stix2.Bundle(asset, attack, relationship)
    print(bundle, flush=True)
    stix2validator.validate_instance(bundle)
    # SendKafkaReport(str(bundle))
    return str(bundle)


def make_visualisation():
    """ Constructs example visualisation for Current Threats by impact level"""
    score = {
        "low_impact": "1",
        "medium_impact": "2",
        "high_impact": "2",
        "critical_impact": "1",
    }

    vis_1 = stix2_custom.RCRACurrentThreatsVis(
        x_rcra_threats=score
    )
    bundle = stix2.Bundle(vis_1)
    stix2validator.validate_instance(bundle)

    # print(bundle, flush=True)
    return str(bundle)


def make_visualisation_current_assets(assets):
    """ Constructs Visualisation for ID new-unverified asset alert """
    vis_1 = stix2_custom.RCRACurrentAssets(
        x_rcra_assets=assets
    )
    bundle = stix2.Bundle(vis_1)
    stix2validator.validate_instance(bundle)

    return str(bundle)


def send_asset_id_alert():
    """' Function Recieves New Detected Assets and Send new visualisation data to ID (all or uknown-unverified only?)"""
    return 1
