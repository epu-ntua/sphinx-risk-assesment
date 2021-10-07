from flask import render_template, request, redirect, jsonify, Response, flash
from multiprocessing import Process

from sqlalchemy.exc import SQLAlchemyError

from app.producer import *
from app.globals import *
from app.utils import *
from app.forms import *
from app import app
from app.utils.utils_database import convert_database_items_to_json_table
from app.utils.utils_risk_assessment import start_risk_assessment, risk_assessment_manual
import pandas as pd


@app.route('/repo/dashboard/asset/', methods=['GET', 'POST'])
def repo_dashboard_asset():
    if request.method == 'POST':
        return redirect("/repo/dashboard/asset/")
    else:
        # assetsArray = get_assetsfromrepository()
        # if assetsArray != -1:
        #     return render_template('asset_dashboard.html', assets=assetsArray)
        # else:
        repo_assets = [
            {
                "id": "1",
                "name": "Asset1",
                "location": "Group1",
                "Verified": "false",
                "mac_address": "xx:xx:xx:xx",
                "ip": "xxx.xxx.xxx.xxx",
                "last_touch_date": "today",
            }
        ]
        print(repo_assets)
        return render_template('templates_dashboard/repo_asset_dashboard.html', repo_assets=repo_assets)


@app.route('/repo/dashboard/threat/', methods=['GET', 'POST'])
def repo_dashboard_threat():
    if request.method == 'POST':
        return redirect("/repo/dashboard/threat/")
    else:
        # assetsArray = get_assetsfromrepository()
        # if assetsArray != -1:
        #     return render_template('asset_dashboard.html', assets=assetsArray)
        # else:
        repo_threats = [
            {
                "id": "1",
                "name": "1",
                "capec": "1",
                "cwe": "1"
            }
        ]
        print(repo_threats)
        return render_template('templates_dashboard/repo_threat_dashboard.html', repo_threats=repo_threats)


@app.route('/repo/dashboard/risk/objectives/threat/<threat_id>/asset/<asset_id>/', methods=['GET', 'POST'])
@app.route('/repo/dashboard/risk/objectives/threat/<threat_id>/asset/<asset_id>/assessment/<assessment_id>/',
           methods=['GET', 'POST'])
# @app.route('/repo/dashboard/risk/objectives/threat/<threat_id>/asset/<asset_id>/', methods=['GET', 'POST'])
def repo_dashboard_risk_objectives(threat_id=1, asset_id=-1, assessment_id=-1):
    if request.method == 'POST':
        results = request.form
        print("NEW FORM IS-------------------")
        print(results)

        exposures_set = []
        materialisations_set = []
        responses_set = []
        consequences_set = []
        impacts_set = []
        objectives_set = []

        exposures_set_string = ""
        materialisations_set_string = ""
        responses_set_string = ""
        consequences_set_string = ""
        impacts_set_string = ""
        objectives_set_string = ""

        for key, value in request.form.items():
            print("KEY IS")
            print(key)
            temp_key = "".join(i for i in key if not i.isdigit())
            temp_digit = "".join(i for i in key if i.isdigit())

            if temp_key == "te":
                exposures_set.append({"id": temp_digit, "value": value})
                exposures_set_string = exposures_set_string + str(temp_digit) + "|" + str(
                    value) + "|"
            elif temp_key == "mat":
                materialisations_set.append({"id": temp_digit, "value": value})
                materialisations_set_string = materialisations_set_string + str(temp_digit) + "|" + str(
                    value) + "|"
            elif temp_key == "con":
                responses_set.append({"id": temp_digit, "value": value})
                responses_set_string = responses_set_string + str(temp_digit) + "|" + str(
                    value) + "|"
            elif temp_key == "serv":
                consequences_set.append({"id": temp_digit, "value": value})
                consequences_set_string = consequences_set_string + str(temp_digit) + "|" + str(
                    value) + "|"
            elif temp_key == "imp":
                impacts_set.append({"id": temp_digit, "value": value})
                impacts_set_string = impacts_set_string + str(temp_digit) + "|" + str(
                    value) + "|"
            elif temp_key == "obj":
                objectives_set.append({"id": temp_digit, "value": value})
                objectives_set_string = objectives_set_string + str(temp_digit) + "|" + str(
                    value) + "|"
                # elif temp_key == "util":
            #     materialisations_set_values = str(temp_digit)+ "|" + str(value.values(0)) + "|"
            else:
                print("Ignore")

        print("----------------Strings------------------")
        print(exposures_set_string)
        print(materialisations_set_string)
        print(responses_set_string)
        print(consequences_set_string)
        print(impacts_set_string)
        print(objectives_set_string)

        risk_assessment_result = risk_assessment_manual(threat_id, asset_id, exposures_set, materialisations_set,
                                                        responses_set,
                                                        consequences_set,
                                                        impacts_set, objectives_set)

        print(risk_assessment_result)
        print(type(risk_assessment_result))

        exposure_inference = ""
        materialisations_inference = ""
        consequences_inference = ""
        services_inference = ""
        impacts_inference = ""
        objectives_inference = ""

        for key, value in risk_assessment_result.items():
            print("KEY IS")
            print(key)
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
            # elif temp_key == "util":
            #     materialisations_set_values = str(temp_digit)+ "|" + str(value.values(0)) + "|"
            else:
                print("Ignore")

        this_risk_assessment = RepoRiskAssessment.query.filter_by(repo_threat_id=threat_id,
                                                                  repo_asset_id=asset_id).first()

        manual_risk_assessment = RepoRiskAssessmentReports(
            risk_assessment_id=this_risk_assessment.id,
            type="manual",
            exposure_set=exposures_set_string,
            responses_set=responses_set_string,
            materialisations_set=materialisations_set_string,
            consequences_set=consequences_set_string,
            # services_set=,
            impacts_set=impacts_set_string,
            objectives_set=objectives_set_string,
            exposure_inference=exposure_inference,
            # responses_set_values = responses_set_values,
            materialisations_inference=materialisations_inference,
            consequences_inference=consequences_inference,
            services_inference=services_inference,
            impacts_inference=impacts_inference,
            objectives_inference=objectives_inference,
        )

        db.session.add(manual_risk_assessment)
        db.session.commit()

        return redirect("/repo/dashboard/risk/objectives/threat/" + threat_id + "/asset/" + asset_id + "/")
    else:
        # assetsArray = get_assetsfromrepository()
        # if assetsArray != -1:
        #     return render_template('asset_dashboard.html', assets=assetsArray)
        # else:
        try:
            these_threats = RepoThreat.query.all()
        except SQLAlchemyError:
            return Response("SQLAlchemyError", 500)

        try:
            these_assets = RepoAsset.query.all()
        except SQLAlchemyError:
            return Response("SQLAlchemyError", 500)

        try:
            this_asset = RepoAsset.query.filter_by(id=asset_id).all()
        except SQLAlchemyError:
            return Response("SQLAlchemyError", 500)

        try:
            this_threat = RepoThreat.query.filter_by(id=threat_id).all()
        except SQLAlchemyError:
            return Response("SQLAlchemyError", 500)

        this_threat = convert_database_items_to_json_table(this_threat)
        these_threats = convert_database_items_to_json_table(these_threats)
        these_assets = convert_database_items_to_json_table(these_assets)

        this_exposure = []
        these_materialisations = []
        these_consequences = []
        these_services = []
        these_impacts = []
        these_objectives = []
        these_utils = []
        if threat_id != -1 and asset_id != -1:
            try:
                this_exposure = RepoAssetRepoThreatRelationship.query.filter_by(repo_threat_id=threat_id).all()
            except SQLAlchemyError:
                return "SQLAlchemyError"

            try:
                these_responses = RepoResponse.query.filter_by(threat_id=threat_id).all()
            except SQLAlchemyError:
                return "SQLAlchemyError"

            try:
                these_materialisations = RepoMaterialisation.query.filter_by(threat_id=threat_id).all()
            except SQLAlchemyError:
                return "SQLAlchemyError"

            try:
                these_consequences = RepoConsequence.query.filter_by(threat_id=threat_id).all()
            except SQLAlchemyError:
                return "SQLAlchemyError"

            try:
                these_services = RepoService.query.filter(RepoService.assets.any(id=asset_id)).all()
            except SQLAlchemyError:
                return "SQLAlchemyError"

            try:
                these_impacts = RepoImpact.query.all()
            except SQLAlchemyError:
                return "SQLAlchemyError"

            try:
                these_objectives = RepoObjective.query.all()
            except SQLAlchemyError:
                return "SQLAlchemyError"

            try:
                these_utils = RepoUtility.query.all()
            except SQLAlchemyError:
                return "SQLAlchemyError"

            this_exposure = convert_database_items_to_json_table(this_exposure)
            these_responses = convert_database_items_to_json_table(these_responses)
            these_materialisations = convert_database_items_to_json_table(these_materialisations)
            these_consequences = convert_database_items_to_json_table(these_consequences)
            these_services = convert_database_items_to_json_table(these_services)
            these_impacts = convert_database_items_to_json_table(these_impacts)
            these_objectives = convert_database_items_to_json_table(these_objectives)
            these_utils = convert_database_items_to_json_table(these_utils)

            # print("---DASHBOARD DATA IS---")
            # print(this_exposure)
            # print(these_responses)
            # print(these_materialisations)
            # print(these_consequences)
            # print(these_services)
            # print(these_impacts)
            # print(these_objectives)
            # print(these_utils)

        # repo_threats = [
        #     {
        #         "likelihood": "Certain",
        #         "monetary": "(Low) No monetary loss",
        #         "confidentiality": "(Low) No records leaked",
        #         "integrity": "(Low) No records lost or altered",
        #         "availability": "(Low) No disruption of services",
        #         "safety": "-"
        #     },
        #     {
        #         "likelihood": "Possible",
        #         "monetary": "-",
        #         "confidentiality": "-",
        #         "integrity": "-",
        #         "availability": "-",
        #         "safety": "(Low) No injuries or fatalities likely"
        #     },
        #     {
        #         "likelihood": "Rare",
        #         "monetary": "-",
        #         "confidentiality": "-",
        #         "integrity": "(Medium) Some records lost or altered",
        #         "availability": "(Medium) Some disruption of services",
        #         "safety": "(Medium) Injuries are likely"
        #     },
        #     {
        #         "likelihood": "Rare than Rare",
        #         "monetary": "(High) Significant monetary loss",
        #         "confidentiality": "(High) Many records leaked",
        #         "integrity": "(High) Many records lost or altered",
        #         "availability": "-",
        #         "safety": "-"
        #     },
        #     {
        #         "likelihood": "Oddness 3 or higher",
        #         "monetary": "(Medium) Some monetary loss",
        #         "confidentiality": "(Medium) Some records leaked",
        #         "integrity": "-",
        #         "availability": "(High) Significant disruption of services",
        #         "safety": "(High) Fatalities are likley"
        #     }
        # ]

        # print(repo_threats)
        # print(this_threat)
        #         test_variable = """
        #           obj5                       |
        # 0        |1        |2        |
        # ---------|---------|---------|
        #  0.0000  | 0.0000  | 0.0000  |
        #         """
        risk_assessment_result = start_risk_assessment(1, 1)
        # print("--------------RESSSSSSSSSSSSSSUUUUUUUUUUUUUUUUUUULLLLLLLLLLLLLLLLLTTTTTTTTT-----------")
        # print(risk_assessment_result)
        # print("--------------RESSSSSSSSSSSSSSUUUUUUUUUUUUUUUUUUULLLLLLLLLLLLLLLLLTTTTTTTTT-----------")
        # print(repo_threats)

        # Table showing objective results
        try:
            these_objectives = RepoObjective.query.all()
        except SQLAlchemyError:
            return "SQLAlchemyError"

        repo_threats_values_certain = {
            "Likelihood": "Certain",
            "Monetary": "",
            "Confidentiality": "",
            "Integrity": "",
            "Availability": "",
            "Safety": ""
        }
        repo_threats_values_possible = {
            "Likelihood": "Possible",
            "Monetary": "",
            "Confidentiality": "",
            "Integrity": "",
            "Availability": "",
            "Safety": ""
        }
        repo_threats_values_rare = {
            "Likelihood": "Rare",
            "Monetary": "",
            "Confidentiality": "",
            "Integrity": "",
            "Availability": "",
            "Safety": ""
        }
        repo_threats_values_rare_2 = {
            "Likelihood": "Rare than Rare",
            "Monetary": "",
            "Confidentiality": "",
            "Integrity": "",
            "Availability": "",
            "Safety": ""
        }
        repo_threats_values_rare_3 = {
            "Likelihood": "Oddness 3 or higher",
            "Monetary": "",
            "Confidentiality": "",
            "Integrity": "",
            "Availability": "",
            "Safety": ""
        }
        for objective in these_objectives:
            value_low = risk_assessment_result["obj" + str(objective.id)].values[0]
            value_med = risk_assessment_result["obj" + str(objective.id)].values[1]
            value_high = risk_assessment_result["obj" + str(objective.id)].values[2]

            # print(objective.name)
            # print(value_low)
            # print(value_med)
            # print(value_high)
            if value_low < 0.00005:
                repo_threats_values_rare_3[objective.name] = repo_threats_values_rare_3[objective.name] + "Low" + "|"
                # print("---------------------------------------------1")
            elif value_low < 0.0005:
                repo_threats_values_rare_2[objective.name] = repo_threats_values_rare_2[objective.name] + "Low" + "|"
                # print("---------------------------------------------2")
            elif value_low < 0.10:
                repo_threats_values_rare[objective.name] = repo_threats_values_rare[objective.name] + "Low" + "|"
                # print("---------------------------------------------3")
            elif value_low < 0.50:
                repo_threats_values_possible[objective.name] = repo_threats_values_possible[
                                                                   objective.name] + "Low" + "|"
                # print("---------------------------------------------4")
            else:
                # print("---------------------------------------------5")
                repo_threats_values_certain[objective.name] = repo_threats_values_certain[objective.name] + "Low" + "|"

            if value_med < 0.00005:
                repo_threats_values_rare_3[objective.name] = repo_threats_values_rare_3[objective.name] + "med" + "|"
            elif value_med < 0.0005:
                repo_threats_values_rare_2[objective.name] = repo_threats_values_rare_2[objective.name] + "med" + "|"
            elif value_med < 0.10:
                repo_threats_values_rare[objective.name] = repo_threats_values_rare[objective.name] + "med" + "|"
            elif value_med < 0.50:
                repo_threats_values_possible[objective.name] = repo_threats_values_possible[
                                                                   objective.name] + "med" + "|"
            else:
                # print("============================================")
                repo_threats_values_certain[objective.name] = repo_threats_values_certain[objective.name] + "med" + "|"

            if value_high < 0.00005:
                repo_threats_values_rare_3[objective.name] = repo_threats_values_rare_3[objective.name] + "high"
            elif value_high < 0.0005:
                repo_threats_values_rare_2[objective.name] = repo_threats_values_rare_2[objective.name] + "high"
            elif value_high < 0.10:
                repo_threats_values_rare[objective.name] = repo_threats_values_rare[objective.name] + "high"
            elif value_high < 0.50:
                repo_threats_values_possible[objective.name] = repo_threats_values_possible[objective.name] + "high"
            else:
                # print("++++++++++++++++++++++++++++++++++++++++++++++")
                repo_threats_values_certain[objective.name] = repo_threats_values_certain[objective.name] + "high"

        repo_threats = [repo_threats_values_certain, repo_threats_values_possible, repo_threats_values_rare,
                        repo_threats_values_rare_2, repo_threats_values_rare_3]
        # print("==================================================")
        # print(repo_threats)
        # # print(value_med)
        # # print(value_low)
        # print("==================================================")
        # repo_threats_values_certain

    for key, value in risk_assessment_result.items():
        risk_assessment_result[key] = pd.DataFrame(value).to_html()
        # risk_assessment_result[key] = pd.DataFrame(value).to_html()

    # pd_results = pd.DataFrame(test_variable)
    # print(risk_assessment_result)
    return render_template('templates_dashboard/repo_risk_objectives_dashboard.html', repo_threats=repo_threats,
                           these_threats=these_threats, threat_id=threat_id, asset_id=asset_id,
                           these_responses=these_responses, risk_assessment_result=risk_assessment_result,
                           this_threat=this_threat, these_assets=these_assets, this_asset=this_asset,
                           this_exposure=this_exposure, these_materialisations=these_materialisations,
                           these_consequences=these_consequences, these_services=these_services,
                           these_impacts=these_impacts, these_objectives=these_objectives, these_utils=these_utils
                           )


@app.route('/repo/dashboard/vulnerability/', methods=['GET', 'POST'])
def repo_dashboard_vulnerability():
    if request.method == 'POST':
        return redirect("/repo/dashboard/vulnerability/")
    else:
        # assetsArray = get_assetsfromrepository()
        # if assetsArray != -1:
        #     return render_template('asset_dashboard.html', assets=assetsArray)
        # else:
        repo_vulnerabilities = [
            {
                "id": "1",
                "name": "1",
                "location": "1",
                "Verified": "1",
                "mac_address": "1",
                "ip": "1",
                "last_touch_date": "1",
            }
        ]
        print(repo_vulnerabilities)
        return render_template('templates_dashboard/repo_vulnerability_dashboard.html',
                               repo_vulnerabilities=repo_vulnerabilities)
