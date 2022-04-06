from flask import render_template, request, redirect, jsonify, Response, flash
from multiprocessing import Process

from sqlalchemy.exc import SQLAlchemyError

from app.producer import *
from app.globals import *
from app.utils import *
from app.forms import *
from app import app
from app.utils.utils_communication import send_risk_report
from app.utils.utils_database import convert_database_items_to_json_table
from app.utils.utils_risk_assessment import start_risk_assessment, risk_assessment_manual
import pandas as pd

from datetime import datetime, timedelta
from dateutil.relativedelta import relativedelta


@app.route('/repo/dashboard/asset/', methods=['GET', 'POST'])
def repo_dashboard_asset():
    if request.method == 'POST':
        return redirect("/repo/dashboard/asset/")
    else:
        # assetsArray = get_assetsfromrepository()
        # if assetsArray != -1:
        #     return render_template('asset_dashboard.html', assets=assetsArray)
        # else:

        # Get all asset types
        try:
            repo_assets_type = RepoAssetsType.query.all()
        except SQLAlchemyError:
            return Response("SQLAlchemyError", 500)

        try:
            repo_asset = RepoAsset.query.all()
        except SQLAlchemyError:
            return Response("SQLAlchemyError", 500)

        try:
            repo_asset_unverified = RepoAsset.query.filter_by(verified=False).all()
        except SQLAlchemyError:
            return Response("SQLAlchemyError", 500)

        # repo_asset = convert_database_items_to_json_table(repo_asset)
        repo_assets_type = convert_database_items_to_json_table(repo_assets_type)

        # Create dict of asset types so we can count all assets types and put values in appropriate order
        dict_assets_type = {}
        dict_assets_verified = {"verified": 0, "unverified": 0}
        dict_assets_services = {}
        for type_object in repo_assets_type:
            dict_assets_type[type_object['name']] = 0

        for type_asset in repo_asset:
            # Count asset types
            dict_assets_type[type_asset.type.name] = dict_assets_type[type_asset.type.name] + 1

            # Count verified assets
            if type_asset.verified:
                dict_assets_verified["verified"] += 1
            else:
                dict_assets_verified["unverified"] += 1

            # Count services per asset
            dict_assets_services[str(type_asset.name or "no_name") + "|" + str(type_asset.ip or "no_ip")] = 0
            for service_type in type_asset.services:
                dict_assets_services[str(type_asset.name or "no_name") + "|" + str(type_asset.ip or "no_ip")] += 1

                # dict_assets_verified[type_asset.verified]
        # Transfer data to list that can be displayed by front end technology
        asset_type_values_list = list(dict_assets_type.values())
        asset_types_list = list(dict_assets_type.keys())
        assets_verified_list = list(dict_assets_verified.values())
        assets_services_counted_list = list(dict_assets_services.values())
        assets_name_list = list(dict_assets_services.keys())

        for it, assets_name_list_instance in enumerate(assets_name_list):
            if assets_name_list_instance is None:
                assets_name_list[it] = "No_name"

        # print("-----------------------------------------------------", assets_name_list)
        # for asset in repo_asset:
        # print(asset_type_values_list)
        # print(asset_types_list)

        # repo_assets_type = json.dumps(repo_assets_type)

        repo_asset_unverified_dict = convert_database_items_to_json_table(repo_asset_unverified)
        # Add new columns for type and subytpe to de displayed in table
        # Uses both the object and converted dict list for ease of access
        for index, json_asset_instance in enumerate(repo_asset_unverified_dict):
            json_asset_instance["subtype"] = repo_asset_unverified[index].type.name
            json_asset_instance["type"] = repo_asset_unverified[index].type.variety.name

        repo_asset_unverified = json.dumps(repo_asset_unverified_dict)
        return render_template('templates_dashboard/repo_asset_dashboard.html',
                               repo_asset_unverified=repo_asset_unverified,
                               asset_type_values_list=asset_type_values_list, asset_types_list=asset_types_list,
                               assets_verified_list=assets_verified_list, assets_name_list=assets_name_list,
                               assets_services_counted_list=assets_services_counted_list)


@app.route('/repo/dashboard/threat/', methods=['GET', 'POST'])
def repo_dashboard_threat():
    if request.method == 'POST':
        return redirect("/repo/dashboard/threat/")
    else:

        repo_threats = [
            {
                "id": "1",
                "name": "1",
                "capec": "1",
                "cwe": "1"
            }
        ]
        # print(repo_threats)
        return render_template('templates_dashboard/repo_threat_dashboard.html', repo_threats=repo_threats,
                               )


@app.route('/repo/dashboard/risk/objectives/threat/<threat_id>/asset/<asset_id>/', methods=['GET', 'POST'])
@app.route('/repo/dashboard/risk/objectives/threat/<threat_id>/asset/<asset_id>/assessment/<report_id>/',
           methods=['GET', 'POST'])
# @app.route('/repo/dashboard/risk/objectives/threat/<threat_id>/asset/<asset_id>/', methods=['GET', 'POST'])
def repo_dashboard_risk_objectives(threat_id=1, asset_id=-1, report_id=-1):
    if request.method == 'POST':
        results = request.form
        # print("NEW FORM IS-------------------")
        # print(results)

        exposures_set = []
        materialisations_set = []
        responses_set = []
        consequences_set = []
        services_set = []
        impacts_set = []
        objectives_set = []

        exposures_set_string = ""
        materialisations_set_string = ""
        responses_set_string = ""
        consequences_set_string = ""
        services_set_string = ""
        impacts_set_string = ""
        objectives_set_string = ""

        for key, value in request.form.items():
            # print("KEY IS")
            # print(key)
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
            elif temp_key == "re":
                # Decision Nodes not working currently
                responses_set.append({"id": temp_digit, "value": value})
                responses_set_string = responses_set_string + str(temp_digit) + "|" + str(
                    value) + "|"
            elif temp_key == "con":
                consequences_set.append({"id": temp_digit, "value": value})
                consequences_set_string = consequences_set_string + str(temp_digit) + "|" + str(
                    value) + "|"
            elif temp_key == "serv":
                services_set.append({"id": temp_digit, "value": value})
                services_set_string = services_set_string + str(temp_digit) + "|" + str(
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

        # print("----------------Strings------------------")
        # print(exposures_set)
        # print(exposures_set_string)
        # print(materialisations_set)
        # print(materialisations_set_string)
        # print(responses_set)
        # print(responses_set_string)
        # print(consequences_set)
        # print(consequences_set_string)
        # print(services_set)
        # print(services_set_string)
        # print(impacts_set)
        # print(impacts_set_string)
        # print(objectives_set)
        # print(objectives_set_string)

        risk_assessment_result = risk_assessment_manual(threat_id, asset_id, exposures_set, materialisations_set,
                                                        responses_set,
                                                        consequences_set,
                                                        services_set,
                                                        impacts_set, objectives_set)

        # print(risk_assessment_result)
        # print(type(risk_assessment_result))

        exposure_inference = ""
        materialisations_inference = ""
        consequences_inference = ""
        services_inference = ""
        impacts_inference = ""
        objectives_inference = ""

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
            services_set=services_set_string,
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
        send_risk_report(manual_risk_assessment.id, asset_id, threat_id)
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

        # Select assets that have active risk assessments with this threat
        try:
            these_assets = RepoAsset.query.filter(
                RepoAsset.risk_assessment.any(RepoRiskAssessment.repo_threat_id == threat_id)).all()
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
        this_risk_assessment = None

        repo_threats = []
        json_reports = ""
        these_responses = []
        risk_assessment_result = []
        if int(threat_id) != -1 and int(asset_id) != -1:
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

            if report_id != -1:
                try:
                    this_risk_assessment = RepoRiskAssessmentReports.query.filter_by(id=report_id).all()
                except SQLAlchemyError:
                    return "SQLAlchemyError"
            else:
                try:
                    this_risk_assessment = RepoRiskAssessmentReports.query.filter(
                        RepoRiskAssessmentReports.risk_assessment.has(repo_asset_id=asset_id,
                                                                      repo_threat_id=threat_id)).all()
                except SQLAlchemyError as er:
                    print(er)
                    return "SQLAlchemyError"
                # print(this_risk_assessment)
                report_id = this_risk_assessment[0].id

            this_exposure = convert_database_items_to_json_table(this_exposure)
            these_responses = convert_database_items_to_json_table(these_responses)
            these_materialisations = convert_database_items_to_json_table(these_materialisations)
            these_consequences = convert_database_items_to_json_table(these_consequences)
            these_services = convert_database_items_to_json_table(these_services)
            these_impacts = convert_database_items_to_json_table(these_impacts)
            these_objectives = convert_database_items_to_json_table(these_objectives)
            these_utils = convert_database_items_to_json_table(these_utils)
            this_risk_assessment = convert_database_items_to_json_table(this_risk_assessment)
            # print("-------------------- RETRIEVED RISK ASSESSMENT IS -------------------------")
            # print(this_risk_assessment)
            # print("---DASHBOARD DATA IS---")
            # print(this_risk_assessment)
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
            risk_assessment_result = start_risk_assessment(threat_id, asset_id)

            # CONVERT RESULTS SAVED IN DATABASE TO FORMAT PRODUCED BY START RISK ASSESSMENT function

            if report_id != -1:
                new_risk_assessment_result = {}
                # print("--------------ACTUAL-----------")
                # print(this_risk_assessment)
                # print(type())
                # print(this_risk_assessment[0]["exposure_inference"])
                exposure_inference_values = this_risk_assessment[0]["exposure_inference"].split("|")
                materialisation_inference_values = this_risk_assessment[0]["materialisations_inference"].split("|")
                consequence_inference_values = this_risk_assessment[0]["consequences_inference"].split("|")
                impact_inference_values = this_risk_assessment[0]["impacts_inference"].split("|")
                services_inference_values = this_risk_assessment[0]["services_inference"].split("|")
                objectives_inference_values = this_risk_assessment[0]["objectives_inference"].split("|")
                utility_inference_values = this_risk_assessment[0]["utilities_inference"].split("|")
                alerts_triggered = this_risk_assessment[0]["alerts_triggered"].split("|")

                # Exposure
                new_risk_assessment_result["te" + exposure_inference_values[0]] = pd.Series(
                    data={"Threat Doesnt Happen": exposure_inference_values[1],
                          "Threat Happens": exposure_inference_values[2]}).to_frame()

                # Materialisation
                new_risk_assessment_result["mat" + materialisation_inference_values[0]] = pd.Series(
                    data={"Materialsiation Doesnt Happen": materialisation_inference_values[1],
                          "Materialisation Happens": materialisation_inference_values[2]}).to_frame()

                # Consequences
                num_consequences = len(consequence_inference_values)
                for it in range(0, num_consequences - 1, 3):
                    new_risk_assessment_result["con" + consequence_inference_values[it]] = pd.Series(
                        data={"Consequence Doesnt Happen": consequence_inference_values[it + 1],
                              "Consequence Happens": consequence_inference_values[it + 2]}).to_frame()

                # Services
                num_services = len(services_inference_values)
                for it in range(0, num_services - 1, 3):
                    new_risk_assessment_result["serv" + services_inference_values[it]] = pd.Series(
                        data={"Consequence Doesnt Happen": services_inference_values[it + 1],
                              "Consequence Happens": services_inference_values[it + 2]}).to_frame()

                # Impacts
                new_risk_assessment_result["imp" + impact_inference_values[0]] = pd.Series(
                    data={"Low": impact_inference_values[1],
                          "Medium": impact_inference_values[2],
                          "High": impact_inference_values[3],
                          }).to_frame()

                new_risk_assessment_result["imp" + impact_inference_values[4]] = pd.Series(
                    data={"Low": impact_inference_values[5],
                          "Medium": impact_inference_values[6],
                          "High": impact_inference_values[7],
                          }).to_frame()

                new_risk_assessment_result["imp" + impact_inference_values[8]] = pd.Series(
                    data={"Low": impact_inference_values[9],
                          "Medium": impact_inference_values[10],
                          "High": impact_inference_values[11],
                          }).to_frame()

                new_risk_assessment_result["imp" + impact_inference_values[12]] = pd.Series(
                    data={"Low": impact_inference_values[13],
                          "Medium": impact_inference_values[14],
                          "High": impact_inference_values[15],
                          }).to_frame()

                new_risk_assessment_result["imp" + impact_inference_values[16]] = pd.Series(
                    data={"Low": impact_inference_values[17],
                          "Medium": impact_inference_values[18],
                          "High": impact_inference_values[19],
                          }).to_frame()

                new_risk_assessment_result["imp" + impact_inference_values[20]] = pd.Series(
                    data={"Low": impact_inference_values[21],
                          "Medium": impact_inference_values[22],
                          "High": impact_inference_values[23],
                          }).to_frame()

                # Objectives
                new_risk_assessment_result["obj" + objectives_inference_values[0]] = pd.Series(
                    data={"Low": objectives_inference_values[1],
                          "Medium": objectives_inference_values[2],
                          "High": objectives_inference_values[3],
                          }).to_frame()

                new_risk_assessment_result["obj" + objectives_inference_values[4]] = pd.Series(
                    data={"Low": objectives_inference_values[5],
                          "Medium": objectives_inference_values[6],
                          "High": objectives_inference_values[7],
                          }).to_frame()

                new_risk_assessment_result["obj" + objectives_inference_values[8]] = pd.Series(
                    data={"Low": objectives_inference_values[9],
                          "Medium": objectives_inference_values[10],
                          "High": objectives_inference_values[11],
                          }).to_frame()

                new_risk_assessment_result["obj" + objectives_inference_values[12]] = pd.Series(
                    data={"Low": objectives_inference_values[13],
                          "Medium": objectives_inference_values[14],
                          "High": objectives_inference_values[15],
                          }).to_frame()

                new_risk_assessment_result["obj" + objectives_inference_values[16]] = pd.Series(
                    data={"Low": objectives_inference_values[17],
                          "Medium": objectives_inference_values[18],
                          "High": objectives_inference_values[19],
                          }).to_frame()

                risk_assessment_result = new_risk_assessment_result
                # to_print = pd.DataFrame(
                #             {
                #                 str(exposure_inference_values[0]) : exposure_inference_values[1],
                #                 str(exposure_inference_values[0]) : exposure_inference_values[2]
                #             }
                #         )
                # print(to_print)

                # temp_exposure_df = {
                #     "te"+str(exposure_inference_values) : pd.DataFrame(
                #         {
                #             str(exposure_inference_values[0]) : exposure_inference_values[1],
                #             str(exposure_inference_values[0]) : exposure_inference_values[2]
                #         }
                #     )
                # }
                # print("--------------ACTUAL-----------")
                #
                # print("--------------NEW ACTUAL-----------")
                # # print(temp_exposure_df)
                # print("--------------NEW ACTUAL-----------")
                #
                # print("--------------RESSSSSSSSSSSSSSUUUUUUUUUUUUUUUUUUULLLLLLLLLLLLLLLLLTTTTTTTTT-----------")
                # print(risk_assessment_result)
                real_te12 = risk_assessment_result["te12"]
                # print(real_te12)
                # print(real_te12.get(key="te12"))
                # print(type(real_te12.get([0])))
                # print(real_te12.get([1]))
                # print(type(real_te12.get([1])))

                temp_pre_series = {0: 0.678, 1: 0.322}

                # temp_pre_series = {"te12": ["0", 0.678], "te12" :["1" ,0.322]}
                # temp_pre_series = {"te12": [0.678,0.322]}
                temp_series = pd.Series(data=temp_pre_series)
                temp_series = pd.DataFrame(temp_series.to_frame()).to_html()
                # temp_series = {"te12": temp_series}
                actual_temp = pd.Series(data=temp_series)
                # print("TEMPSERIES IS")
                # print(actual_temp)
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
            # print(risk_assessment_result)
            for objective in these_objectives:

                # Due to differences between the values loaded from report and default risk assessment need different call
                if report_id == -1:
                    value_low = risk_assessment_result["obj" + str(objective.id)].values[0]
                    value_med = risk_assessment_result["obj" + str(objective.id)].values[1]
                    value_high = risk_assessment_result["obj" + str(objective.id)].values[2]
                else:
                    value_low = json.loads(risk_assessment_result["obj" + str(objective.id)].values[0][0])
                    value_med = json.loads(risk_assessment_result["obj" + str(objective.id)].values[1][0])
                    value_high = json.loads(risk_assessment_result["obj" + str(objective.id)].values[2][0])

                # print(objective.name)
                # print(value_low)
                # print(value_med)
                # print(value_high)
                if value_low < 0.00005:
                    repo_threats_values_rare_3[objective.name] = repo_threats_values_rare_3[
                                                                     objective.name] + "Low" + "|"
                    # print("---------------------------------------------1")
                elif value_low < 0.0005:
                    repo_threats_values_rare_2[objective.name] = repo_threats_values_rare_2[
                                                                     objective.name] + "Low" + "|"
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
                    repo_threats_values_certain[objective.name] = repo_threats_values_certain[
                                                                      objective.name] + "Low" + "|"

                if value_med < 0.00005:
                    repo_threats_values_rare_3[objective.name] = repo_threats_values_rare_3[
                                                                     objective.name] + "med" + "|"
                elif value_med < 0.0005:
                    repo_threats_values_rare_2[objective.name] = repo_threats_values_rare_2[
                                                                     objective.name] + "med" + "|"
                elif value_med < 0.10:
                    repo_threats_values_rare[objective.name] = repo_threats_values_rare[objective.name] + "med" + "|"
                elif value_med < 0.50:
                    repo_threats_values_possible[objective.name] = repo_threats_values_possible[
                                                                       objective.name] + "med" + "|"
                else:
                    # print("============================================")
                    repo_threats_values_certain[objective.name] = repo_threats_values_certain[
                                                                      objective.name] + "med" + "|"

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

            try:
                repo_reports = RepoRiskAssessmentReports.query.filter(
                    RepoRiskAssessmentReports.risk_assessment.has(repo_asset_id=asset_id,
                                                                  repo_threat_id=threat_id)).all()
            except SQLAlchemyError:
                return Response("SQLAlchemyError", 500)
                # print("------------------------------")
                # print(repo_actors, flush=True)
                #
                # print(repo_actors[0].__table__.columns._data.keys(), flush=True)
            # print(repo_reports)
            json_reports = convert_database_items_to_json_table(repo_reports)
            json_detailed_reports = []
            custom_it = 0
            for each_report in repo_reports:
                # print("Example ARE --------")
                # print(json_reports[custom_it])
                #  Add basic info to dashboard
                actual_risk_assessment = each_report.risk_assessment
                json_reports[custom_it]["asset_name"] = actual_risk_assessment.asset.name
                json_reports[custom_it]["asset_ip"] = actual_risk_assessment.asset.ip
                json_reports[custom_it]["threat_name"] = actual_risk_assessment.threat.name
                # print(each_report)

                # Create detailed report jsons
                json_detailed_report_to_add = {}
                json_detailed_report_to_add["type"] = each_report.type
                json_detailed_report_to_add["date_time"] = each_report.date_time.strftime("%m/%d/%Y, %H:%M:%S")
                materialisations_list = each_report.materialisations_inference.split("|")
                materialisations_list.pop()
                # print(materialisations_list)
                json_detailed_report_to_add["materialisations"] = []

                for custom_it_mat in range(0, len(materialisations_list), 3):
                    this_mat_name = RepoMaterialisation.query.filter_by(
                        id=materialisations_list[custom_it_mat]).first().name
                    json_detailed_report_to_add["materialisations"].append(
                        {"name": this_mat_name, "occurs": materialisations_list[custom_it_mat + 1],
                         "Nothing": materialisations_list[custom_it_mat + 2]})

                # json_detailed_report_to_add["date_time"].strftime("%m/%d/%Y, %H:%M:%S")
                json_reports[custom_it]["detailed"] = json_detailed_report_to_add
                custom_it = custom_it + 1

            # print(json_reports)
            for each_report in json_reports:
                each_report["date_time"] = each_report["date_time"].strftime("%m/%d/%Y, %H:%M:%S")
            # print("==============================================")
            # print(json_reports)
            json_reports = json.dumps(json_reports)

        # existing_report_data = {
        # }
        # if assessment_id != -1:

        # pd_results = pd.DataFrame(test_variable)
        # print(risk_assessment_result)
        return render_template('templates_dashboard/repo_risk_objectives_dashboard.html', repo_threats=repo_threats,
                               these_threats=these_threats, threat_id=threat_id, asset_id=asset_id,
                               repo_reports=json_reports, report_id=report_id,
                               this_risk_assessment=this_risk_assessment,
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
        try:
            repo_assets_type = RepoAssetsType.query.all()
        except SQLAlchemyError:
            return Response("SQLAlchemyError", 500)

        try:
            repo_assets = RepoAsset.query.all()
        except SQLAlchemyError:
            return Response("SQLAlchemyError", 500)

        try:
            repo_vulnerabilities = VulnerabilityReportVulnerabilitiesLink.query.all()
        except SQLAlchemyError:
            return Response("SQLAlchemyError", 500)

        dict_assets_type = {}

        # For vuln occurance we only care about associated CVE ids
        dict_vulnerabilities_occurrence = {}

        # Set entries for all asset types regardless if they have any associated vulnerabilties or not
        for asset_type_object in repo_assets_type:
            dict_assets_type[asset_type_object.name] = 0

        vulnerability_months_list_values = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        already_used_asset_vulnerabilities = []

        for vulnerability_object in repo_vulnerabilities:
            # Count asset types
            # print(vulnerability_object.asset)
            dict_assets_type[vulnerability_object.asset.type.name] += 1
            # print(vulnerability_object.cve.CVEId)
            # print(dict_vulnerabilities_occurrence)
            if vulnerability_object.cve.CVEId:
                if vulnerability_object.cve.CVEId in dict_vulnerabilities_occurrence:
                    dict_vulnerabilities_occurrence[vulnerability_object.cve.CVEId] += 1
                else:
                    dict_vulnerabilities_occurrence[vulnerability_object.cve.CVEId] = 1

            # Gather data for timeline vulnerarbilities
            time_since_insertion = datetime.now() - vulnerability_object.date
            # print("Timedelta is: ", time_since_insertion.resolution.days)
            if time_since_insertion.resolution.days < 365:
                used_asset_log = {"asset": vulnerability_object.asset_id, "vulnerability": vulnerability_object.cve_id}
                if used_asset_log in already_used_asset_vulnerabilities:
                    continue
                else:
                    already_used_asset_vulnerabilities.append(used_asset_log)
                    vulnerability_months_list_values[vulnerability_object.date.month - 1] += 1

        # for vulnerability_object in repo_vulnerabilities:

        # Get List of month starting from this month
        now = datetime.now()
        vulnerability_months_list = [(now + relativedelta(months=i)).strftime('%b') for i in range(12)]

        # print(vulnerability_months_list)

        asset_types_list = list(dict_assets_type.keys())
        asset_types_vulnerability_occurrence = list(dict_assets_type.values())
        # Remove entries with no value
        custom_it = 0
        while custom_it < len(asset_types_list):
            if asset_types_vulnerability_occurrence[custom_it] == 0:
                asset_types_list.pop(custom_it)
                asset_types_vulnerability_occurrence.pop(custom_it)
            else:
                custom_it += 1

        vulnerability_cve_id_list = list(dict_vulnerabilities_occurrence.keys())
        vulnerability_cve_id_occurrence = list(dict_vulnerabilities_occurrence.values())
        # Get only the first 10 of the list for this visualisation
        vulnerability_cve_id_list = vulnerability_cve_id_list[:10]
        vulnerability_cve_id_occurrence = vulnerability_cve_id_occurrence[:10]

        repo_assets = convert_database_items_to_json_table(repo_assets)
        repo_assets = json.dumps(repo_assets)
        # print("--------- Vuln Dashboard Data is -----------")
        # print(asset_types_list)
        # print(asset_types_vulnerability_occurrence)
        # print(repo_assets)
        return render_template('templates_dashboard/repo_vulnerability_dashboard.html',
                               repo_assets=repo_assets,
                               asset_types_vulnerability_occurrence=asset_types_vulnerability_occurrence,
                               vulnerability_months_list=vulnerability_months_list,
                               vulnerability_months_list_values=vulnerability_months_list_values,
                               asset_types_list=asset_types_list, vulnerability_cve_id_list=vulnerability_cve_id_list,
                               vulnerability_cve_id_occurrence=vulnerability_cve_id_occurrence)


@app.route('/repo/dashboard/risk/history/threat/<threat_id>/asset/<asset_id>/', methods=['GET', 'POST'])
@app.route('/repo/dashboard/risk/history/threat/<threat_id>/asset/<asset_id>/type/<type_id>/', methods=['GET', 'POST'])
# @app.route('/repo/dashboard/risk/events/threat/<threat_id>/asset/<asset_id>/report/<report_id>', methods=['GET', 'POST'])
# @app.route('/repo/dashboard/risk/objectives/threat/<threat_id>/asset/<asset_id>/', methods=['GET', 'POST'])
def repo_dashboard_risk_history(threat_id=1, asset_id=-1,type_id=-1):
    """ type_id : -1 ALL  | 1 Baseline | 2 Incidents | 3 Secondary Incidents"""
    if request.method == 'POST':
        pass
    else:
        # assetsArray = get_assetsfromrepository()
        # if assetsArray != -1:
        #     return render_template('asset_dashboard.html', assets=assetsArray)
        # else:
        # try:
        #     these_threats = RepoThreat.query.all()
        # except SQLAlchemyError:
        #     return Response("SQLAlchemyError", 500)
        #
        # # Select assets that have active risk assessments with this threat
        # try:
        #     these_assets = RepoAsset.query.filter(RepoAsset.risk_assessment.any(RepoRiskAssessment.repo_threat_id == threat_id)).all()
        # except SQLAlchemyError:
        #     return Response("SQLAlchemyError", 500)

        try:
            these_threats = RepoThreat.query.all()
        except SQLAlchemyError:
            return Response("SQLAlchemyError", 500)

        # Select assets that have active risk assessments with this threat
        try:
            these_assets = RepoAsset.query.filter(
                RepoAsset.risk_assessment.any(RepoRiskAssessment.repo_threat_id == threat_id)).all()
        except SQLAlchemyError:
            return Response("SQLAlchemyError", 500)
        try:
            this_threat = RepoThreat.query.filter_by(id=threat_id).all()
        except SQLAlchemyError:
            return Response("SQLAlchemyError", 500)

        this_threat = convert_database_items_to_json_table(this_threat)
        these_threats = convert_database_items_to_json_table(these_threats)
        these_assets = convert_database_items_to_json_table(these_assets)

        # this_exposure = []
        # these_materialisations = []
        # these_consequences = []
        # these_services = []
        # these_impacts = []

        # these_utils = []
        # this_risk_assessment = None

        # repo_threats = []
        # json_reports = ""
        # these_responses = []
        # risk_assessment_result = []

        all_objectives_confidentiality_low = []
        all_objectives_confidentiality_med = []
        all_objectives_confidentiality_high = []
        all_objectives_integrity_low = []
        all_objectives_integrity_med = []
        all_objectives_integrity_high = []
        all_objectives_availability_low = []
        all_objectives_availability_med = []
        all_objectives_availability_high = []
        all_objectives_monetary_low = []
        all_objectives_monetary_med = []
        all_objectives_monetary_high = []
        all_objectives_safety_low = []
        all_objectives_safety_med = []
        all_objectives_safety_high = []
        all_reports_datetimes = []
        all_reports_utilities_optimal_1 = []
        all_reports_utilities_optimal_2 = []
        json_reports=None
        this_asset=None
        type_display = ""
        if int(threat_id) != -1 and int(asset_id) != -1:
            try:
                this_asset = RepoAsset.query.filter_by(id=asset_id).all()
            except SQLAlchemyError:
                return Response("SQLAlchemyError", 500)

            # Get reports for tables
            if str(type_id) == str(-1):
                try:
                    repo_reports = RepoRiskAssessmentReports.query.filter(
                        RepoRiskAssessmentReports.risk_assessment.has(repo_asset_id=asset_id,
                                                                      repo_threat_id=threat_id)).all()
                except SQLAlchemyError:
                    return Response("SQLAlchemyError", 500)
                type_display = "All"
            elif str(type_id) == str(1):
                try:
                    repo_reports = RepoRiskAssessmentReports.query.filter(RepoRiskAssessmentReports.type == "baseline").filter(
                        RepoRiskAssessmentReports.risk_assessment.has(repo_asset_id=asset_id,
                                                                      repo_threat_id=threat_id,)).all()
                except SQLAlchemyError:
                    return Response("SQLAlchemyError", 500)
                type_display = "Baseline"
            elif str(type_id) == str(2):
                try:
                    repo_reports = RepoRiskAssessmentReports.query.filter(RepoRiskAssessmentReports.type == "incident").filter(
                        RepoRiskAssessmentReports.risk_assessment.has(repo_asset_id=asset_id,
                                                                      repo_threat_id=threat_id)).all()
                except SQLAlchemyError:
                    return Response("SQLAlchemyError", 500)
                type_display = "Incident"
            elif str(type_id) == str(3):
                try:
                    repo_reports = RepoRiskAssessmentReports.query.filter(RepoRiskAssessmentReports.type == "incident_secondary").filter(
                        RepoRiskAssessmentReports.risk_assessment.has(repo_asset_id=asset_id,
                                                                      repo_threat_id=threat_id )).all()
                except SQLAlchemyError:
                    return Response("SQLAlchemyError", 500)
                type_display = "Incident Secondary"

            # print("_++_+_+_+_+_+_++")
            # print(type_id)
            for single_report in repo_reports:
                # Add labels for the graphs
                all_reports_datetimes.append(single_report.date_time.strftime("%m/%d/%Y, %H:%M:%S") + " | " + single_report.type)

                objectives_inference_values = single_report.objectives_inference.split("|")

                all_objectives_confidentiality_low.append(objectives_inference_values[1])
                all_objectives_confidentiality_med.append(objectives_inference_values[2])
                all_objectives_confidentiality_high.append(objectives_inference_values[3])
                all_objectives_integrity_low.append(objectives_inference_values[5])
                all_objectives_integrity_med.append(objectives_inference_values[6])
                all_objectives_integrity_high.append(objectives_inference_values[7])
                all_objectives_availability_low.append(objectives_inference_values[9])
                all_objectives_availability_med.append(objectives_inference_values[10])
                all_objectives_availability_high.append(objectives_inference_values[11])
                all_objectives_monetary_low.append(objectives_inference_values[13])
                all_objectives_monetary_med.append(objectives_inference_values[14])
                all_objectives_monetary_high.append(objectives_inference_values[15])
                all_objectives_safety_low.append(objectives_inference_values[17])
                all_objectives_safety_med.append(objectives_inference_values[18])
                all_objectives_safety_high.append(objectives_inference_values[19])

                utility_inference_values = single_report.utilities_inference.split("|")

                all_reports_utilities_optimal_1.append(json.loads(utility_inference_values[0])["optimal_scenario"]["probability"])
                all_reports_utilities_optimal_2.append(json.loads(utility_inference_values[2])["optimal_scenario"]["probability"])
                # print("------------------------------")
                # print(repo_actors, flush=True)
                #
                # print(repo_actors[0].__table__.columns._data.keys(), flush=True)
            # print(repo_reports)
            json_reports = convert_database_items_to_json_table(repo_reports)
            json_detailed_reports = []
            custom_it = 0
            for each_report in repo_reports:
                # print("Example ARE --------")
                # print(json_reports[custom_it])
                #  Add basic info to dashboard
                actual_risk_assessment = each_report.risk_assessment
                json_reports[custom_it]["asset_name"] = actual_risk_assessment.asset.name
                json_reports[custom_it]["asset_ip"] = actual_risk_assessment.asset.ip
                json_reports[custom_it]["threat_name"] = actual_risk_assessment.threat.name
                # print(each_report)

                # Create detailed report jsons
                json_detailed_report_to_add = {}
                json_detailed_report_to_add["type"] = each_report.type
                json_detailed_report_to_add["date_time"] = each_report.date_time.strftime("%m/%d/%Y, %H:%M:%S")
                materialisations_list = each_report.materialisations_inference.split("|")
                materialisations_list.pop()
                # print(materialisations_list)
                json_detailed_report_to_add["materialisations"] = []

                for custom_it_mat in range(0, len(materialisations_list), 3):
                    this_mat_name = RepoMaterialisation.query.filter_by(
                        id=materialisations_list[custom_it_mat]).first().name
                    json_detailed_report_to_add["materialisations"].append(
                        {"name": this_mat_name, "occurs": materialisations_list[custom_it_mat + 1],
                         "Nothing": materialisations_list[custom_it_mat + 2]})

                # json_detailed_report_to_add["date_time"].strftime("%m/%d/%Y, %H:%M:%S")
                json_reports[custom_it]["detailed"] = json_detailed_report_to_add
                custom_it = custom_it + 1

            # print(json_reports)
            for each_report in json_reports:
                each_report["date_time"] = each_report["date_time"].strftime("%m/%d/%Y, %H:%M:%S")
            # print("==============================================")
            # print(json_reports)
            json_reports = json.dumps(json_reports)

        # existing_report_data = {
        # }
        # if assessment_id != -1:

        # pd_results = pd.DataFrame(test_variable)
        # print(risk_assessment_result)
        return render_template('templates_dashboard/repo_risk_history_dashboard.html',
                               these_threats=these_threats, threat_id=threat_id, asset_id=asset_id,
                               repo_reports=json_reports, type_id=type_id, type_display=type_display,
                               this_threat=this_threat, these_assets=these_assets, this_asset=this_asset,
                               all_objectives_confidentiality_low=all_objectives_confidentiality_low,
                               all_objectives_confidentiality_med=all_objectives_confidentiality_med,
                               all_objectives_confidentiality_high=all_objectives_confidentiality_high,
                               all_objectives_integrity_low=all_objectives_integrity_low,
                               all_objectives_integrity_med=all_objectives_integrity_med,
                               all_objectives_integrity_high=all_objectives_integrity_high,
                               all_objectives_availability_low=all_objectives_availability_low,
                               all_objectives_availability_med=all_objectives_availability_med,
                               all_objectives_availability_high=all_objectives_availability_high,
                               all_objectives_monetary_low=all_objectives_monetary_low,
                               all_objectives_monetary_med=all_objectives_monetary_med,
                               all_objectives_monetary_high=all_objectives_monetary_high,
                               all_objectives_safety_low=all_objectives_safety_low,
                               all_objectives_safety_med=all_objectives_safety_med,
                               all_objectives_safety_high=all_objectives_safety_high,
                               all_reports_datetimes=all_reports_datetimes,
                               all_reports_utilities_optimal_1=all_reports_utilities_optimal_1,
                               all_reports_utilities_optimal_2=all_reports_utilities_optimal_2
                               )
