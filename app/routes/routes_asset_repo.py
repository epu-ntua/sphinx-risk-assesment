from flask import render_template, request, redirect, jsonify, Response, flash
from multiprocessing import Process
from app.producer import *
from app.globals import *
# from app.utils import *
from app.utils.utils_database import *
# from app.utils.utils_communication import *
from app.forms import *
from app import app
import ast
from sqlalchemy.exc import SQLAlchemyError
from app.utils.utils_3rd_party_data_handling import v_report


@app.route('/repo/assets/', methods=['GET', 'POST'])
@app.route('/repo/assets/<asset_id>/', methods=['GET', 'POST'])
def view_repo_assets(asset_id=-1):
    if request.method == 'POST':
        new_asset_form = FormAddRepoAsset()
        new_edit_form = FormEditRepoAsset()

        # If edit form has been submitted
        # Distinction can only be made by the id of the submit button
        if 'edit_submit' in request.form:
            if new_edit_form.validate_on_submit():
                print("PUT ACTOR", "|", new_edit_form.edit_id.data, "|", flush=True)

                try:
                    to_edit_asset = RepoAsset.query.filter_by(id=new_edit_form.edit_id.data).first()
                except SQLAlchemyError:
                    return Response("SQLAlchemyError when editing records", 500)

                edit_owner_id = None
                edit_verified_by_id = None
                edit_net_group_fk_id = None
                edit_type_fk_id = None
                edit_verified = None
                edit_static_ip = None

                if new_edit_form.edit_owner.data:
                    edit_owner_id = new_edit_form.edit_owner.data.id

                if new_edit_form.edit_type_fk.data:
                    edit_type_fk_id = new_edit_form.edit_type_fk.data.id

                if new_edit_form.edit_verified_by.data:
                    edit_verified_by_id = new_edit_form.edit_verified_by.data.id

                if new_edit_form.edit_net_group_fk.data:
                    edit_net_group_fk_id = new_edit_form.edit_net_group_fk.data.id

                if new_edit_form.edit_verified:
                    # print("I Go HERE ", new_edit_form.edit_verified.data)
                    if new_edit_form.edit_verified.data:
                        edit_verified = 1
                    else:
                        edit_verified = 0

                if new_edit_form.edit_has_static_ip:
                    # print("I Go HERE ", new_edit_form.edit_verified.data)
                    if new_edit_form.edit_has_static_ip.data:
                        edit_static_ip = 1
                    else:
                        edit_static_ip = 0

                if RepoService.query.filter(RepoService.assets.any(id=to_edit_asset.id)).count() > 0:
                    value_weight = RepoService.query.filter(RepoService.assets.any(id=to_edit_asset.id)).count()
                    value_calculations = value_weight * (int(new_edit_form.edit_loss_of_revenue.data) + int(new_edit_form.edit_additional_expenses.data) + \
                                int(new_edit_form.edit_security_levels.data) + int(new_edit_form.edit_integrity.data) + \
                                int(new_edit_form.edit_availability.data) + int(new_edit_form.edit_confidentiality.data))
                    final_value = 1 if value_calculations <= 6 else 2 if value_calculations <= 8 else 3
                else:
                    final_value = None

                # print(new_edit_form.edit_verified)
                # print("----------here--------------")
                to_edit_asset.name = new_edit_form.edit_name.data
                to_edit_asset.description = new_edit_form.edit_description.data
                to_edit_asset.owner = edit_owner_id
                to_edit_asset.location = new_edit_form.edit_location.data
                to_edit_asset.verified = edit_verified
                to_edit_asset.verified_by = edit_verified_by_id
                to_edit_asset.mac_address = new_edit_form.edit_mac_address.data
                to_edit_asset.has_static_ip = edit_static_ip
                to_edit_asset.ip = new_edit_form.edit_ip.data
                to_edit_asset.net_group_fk = edit_net_group_fk_id
                to_edit_asset.value = final_value
                to_edit_asset.loss_of_revenue = new_edit_form.edit_loss_of_revenue.data
                to_edit_asset.additional_expenses = new_edit_form.edit_additional_expenses.data
                to_edit_asset.security_levels = new_edit_form.edit_security_levels.data
                to_edit_asset.customer_service = new_edit_form.edit_customer_service.data
                to_edit_asset.operating_zone = new_edit_form.edit_operating_zone.data
                to_edit_asset.last_touch_date = new_edit_form.edit_last_touch_date.data
                to_edit_asset.type_fk = edit_type_fk_id
                to_edit_asset.integrity = new_edit_form.edit_integrity.data
                to_edit_asset.availability = new_edit_form.edit_availability.data
                to_edit_asset.confidentiality = new_edit_form.edit_confidentiality.data
                to_edit_asset.current_status = new_edit_form.edit_current_status.data

                db.session.commit()
                return redirect("/repo/assets/")
            else:
                # If error in validation, then error
                print(new_edit_form.errors)
                flash('Error: Validation Error - Couldn\'t edit asset, ')
                return redirect("/repo/assets/")

        elif "submit" in request.form:
            # If new asset form has been submitted
            if new_asset_form.validate_on_submit():
                print("POST ACTOR", flush=True)
                edit_owner_id = None
                edit_verified_by_id = None
                edit_net_group_fk_id = None
                edit_type_fk_id = None

                if new_asset_form.owner.data:
                    edit_owner_id = new_asset_form.owner.data.id

                if new_asset_form.type_fk.data:
                    edit_type_fk_id = new_asset_form.type_fk.data.id

                if new_asset_form.verified_by.data:
                    edit_verified_by_id = new_asset_form.verified_by.data.id

                if new_asset_form.net_group_fk.data:
                    edit_net_group_fk_id = new_asset_form.net_group_fk.data.id

                # print(new_actor_form.name.data, flush=True)
                to_add_asset = RepoAsset(name=new_asset_form.name.data,
                                         description=new_asset_form.description.data,
                                         owner=edit_owner_id,
                                         location=new_asset_form.location.data,
                                         verified=new_asset_form.verified.data,
                                         verified_by=bool(edit_verified_by_id),
                                         mac_address=new_asset_form.mac_address.data,
                                         has_static_ip=new_asset_form.has_static_ip.data,
                                         ip=new_asset_form.ip.data,
                                         net_group_fk=edit_net_group_fk_id,
                                         value=new_asset_form.value.data,
                                         loss_of_revenue=new_asset_form.loss_of_revenue.data,
                                         additional_expenses=new_asset_form.additional_expenses.data,
                                         security_levels=new_asset_form.security_levels.data,
                                         customer_service=new_asset_form.customer_service.data,
                                         operating_zone=new_asset_form.operating_zone.data,
                                         last_touch_date=new_asset_form.last_touch_date.data,
                                         type_fk=edit_type_fk_id,
                                         integrity=new_asset_form.integrity.data,
                                         availability=new_asset_form.availability.data,
                                         confidentiality=new_asset_form.confidentiality.data,
                                         current_status=new_asset_form.current_status.data)
                db.session.add(to_add_asset)
                db.session.commit()

                flash('Actor "{}" Added Succesfully'.format(new_asset_form.name.data))
                return redirect("/repo/assets/")
            else:
                # If error in validation, then error
                print(new_asset_form.errors)
                flash('Error: Validation Error - Couldn\'t add asset, ')
                return redirect("/repo/assets/")
        else:
            # If none of them, then error
            print(new_asset_form.errors)
            print(new_edit_form.errors)
            flash('Error: No correct form submitted - Couldn\'t add asset, ')
            return redirect("/repo/assets/")



        # new_asset_form = FormAddRepoAsset()
        # print(new_asset_form.errors)
        # print(new_asset_form.validate_on_submit())
        # if not new_asset_form.validate_on_submit():
        #     # print(new_service_form.name.data, flush=True)
        #     print("2")
        #     owner_id = None
        #     verified_by_id = None
        #     net_group_fk_id = None
        #     type_fk_id = None
        #
        #     if new_asset_form.owner.data:
        #         owner_id = new_asset_form.owner.data.id
        #
        #     if new_asset_form.type_fk.data:
        #         type_fk_id = new_asset_form.type_fk.data.id
        #
        #     if new_asset_form.verified_by.data:
        #         verified_by_id = new_asset_form.verified_by.data.id
        #
        #     if new_asset_form.net_group_fk.data:
        #         net_group_fk_id = new_asset_form.net_group_fk.id
        #
        #     to_add_asset = RepoAsset(name=new_asset_form.name.data,
        #                              description=new_asset_form.description.data,
        #                              owner=owner_id,
        #                              location=new_asset_form.location.data,
        #                              verified=new_asset_form.verified.data,
        #                              verified_by=verified_by_id,
        #                              mac_address=new_asset_form.mac_address.data,
        #                              has_static_ip=new_asset_form.has_static_ip.data,
        #                              ip=new_asset_form.ip.data,
        #                              net_group_fk=net_group_fk_id,
        #                              value=new_asset_form.value.data,
        #                              loss_of_revenue=new_asset_form.loss_of_revenue.data,
        #                              additional_expenses=new_asset_form.additional_expenses.data,
        #                              security_levels=new_asset_form.security_levels.data,
        #                              customer_service=new_asset_form.customer_service.data,
        #                              operating_zone=new_asset_form.operating_zone.data,
        #                              last_touch_date=new_asset_form.last_touch_date.data,
        #                              type_fk=type_fk_id)
        #     db.session.add(to_add_asset)
        #     db.session.commit()
        #
        #     flash('Service "{}" Added Succesfully'.format(new_asset_form.name.data))
        #     return redirect("/repo/assets/")

        return redirect("/repo/assets/")
    else:
        if str(asset_id) == "-1":
            try:
                repo_assets = RepoAsset.query.all()
            except SQLAlchemyError:
                return Response("SQLAlchemyError", 500)
        else:
            try:
                repo_assets = RepoAsset.query.filter_by(id=int(asset_id)).all()
            except SQLAlchemyError:
                return Response("SQLAlchemyError", 500)


        json_assets = convert_database_items_to_json_table(repo_assets)
        # Add new columns for type and subytpe to de displayed in table
        # Uses both the object and converted dict list for ease of access
        for index,json_asset_instance in enumerate(json_assets):
            json_asset_instance["subtype"] = repo_assets[index].type.name
            json_asset_instance["type"] = repo_assets[index].type.variety.name
            json_asset_instance["integrity_id"] = json_asset_instance["integrity"]
            json_asset_instance["availability_id"] = json_asset_instance["availability"]
            json_asset_instance["confidentiality_id"] = json_asset_instance["confidentiality"]
            json_asset_instance["loss_of_revenue_id"] = json_asset_instance["loss_of_revenue"]
            json_asset_instance["additional_expenses_id"] = json_asset_instance["additional_expenses"]
            json_asset_instance["current_status_id"] = json_asset_instance["current_status"]
            json_asset_instance["operating_zone_id"] = json_asset_instance["operating_zone"]
            json_asset_instance["security_levels_id"] = json_asset_instance["security_levels"]
            json_asset_instance["integrity"] = 'Low' if json_asset_instance["integrity"] == 1 else 'Medium' if json_asset_instance["integrity"] == 2 else 'High'
            json_asset_instance["availability"] = 'Low' if json_asset_instance["availability"] == 1 else 'Medium' if json_asset_instance["availability"] == 2 else 'High'
            json_asset_instance["confidentiality"] = 'Low' if json_asset_instance["confidentiality"] == 1 else 'Medium' if json_asset_instance["confidentiality"] == 2 else 'High'
            json_asset_instance["loss_of_revenue"] = 'Low' if json_asset_instance["loss_of_revenue"] == 1 else 'Medium' if json_asset_instance["loss_of_revenue"] == 2 else 'High'
            json_asset_instance["additional_expenses"] = 'Low' if json_asset_instance["additional_expenses"] == 1 else 'Medium' if json_asset_instance["additional_expenses"] == 2 else 'High'
            json_asset_instance["value"] = 'Low' if json_asset_instance["value"] == 1 else 'Medium' if json_asset_instance["value"] == 2 else 'High' if json_asset_instance["value"] == 3 else ''
            json_asset_instance["current_status"] = 'Active' if json_asset_instance["current_status"] == 1 else 'Inactive' if json_asset_instance["current_status"] == 2 else 'Disposed' if json_asset_instance["current_status"] == 3 else 'Unknown'
            json_asset_instance["operating_zone"] = 'Corporate Intranet' if json_asset_instance["operating_zone"] == 1 else 'Business Partners/Clients' if json_asset_instance["operating_zone"] == 2 else 'Employee Private networks' if json_asset_instance["operating_zone"] == 3 else 'Public space'
            json_asset_instance["security_levels"] = 'No specific requirements or security protection necessary' if json_asset_instance["security_levels"] == 1 else 'Protection against casual or coincidental violation' if json_asset_instance["security_levels"] == 2 else 'Protection against intentional violation using simple means with low resources, generic skills and low motivation' if json_asset_instance["security_levels"] == 3 else 'Protection against intentional violation using sophisticated means with moderate resources, specific skills and moderate motivation' if json_asset_instance["security_levels"] == 4 else 'Protection against intentional violation using sophisticated means with extended resources, specific skills and high motivation'

        print(json_assets)
        json_assets = json.dumps(json_assets)

        new_asset_form = FormAddRepoAsset()
        edit_asset_form = FormEditRepoAsset()
        print("REPO ASSETS", json_assets)
        return render_template("templates_asset_repo/view_repo_assets.html", repo_assets=json_assets,
                               new_asset_form=new_asset_form, edit_asset_form=edit_asset_form, asset_id=asset_id)


@app.route('/repo/impacts/', methods=['GET', 'POST', 'PUT'])
def view_repo_impacts():
    if request.method == 'POST':
        new_impact_form = FormAddRepoImpact()

        if new_impact_form.validate_on_submit():
            new_impact = RepoImpact(name=new_impact_form.name.data,
                                    description=new_impact_form.description.data)
            db.session.add(new_impact)
            db.session.commit()

            flash('Impact "{}" Added Succesfully'.format(new_impact_form.name.data))
            return redirect('/repo/impacts/')
        else:
            print("Errors", new_impact_form.errors, flush=True)
            flash('Objective "{}" Error on add'.format(new_impact_form.name.data))

        return redirect('/repo/impacts/')
    else:
        try:
            repo_impacts = RepoImpact.query.all()
        except SQLAlchemyError:
            return Response("SQLAlchemyError", 500)

        # print("------------------------------")
        # print(repo_actors, flush=True)
        #
        # print(repo_actors[0].__table__.columns._data.keys(), flush=True)

        repo_impacts = convert_database_items_to_json_table(repo_impacts)
        repo_impacts = json.dumps(repo_impacts)
        # print("ACTORS ARE --------")
        # print("JSON OBJECTIVES LIST IS", json_objectives)

        new_impact_form = FormAddRepoImpact()
        return render_template("templates_asset_repo/view_repo_impacts.html", repo_impacts=repo_impacts,
                               new_impact_form=new_impact_form)


@app.route('/repo/objectives/', methods=['GET', 'POST', 'PUT'])
def view_repo_objectives():
    if request.method == 'POST':
        if 'objective_alert_form' in request.form:
            # print("ID ALRT CHANGE", request.form)
            objective_states = RepoObjectivesOptions.query.filter_by(
                objective_fk=request.form["objectiveAlertId"]).all()

            # print(objective_states)
            for objective_state in objective_states:
                objective_state.alert_level = request.form[objective_state.name]

            db.session.commit()
        else:
            new_objective_form = FormAddRepoObjective()

            if new_objective_form.validate_on_submit():
                new_objective = RepoObjective(name=new_objective_form.name.data,
                                              description=new_objective_form.description.data)
                db.session.add(new_objective)
                db.session.flush()

                for state in new_objective_form.states.data:
                    # print("Repo Options:", stat
                    new_objective_state = RepoObjectivesOptions(name=state["name"], objective_fk=new_objective.id)
                    db.session.add(new_objective_state)
                    db.session.flush()

                db.session.commit()
                flash('Objective "{}" Added Succesfully'.format(new_objective_form.name.data))
                # add_new_objective = RepoObjective(name=new_objective_form.name.data)
                return redirect('/repo/objectives/')
            else:
                print("Errors", new_objective_form.errors, flush=True)

            flash('Objective "{}" Error on add'.format(new_objective_form.name.data))

        return redirect('/repo/objectives/')
    else:
        try:
            repo_objectives = RepoObjective.query.all()
        except SQLAlchemyError:
            return Response("SQLAlchemyError", 500)

        # print("------------------------------")
        # print(repo_actors, flush=True)
        #
        # print(repo_actors[0].__table__.columns._data.keys(), flush=True)

        json_objectives = convert_database_items_to_json_table(repo_objectives)
        json_objectives = json.dumps(json_objectives)
        # print("ACTORS ARE --------")
        json_objectives = ast.literal_eval(json_objectives)
        # print("JSON OBJECTIVES LIST IS", json_objectives)

        for it in json_objectives:
            it["states"] = "|"
            it["alerts"] = "|"
            # print(it)
            try:
                json_objective_current_state = RepoObjectivesOptions.query.filter_by(objective_fk=it["id"]).all()
            except SQLAlchemyError:
                return Response("SQLAlchemyError", 500)

            for current_state in json_objective_current_state:
                it["states"] = it["states"] + current_state.name + "|"
                it["alerts"] = it["alerts"] + str(current_state.alert_level) + "|"

        # print(json_objectives)
        # it["states"] = json_objective_current_state
        # json_objectives = [{'id': '1', 'name': 'Monetary', 'states': 'x<1000 | 1000 < x < 10000 | x > 10000'},
        #                    {'id': '2', 'name': 'Confidentiality', 'states': 'Low | Med | High'},
        #                    {'id': '3', 'name': 'Integrity', 'states': 'Low | Med | High'},
        #                    {'id': '4', 'name': 'Availability', 'states': 'Low | Med | High'},
        #                    {'id': '5', 'name': 'Safety', 'states': 'No Injuries | Injuries | Fatalities'}
        #                    ]
        new_objective_form = FormAddRepoObjective()
        return render_template("templates_asset_repo/view_repo_objectives.html", repo_objectives=json_objectives,
                               new_objective_form=new_objective_form)


@app.route('/repo/objective/<objective_id>/info/', methods=['GET', 'POST'])
def view_repo_objective_info(objective_id):
    if request.method == 'POST':
        new_objective_impact_form = FormAddRepoObjectiveImpact()

        if new_objective_impact_form.validate_on_submit():
            try:
                this_objective = RepoObjective.query.filter_by(id=objective_id).first()
            except SQLAlchemyError:
                return Response("SQLAlchemyError", 500)

            try:
                to_relate_impact = RepoImpact.query.filter_by(id=new_objective_impact_form.impact_fk.data.id).first()
            except SQLAlchemyError:
                return Response("SQLAlchemyError", 500)

            this_objective.impacts.append(to_relate_impact)
            db.session.commit()
        else:
            print("Form Consequence Impact Error :", new_objective_impact_form.errors)

        return redirect("/repo/objective/" + objective_id + "/info/")
    else:
        try:
            this_objective = RepoObjective.query.filter_by(id=objective_id).all()
        except SQLAlchemyError:
            return Response("SQLAlchemyError", 500)

        try:
            repo_related_impacts = RepoImpact.query.filter(RepoImpact.objectives.any(id=objective_id)).all()
        except SQLAlchemyError:
            return Response("SQLAlchemyError", 500)

        this_objective = convert_database_items_to_json_table(this_objective)
        this_objective_dict = this_objective
        this_objective = json.dumps(this_objective)

        repo_related_impacts = convert_database_items_to_json_table(repo_related_impacts)
        repo_related_impacts = json.dumps(repo_related_impacts)

        new_objective_impact_form = FormAddRepoObjectiveImpact()

        return render_template("templates_asset_repo/view_repo_objective_info.html", this_objective=this_objective,
                               this_objective_dict=this_objective_dict,
                               repo_related_impacts=repo_related_impacts,
                               new_objective_impact_form=new_objective_impact_form)


@app.route('/repo/utilities/', methods=['GET', 'POST', 'PUT'])
def view_repo_utilities():
    if request.method == 'POST':
        if 'submit_utility' in request.form:
            print("UTILITY IS:", request.form)
            to_add_utility = RepoUtility(name=request.form["name"])

            db.session.add(to_add_utility)
            # print(objective_states)
            db.session.commit()
        else:
            new_utility_objective = FormAddRepoUtilityObjective()
            if new_utility_objective.validate_on_submit():
                try:
                    to_edit_utility = RepoUtility.query.filter_by(id=new_utility_objective.utility_id.data).first()
                except SQLAlchemyError:
                    return Response("SQLAlchemyError", 500)

                to_edit_utility.objectives.append(new_utility_objective.objective.data)

                db.session.commit()
                flash('Utility-Objective "{}" Added Succesfully'.format(new_utility_objective.objective.data))
                # add_new_objective = RepoObjective(name=new_objective_form.name.data)
                return redirect('/repo/utilities/')
            else:
                print("Errors", new_utility_objective.errors, flush=True)

            flash('Utility "{}" Error on add'.format(new_utility_objective.utility_id.data))

        return redirect('/repo/utilities/')
    else:
        try:
            repo_utilities = RepoUtility.query.all()
        except SQLAlchemyError:
            return Response("SQLAlchemyError", 500)

        # print("------------------------------")
        # print(repo_actors, flush=True)
        #
        # print(repo_actors[0].__table__.columns._data.keys(), flush=True)

        json_utilities = convert_database_items_to_json_table(repo_utilities)

        print(json_utilities)

        for utility in json_utilities:
            print(utility["id"])
            try:
                repo_objectives_related = RepoObjective.query.filter(
                    RepoObjective.utilities.any(id=utility["id"])).all()
            except SQLAlchemyError:
                return Response("SQLAlchemyError", 500)

            utility["objectives"] = ""
            for repo_objective_related in repo_objectives_related:
                utility["objectives"] += repo_objective_related.name + "|"

                # Passing this to add edit functionality at a later date
                utility["Objective" + str(repo_objective_related.id)] = repo_objective_related.name

        print(json_utilities)
        json_utilities = json.dumps(json_utilities)

        new_utlity_form = FormAddRepoUtility()
        new_utlity_objective_form = FormAddRepoUtilityObjective()
        return render_template("templates_asset_repo/view_repo_utilities.html", json_utilities=json_utilities,
                               new_utlity_form=new_utlity_form, new_utlity_objective_form=new_utlity_objective_form)


@app.route('/repo/actors/', methods=['GET', 'POST', 'PUT'])
def view_repo_actors():
    if request.method == 'POST':
        new_actor_form = FormAddRepoActor()

        if new_actor_form.validate_on_submit():
            if new_actor_form.id.data:
                print("PUT ACTOR", "|", new_actor_form.id.data, "|", flush=True)

                try:
                    to_edit_actor = RepoActor.query.filter_by(id=new_actor_form.id.data).first()
                except SQLAlchemyError:
                    return Response("SQLAlchemyError when editing records", 500)

                # print("---------------------")
                # print(to_edit_actor.id.data)
                # print(to_edit_actor.name.data)
                to_edit_actor.name = new_actor_form.name.data
                db.session.commit()
                return redirect("/repo/actors/")
            else:
                print("POST ACTOR", flush=True)
                # print(new_actor_form.name.data, flush=True)
                to_add_actor = RepoActor(name=new_actor_form.name.data)
                db.session.add(to_add_actor)
                db.session.commit()

                flash('Actor "{}" Added Succesfully'.format(new_actor_form.name.data))
                return redirect("/repo/actors/")
        else:
            print(new_actor_form.errors)
            flash('Error: Validation Error - Couldn\'t add actor, ')
            return redirect("/repo/actors/")

    else:
        try:
            repo_actors = RepoActor.query.all()
        except SQLAlchemyError:
            return Response("SQLAlchemyError", 500)
        # print("------------------------------")
        # print(repo_actors, flush=True)
        #
        # print(repo_actors[0].__table__.columns._data.keys(), flush=True)

        json_actors = convert_database_items_to_json_table(repo_actors)
        json_actors = json.dumps(json_actors)
        # print("ACTORS ARE --------")
        print(json_actors)
        new_actor_form = FormAddRepoActor()
        return render_template("templates_asset_repo/view_repo_actors.html", repo_actors=json_actors,
                               new_actor_form=new_actor_form)


@app.route('/repo/services/', methods=['GET', 'POST'])
def view_repo_services():
    if request.method == 'POST':
        new_service_form = FormAddRepoService()

        if new_service_form.validate_on_submit():
            if new_service_form.id.data:
                # print("PUT ACTOR", "|", new_vulnerability_form.id.data, "|", flush=True)

                try:
                    to_add_service = RepoService.query.filter_by(id=new_service_form.id.data).first()
                except SQLAlchemyError:
                    return Response("SQLAlchemyError when editing records", 500)

                # print("---------------------")
                # print(to_edit_actor.id.data)
                # print(to_edit_actor.name.data)
                to_add_service.name = new_service_form.name.data
                db.session.commit()
                return redirect("/repo/services/")
            else:
                # print("POST ACTOR", flush=True)
                # print(new_actor_form.name.data, flush=True)
                to_add_service = RepoService(name=new_service_form.name.data)
                db.session.add(to_add_service)
                db.session.commit()

                flash('Service "{}" Added Succesfully'.format(new_service_form.name.data))
                return redirect("/repo/services/")
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
        print("ACTORS ARE --------")
        print(json_services)
        new_service_form = FormAddRepoService()
        return render_template("templates_asset_repo/view_repo_services.html", repo_services=json_services,
                               new_service_form=new_service_form)


@app.route('/repo/net_groups/', methods=['GET', 'POST'])
def view_repo_net_groups():
    if request.method == 'POST':
        new_net_group_form = FormAddRepoNetGroup()

        if new_net_group_form.validate_on_submit():
            if new_net_group_form.id.data:
                print("PUT ACTOR", "|", new_net_group_form.id.data, "|", flush=True)

                try:
                    to_add_net_group = RepoNetGroup.query.filter_by(id=new_net_group_form.id.data).first()
                except SQLAlchemyError:
                    return Response("SQLAlchemyError when editing records", 500)

                # print("---------------------")
                # print(to_edit_actor.id.data)
                # print(to_edit_actor.name.data)
                to_add_net_group.name = new_net_group_form.name.data
                db.session.commit()
                return redirect("/repo/net_groups/")
            else:
                print("POST ACTOR", flush=True)
                # print(new_actor_form.name.data, flush=True)
                to_add_net_group = RepoNetGroup(name=new_net_group_form.name.data)
                db.session.add(to_add_net_group)
                db.session.commit()

                flash('Net Group "{}" Added Succesfully'.format(new_net_group_form.name.data))
                return redirect("/repo/net_groups/")
    else:
        try:
            repo_net_groups = RepoNetGroup.query.all()
        except SQLAlchemyError:
            return Response("SQLAlchemyError", 500)
        # print("------------------------------")
        # print(repo_actors, flush=True)
        #
        # print(repo_actors[0].__table__.columns._data.keys(), flush=True)

        json_net_groups = convert_database_items_to_json_table(repo_net_groups)
        json_net_groups = json.dumps(json_net_groups)
        # print("ACTORS ARE --------")
        # print(json_actors)
        new_net_group_form = FormAddRepoNetGroup()
        return render_template("templates_asset_repo/view_repo_net_group.html", repo_net_groups=json_net_groups,
                               new_net_group_form=new_net_group_form)


@app.route('/repo/vulnerabilities/', methods=['GET', 'POST'])
def view_repo_vulnerabilities():
    path_to_VAaaS_report = os.path.join(os.path.abspath(os.path.join(os.path.dirname(__file__), os.path.pardir)),
                                        'Json_texts', 'VaaS Output 2022.json')
    path_to_SIEM_report = os.path.join(os.path.abspath(os.path.join(os.path.dirname(__file__), os.path.pardir)),
                                        'Json_texts', 'siem-certification-vulnerabilities.json')
    # x = v_report(path_to_VAaaS_report)
    with open(path_to_VAaaS_report,"r") as fp:
        obj = json.load(fp)
        for attribute, value in obj.items():
            y = v_report_json(attribute, value)

    with open(path_to_SIEM_report, "r") as fp:
        obj = json.load(fp)
        y = certification_report_json(obj)

    if request.method == 'POST':
        new_vulnerability_form = FormAddVulnerabilityReportVulnerabilitiesLink()

        if new_vulnerability_form.validate_on_submit():
            if new_vulnerability_form.id.data:
                # print("PUT ACTOR", "|", new_vulnerability_form.id.data, "|", flush=True)

                try:
                    to_add_vulnerability = VulnerabilityReportVulnerabilitiesLink.query.filter_by(
                        id=new_vulnerability_form.id.data).first()
                except SQLAlchemyError:
                    return Response("SQLAlchemyError when editing records", 500)

                # print("---------------------")
                # print(to_edit_actor.id.data)
                # print(to_edit_actor.name.data)
                to_add_vulnerability.name = new_vulnerability_form.name.data
                db.session.commit()
                return redirect("/repo/vulnerabilities/")
            else:
                print("POST ACTOR", flush=True)
                # print(new_actor_form.name.data, flush=True)
                to_add_vulnerability = VulnerabilityReportVulnerabilitiesLink(name=new_vulnerability_form.name.data)
                to_add_vulnerability = VulnerabilityReportVulnerabilitiesLink(VReport_id=new_vulnerability_form.VReport_id.data)
                to_add_vulnerability = VulnerabilityReportVulnerabilitiesLink(
                    VReport_CVSS_score=new_vulnerability_form.VReport_CVSS_score.data)
                to_add_vulnerability = VulnerabilityReportVulnerabilitiesLink(
                    VReport_assetIp=new_vulnerability_form.VReport_assetIp.data)
                db.session.add(to_add_vulnerability)
                db.session.commit()

                flash('Vulnerability "{}" Added Succesfully'.format(new_vulnerability_form.name.data))
                return redirect("/repo/vulnerabilities/")
    else:
        try:
            repo_vulnerabilities = VulnerabilityReportVulnerabilitiesLink.query.all()
        except SQLAlchemyError:
            return Response("SQLAlchemyError", 500)
        # print("------------------------------")
        # print(repo_actors, flush=True)
        #
        # print(repo_actors[0].__table__.columns._data.keys(), flush=True)

        json_vulnerabilities = convert_database_items_to_json_table(repo_vulnerabilities)
        for it,json_vulnerability in enumerate(json_vulnerabilities):
            print(json_vulnerability)
            json_vulnerability["asset_id"] = repo_vulnerabilities[it].asset.name
            json_vulnerability["cve_id"] = repo_vulnerabilities[it].cve.CVEId
            json_vulnerability["VReport_id"] = repo_vulnerabilities[it].vreport.reportId
            json_vulnerability["VReport_source_component"] = repo_vulnerabilities[it].vreport.source_component
            json_vulnerability["VReport_source_component"] = 'VAaaS' if json_vulnerability["VReport_source_component"] == 1 else 'Certification'

        json_vulnerabilities = json.dumps(json_vulnerabilities, default=str)
        # print("ACTORS ARE --------")
        # print(json_actors)
        new_vulnerability_form = FormAddVulnerabilityReportVulnerabilitiesLink()
        return render_template("templates_asset_repo/view_repo_vulnerabilities.html",
                               repo_vulnerabilities=json_vulnerabilities,
                               new_vulnerability_form=new_vulnerability_form)


@app.route('/repo/vulnerability/<vulnerability_id>/controls/', methods=['GET', 'POST'])
def view_repo_vulnerability_info(vulnerability_id):
    if request.method == 'POST':
        new_vulnerability_form = FormAddVulnerabilityReportVulnerabilitiesLink()

        if new_vulnerability_form.validate_on_submit():
            if new_vulnerability_form.id.data:
                # print("PUT ACTOR", "|", new_vulnerability_form.id.data, "|", flush=True)

                try:
                    to_add_vulnerability = VulnerabilityReportVulnerabilitiesLink.query.filter_by(
                        id=new_vulnerability_form.id.data).first()
                except SQLAlchemyError:
                    return Response("SQLAlchemyError when editing records", 500)

                # print("---------------------")
                # print(to_edit_actor.id.data)
                # print(to_edit_actor.name.data)
                to_add_vulnerability.name = new_vulnerability_form.name.data
                db.session.commit()
                return redirect("/repo/vulnerabilities/")
            else:
                print("POST ACTOR", flush=True)
                # print(new_actor_form.name.data, flush=True)
                to_add_vulnerability = VulnerabilityReportVulnerabilitiesLink(name=new_vulnerability_form.name.data)
                db.session.add(to_add_vulnerability)
                db.session.commit()

                flash('Vulnerability "{}" Added Succesfully'.format(new_vulnerability_form.name.data))
                return redirect("/repo/vulnerabilities/")
    else:
        try:
            repo_services = VulnerabilityReportVulnerabilitiesLink.query.all()
        except SQLAlchemyError:
            return Response("SQLAlchemyError", 500)

        try:
            this_vulnerability = VulnerabilityReportVulnerabilitiesLink.query.filter_by(id=vulnerability_id).all()
        except SQLAlchemyError:
            return Response("SQLAlchemyError", 500)
        # print("------------------------------")
        # print(repo_actors, flush=True)
        #
        # print(repo_actors[0].__table__.columns._data.keys(), flush=True)

        json_vulnerabilities = convert_database_items_to_json_table(repo_services)
        json_vulnerabilities = json.dumps(json_vulnerabilities, default=str)

        this_vulnerability = convert_database_items_to_json_table(this_vulnerability)
        this_vulnerability = json.dumps(this_vulnerability, default=str)
        print("ACTORS ARE --------")
        print(json_vulnerabilities)
        json_vulnerabilities = [{
            "id": 1, "name": "Control - 1", "effectiveness": 56
        },
            {
                "id": 2, "name": "Control - 2", "effectiveness": 76
            }
        ]

        new_vulnerability_form = FormAddRepoVulnerabilityControl()
        return render_template("templates_asset_repo/view_repo_vulnerability_info.html",
                               repo_vulnerabilities=json_vulnerabilities,
                               this_vulnerability=this_vulnerability,
                               new_vulnerability_form=new_vulnerability_form)


@app.route('/repo/threats/', methods=['GET', 'POST'])
def view_repo_threats():
    if request.method == 'POST':
        new_threat_form = FormAddRepoThreat()

        if new_threat_form.validate_on_submit():
            if new_threat_form.id.data:
                # print("PUT ACTOR", "|", new_vulnerability_form.id.data, "|", flush=True)

                try:
                    to_add_threat = RepoThreat.query.filter_by(id=new_threat_form.id.data).first()
                except SQLAlchemyError:
                    return Response("SQLAlchemyError when editing records", 500)

                # print("---------------------")
                # print(to_edit_actor.id.data)
                # print(to_edit_actor.name.data)
                to_add_threat.name = new_threat_form.name.data
                db.session.commit()
                return redirect("/repo/threats/")
            else:
                print("POST ACTOR", flush=True)
                # print(new_actor_form.name.data, flush=True)
                to_add_threat = RepoThreat(name=new_threat_form.name.data)
                db.session.add(to_add_threat)
                db.session.commit()

                flash('Threat "{}" Added Succesfully'.format(new_threat_form.name.data))
                return redirect("/repo/threats/")
    else:
        try:
            repo_threats = RepoThreat.query.all()
        except SQLAlchemyError:
            return Response("SQLAlchemyError", 500)
        # print("------------------------------")
        # print(repo_actors, flush=True)
        #
        # print(repo_actors[0].__table__.columns._data.keys(), flush=True)

        json_threats = convert_database_items_to_json_table(repo_threats)
        json_threats = json.dumps(json_threats)
        # print("Threats ARE --------")
        # print(json_threats)
        new_threat_form = FormAddRepoThreat()
        return render_template("templates_asset_repo/view_repo_threats.html", repo_threats=json_threats,
                               new_threat_form=new_threat_form)


@app.route('/repo/threat/<threat_id>/info/', methods=['GET', 'POST'])
def view_repo_threat_info(threat_id):
    if request.method == 'POST':
        # new_materialisation_consequence_form = FormAddRepoMaterialisationConsequence()

        new_materialisation_form = FormAddRepoMaterialisation()
        new_consequence_form = FormAddRepoConsequence()

        new_response_form = FormAddRepoResponse()

        if new_materialisation_form.validate_on_submit():
            print("SAVING MATERIALISATION")
            to_add_materialisation = RepoMaterialisation(
                name=new_materialisation_form.name_materialisation.data,
                threat_id=new_materialisation_form.threat_id.data)

            db.session.add(to_add_materialisation)
            db.session.commit()
        else:
            print("Form Materialisation Error :", new_materialisation_form.errors)

        if new_consequence_form.validate_on_submit():
            print("SAVING CONSEQUENCE")
            to_add_consequences = RepoConsequence(name=new_consequence_form.name_consequence.data,
                                                  threat_id=new_consequence_form.threat_id.data,
                                                  materialisation_id=new_consequence_form.materialisation_fk.data.id)

            db.session.add(to_add_consequences)
            db.session.commit()
        else:
            print("Form Materialisation Error :", new_materialisation_form.errors)

        if new_response_form.validate_on_submit():
            print("SAVING RESPONSE")
            to_add_response = RepoResponse(name=new_response_form.name.data, threat_id=new_response_form.threat_id.data)

            db.session.add(to_add_response)
            db.session.commit()
        else:
            print("Form Response :", new_response_form.errors)

        return redirect("/repo/threat/" + threat_id + "/info/")
    else:
        try:
            repo_threat = RepoThreat.query.filter_by(id=threat_id).all()
        except SQLAlchemyError:
            return Response("SQLAlchemyError", 500)

        try:
            repo_materialisations = RepoMaterialisation.query.filter_by(threat_id=threat_id).all()
        except SQLAlchemyError:
            return Response("SQLAlchemyError", 500)

        try:
            repo_consequences = RepoConsequence.query.filter_by(threat_id=threat_id).all()
        except SQLAlchemyError:
            return Response("SQLAlchemyError", 500)

        try:
            repo_responses = RepoResponse.query.filter_by(threat_id=threat_id).all()
        except SQLAlchemyError:
            return Response("SQLAlchemyError", 500)

        repo_threat = convert_database_items_to_json_table(repo_threat)
        repo_threat_dict = repo_threat
        repo_threat = json.dumps(repo_threat)

        repo_materialisations = convert_database_items_to_json_table(repo_materialisations)
        repo_materialisations = json.dumps(repo_materialisations)

        repo_consequences = convert_database_items_to_json_table(repo_consequences)
        repo_consequences = json.dumps(repo_consequences)

        repo_responses = convert_database_items_to_json_table(repo_responses)
        repo_responses = json.dumps(repo_responses)

        # new_materialisation_consequence_form = FormAddRepoMaterialisationConsequence()
        new_materialisation_form = FormAddRepoMaterialisation()
        new_consequence_form = FormAddRepoConsequence()

        new_response_form = FormAddRepoResponse()
        print("Mats here is: ", repo_materialisations)
        return render_template("templates_asset_repo/view_repo_threat_info.html", repo_threat=repo_threat,
                               repo_threat_dict=repo_threat_dict,
                               repo_materialisations=repo_materialisations, repo_consequences=repo_consequences,
                               new_materialisation_form=new_materialisation_form,
                               new_consequence_form=new_consequence_form,
                               repo_responses=repo_responses, new_response_form=new_response_form)


@app.route('/repo/threat/<threat_id>/cve/', methods=['GET', 'POST'])
def view_repo_threat_cve(threat_id):
    if request.method == 'POST':
        # new_materialisation_consequence_form = FormAddRepoMaterialisationConsequence()

        new_cve_relationship_form = FormAddCVEtoAsset()



        if new_cve_relationship_form.validate_on_submit():
            try:
                this_threat = RepoThreat.query.filter_by(id=threat_id).first()
            except SQLAlchemyError:
                return Response("SQLAlchemyError", 500)

            this_threat.cves.append(new_cve_relationship_form.cve.data)

            db.session.commit()
        else:
            print("Form CVE add relationship error :", new_cve_relationship_form.errors)

        return redirect("/repo/threat/" + threat_id + "/cve/")
    else:
        try:
            repo_threat = RepoThreat.query.filter_by(id=threat_id).all()
        except SQLAlchemyError:
            return Response("SQLAlchemyError", 500)

        try:
            repo_cves = CommonVulnerabilitiesAndExposures.query.all()
        except SQLAlchemyError:
            return Response("SQLAlchemyError", 500)

        try:
            repo_cves_related = CommonVulnerabilitiesAndExposures.query.filter(CommonVulnerabilitiesAndExposures.threats.any(RepoThreat.id == threat_id)).all()
        except SQLAlchemyError:
            return Response("SQLAlchemyError", 500)


        # try:
        #     repo_materialisations = RepoMaterialisation.query.filter_by(threat_id=threat_id).all()
        # except SQLAlchemyError:
        #     return Response("SQLAlchemyError", 500)
        #
        # try:
        #     repo_consequences = RepoConsequence.query.filter_by(threat_id=threat_id).all()
        # except SQLAlchemyError:
        #     return Response("SQLAlchemyError", 500)
        #
        # try:
        #     repo_responses = RepoResponse.query.filter_by(threat_id=threat_id).all()
        # except SQLAlchemyError:
        #     return Response("SQLAlchemyError", 500)

        repo_threat = convert_database_items_to_json_table(repo_threat)
        repo_threat_dict = repo_threat
        repo_threat = json.dumps(repo_threat)

        json_cves = convert_database_items_to_json_table(repo_cves)
        json_cves = json.dumps(json_cves)

        json_cves_related = convert_database_items_to_json_table(repo_cves_related)
        json_cves_related = json.dumps(json_cves_related)


        # new_materialisation_consequence_form = FormAddRepoMaterialisationConsequence()

        new_cve_relationship_form = FormAddCVEtoAsset()

        # print("Mats here is: ", repo_materialisations)
        return render_template("templates_asset_repo/view_repo_threat_cve.html", repo_threat=repo_threat,
                               repo_threat_dict=repo_threat_dict,
                               json_cves=json_cves, json_cves_related =json_cves_related,
                               new_cve_relationship_form=new_cve_relationship_form)



@app.route('/repo/threat/<threat_id>/info/consequence/<consequence_id>/info/', methods=['GET', 'POST'])
def view_repo_threat_info_consequence_info(threat_id, consequence_id):
    if request.method == 'POST':
        new_consequence_impact_form = FormAddRepoConsequenceImpact()

        if new_consequence_impact_form.validate_on_submit():
            try:
                this_consequence = RepoConsequence.query.filter_by(id=consequence_id).first()
            except SQLAlchemyError:
                return Response("SQLAlchemyError", 500)

            try:
                to_relate_impact = RepoImpact.query.filter_by(id=new_consequence_impact_form.impact_fk.data.id).first()
            except SQLAlchemyError:
                return Response("SQLAlchemyError", 500)

            this_consequence.impacts.append(to_relate_impact)
            db.session.commit()
        else:
            print("Form Consequence Impact Error :", new_consequence_impact_form.errors)

        return redirect("/repo/threat/" + threat_id + "/info/consequence/" + consequence_id + "/info/")
    else:
        try:
            this_threat = RepoThreat.query.filter_by(id=threat_id).all()
        except SQLAlchemyError:
            return Response("SQLAlchemyError", 500)

        try:
            this_consequence = RepoConsequence.query.filter_by(id=consequence_id).all()
        except SQLAlchemyError:
            return Response("SQLAlchemyError", 500)

        try:
            repo_related_impacts = RepoImpact.query.filter(RepoImpact.consequences.any(id=consequence_id)).all()
        except SQLAlchemyError:
            return Response("SQLAlchemyError", 500)

        this_threat = convert_database_items_to_json_table(this_threat)
        this_threat_dict = this_threat
        this_threat = json.dumps(this_threat)

        this_consequence = convert_database_items_to_json_table(this_consequence)
        this_consequence_dict = this_consequence
        this_consequence = json.dumps(this_consequence)

        repo_related_impacts = convert_database_items_to_json_table(repo_related_impacts)
        repo_related_impacts = json.dumps(repo_related_impacts)

        new_consequence_impact_form = FormAddRepoConsequenceImpact()

        return render_template("templates_asset_repo/view_repo_threat_info_consequence_info.html",
                               this_threat=this_threat,
                               this_threat_dict=this_threat_dict,
                               this_consequence=this_consequence,
                               this_consequence_dict=this_consequence_dict,
                               repo_related_impacts=repo_related_impacts,
                               new_consequence_impact_form=new_consequence_impact_form)


@app.route('/repo/service/<service_id>/info/', methods=['GET', 'POST'])
def view_repo_serivce_info(service_id):
    if request.method == 'POST':
        new_service_impact_form = FormAddRepoServiceImpact()

        if new_service_impact_form.validate_on_submit():
            print("SAVING SERVICE IMPACT CONNECTION: ")
            print(new_service_impact_form.impact_fk.data.id)
            try:
                this_service = RepoService.query.filter_by(id=service_id).first()
            except SQLAlchemyError:
                return Response("SQLAlchemyError", 500)

            try:
                this_impact = RepoImpact.query.filter_by(id=new_service_impact_form.impact_fk.data.id).first()
            except SQLAlchemyError:
                return Response("SQLAlchemyError", 500)
            print("SAVING SERVICE IMPACT CONNECTION 2")
            this_service.impacts.append(this_impact)
            print("SAVING SERVICE IMPACT CONNECTION 3")
            db.session.commit()
            print("SAVING SERVICE IMPACT CONNECTION 4")
            # to_add_materialisation = RepoMaterialisation(
            #     name=new_materialisation_form.name_materialisation.data,
            #     threat_id=new_materialisation_form.threat_id.data)
            #
            # db.session.add(to_add_materialisation)
            # db.session.commit()
        else:
            print("Form Service Impact Error :", new_service_impact_form.errors)

        return redirect("/repo/service/" + service_id + "/info/")
    else:
        try:
            repo_impacts = RepoImpact.query.all()
        except SQLAlchemyError:
            return Response("SQLAlchemyError", 500)

        try:
            this_service = RepoService.query.filter_by(id=service_id).all()
        except SQLAlchemyError:
            return Response("SQLAlchemyError", 500)

        try:
            repo_impacts_service_connected = RepoImpact.query.filter(RepoImpact.services.any(id=service_id)).all()
        except SQLAlchemyError:
            return Response("SQLAlchemyError", 500)

        repo_impacts_service_connected = convert_database_items_to_json_table(repo_impacts_service_connected)
        repo_impacts_service_connected = json.dumps(repo_impacts_service_connected)

        repo_impacts = convert_database_items_to_json_table(repo_impacts)

        this_service = convert_database_items_to_json_table(this_service)
        this_service = json.dumps(this_service)

        # new_materialisation_consequence_form = FormAddRepoMaterialisationConsequence()
        new_service_impact_form = FormAddRepoServiceImpact()

        return render_template("templates_asset_repo/view_repo_service_info.html", repo_impacts=repo_impacts,
                               service_id=service_id,
                               this_service=this_service,
                               repo_impacts_service_connected=repo_impacts_service_connected,
                               new_service_impact_form=new_service_impact_form)


# DONT THINK THIS IS VALID ANYMORE
@app.route('/repo/assets/threats-relations/<asset_id>/', methods=['GET', 'POST'])
def view_repo_asset_threats_relation(asset_id):
    if request.method == 'POST':
        # flash('Threat "{}" Added Succesfully'.format(new_threat_form.name.data))
        return redirect("/repo/assets/threats-relations/1/")
    else:
        try:
            repo_asset = RepoAsset.query.filter_by(id=int(asset_id)).all()
        except SQLAlchemyError:
            return Response("SQLAlchemyError", 500)

        try:
            repo_threats = RepoThreat.query.all()
        except SQLAlchemyError:
            return Response("SQLAlchemyError", 500)

        repo_asset = convert_database_items_to_json_table(repo_asset)
        repo_asset = json.dumps(repo_asset)
        # new_threat_form = FormAddRepoThreat()
        return render_template("templates_asset_repo/view_repo_assets_threats_relation.html", repo_assets=repo_asset,
                               repo_threats=repo_threats)


@app.route('/repo/assets/services-relations/<asset_id>/', methods=['GET', 'POST'])
def view_repo_asset_services_relation(asset_id):
    if request.method == 'POST':
        try:
            repo_asset = RepoAsset.query.filter_by(id=int(asset_id)).first()
        except SQLAlchemyError:
            return Response("SQLAlchemyError", 500)

        # Add new asset-services relations
        try:
            services = RepoService.query.all()
        except SQLAlchemyError:
            return Response("SQLAlchemyError", 500)

        try:
            related_services = RepoService.query.filter(RepoService.assets.any(id=asset_id)).all()
        except SQLAlchemyError:
            return Response("SQLAlchemyError", 500)

        for service in services:
            related_service = None
            for potentialy_related in related_services:
                if potentialy_related.id == service.id:
                    related_service = potentialy_related
                    break
            else:
                related_service = None
            if request.form[str(service.id)] == "0":
                print("NO RELATION", service.name)
                # Find if service was prebiously related

                if related_service is not None:
                    # If it exists delete it
                    print("NO RELATION DELETE", service.name, ":", repo_asset.services)
                    repo_asset.services.remove(related_service)
                else:
                    print("NO RELATION NOTHING", service.name)
                    # Otherwise do nothing
                    continue
            else:
                print("RELATION", service.name)

                if related_service is not None:
                    # If it exists do nothing
                    print("RELATION NOTHING", service.name)
                    continue
                else:
                    print("RELATION ADD", service.name)
                    # Otherwise add it
                    repo_asset.services.append(service)

        # Update Asset value
        if RepoService.query.filter(RepoService.assets.any(id=int(asset_id))).count() > 0:
            value_weight = RepoService.query.filter(RepoService.assets.any(id=int(asset_id))).count()
            value_calculations = value_weight * (int(repo_asset.loss_of_revenue) + int(repo_asset.additional_expenses) + int(repo_asset.security_levels) + int(repo_asset.integrity) + int(repo_asset.availability) + int(repo_asset.confidentiality))
            final_value = 1 if value_calculations <= 6 else 2 if value_calculations <= 8 else 3
            repo_asset.value = final_value

        db.session.commit()
        # for service in services:
        #     to_add_asset.services.append(service)

        # flash('Threat "{}" Added Succesfully'.format(new_threat_form.name.data))
        return redirect("/repo/assets/services-relations/" + asset_id + "/")
    else:
        try:
            repo_asset = RepoAsset.query.filter_by(id=int(asset_id)).all()
        except SQLAlchemyError:
            return Response("SQLAlchemyError", 500)

        try:
            all_services = RepoService.query.all()
        except SQLAlchemyError:
            return Response("SQLAlchemyError", 500)

        try:
            related_services = RepoService.query.filter(RepoService.assets.any(id=asset_id)).all()
        except SQLAlchemyError:
            return Response("SQLAlchemyError", 500)

        print("Start Related Services:", related_services)
        repo_asset = convert_database_items_to_json_table(repo_asset)
        repo_asset = json.dumps(repo_asset)

        related_services = convert_database_items_to_json_table(related_services)

        unrelated_services = convert_database_items_to_json_table(all_services)

        for related_service in related_services:
            unrelated_services.remove(related_service)

        related_services = json.dumps(related_services)
        unrelated_services = json.dumps(unrelated_services)
        related_services = ast.literal_eval(related_services)
        unrelated_services = ast.literal_eval(unrelated_services)

        print("Related Services:", related_services)
        print("Unrelated Services:", unrelated_services)
        return render_template("templates_asset_repo/view_repo_assets_services_relation.html", repo_assets=repo_asset,
                               related_services=related_services, unrelated_services=unrelated_services,
                               asset_id=asset_id)


@app.route('/repo/controls/', methods=['GET', 'POST'])
def view_repo_controls():
    if request.method == 'POST':
        new_control_form = FormAddRepoControl()

        if new_control_form.validate_on_submit():
            if new_control_form.id.data:
                # print("PUT ACTOR", "|", new_vulnerability_form.id.data, "|", flush=True)

                try:
                    to_add_control = RepoControl.query.filter_by(id=new_control_form.id.data).first()
                except SQLAlchemyError:
                    return Response("SQLAlchemyError when editing records", 500)

                # print("---------------------")
                # print(to_edit_actor.id.data)
                # print(to_edit_actor.name.data)
                to_add_control.name = new_control_form.name.data
                db.session.commit()
                return redirect("/repo/control/")
            else:
                # print("POST ACTOR", flush=True)
                # print(new_actor_form.name.data, flush=True)
                to_add_control = RepoControl(name=new_control_form.name.data,
                                             description=new_control_form.description.data,
                                             effectiveness=new_control_form.effectiveness.data,
                                             vulnerability_id=new_control_form.vulnerability.data.id)
                db.session.add(to_add_control)
                db.session.commit()

                print("DATA_________________")
                print(new_control_form.vulnerability.data.id)
                print(to_add_control.name)
                print(to_add_control.vulnerabilities.id)
                # try:
                #     to_relate_vulnerability = VulnerabilityReportVulnerabilitiesLink.query.filter_by(
                #         id=new_control_form.vulnerability.data.id).first()
                # except SQLAlchemyError:
                #     return Response("SQLAlchemyError", 500)

                # to_add_control.vulnerabilities.append(to_relate_vulnerability)

                # db.session.commit()

                flash('Control "{}" Added Succesfully'.format(to_add_control.name))
                return redirect("/repo/controls/")
    else:
        try:
            repo_controls = RepoControl.query.all()
        except SQLAlchemyError:
            return Response("SQLAlchemyError", 500)
        # print("------------------------------")
        # print(repo_actors, flush=True)
        #
        # print(repo_actors[0].__table__.columns._data.keys(), flush=True)

        json_controls = convert_database_items_to_json_table(repo_controls)
        print("Controls ARE --------")
        for it, control in enumerate(json_controls):
            control["vulnerability"] = repo_controls[it].vulnerabilities.cve.CVEId
            control["vulnerability_id"] = {"id": control["vulnerability_id"],
                                           "name": repo_controls[it].vulnerabilities.cve.CVEId}
            # print(type(control))
            print(control)

        json_controls = json.dumps(json_controls)
        # print(json_controls)
        new_control_form = FormAddRepoControl()
        return render_template("templates_asset_repo/view_repo_controls.html", repo_controls=json_controls,
                               new_control_form=new_control_form)


@app.route('/repo/security_posture/', methods=['GET', 'POST'])
def view_repo_organisation_security_posture():
    if request.method == 'POST':
        new_security_posture_form = FormEditRepoOrganisationSecurityPosture()
        if new_security_posture_form.id.data:
            try:
                to_edit_security_posture = RepoOrganisationSecurityPosture.query.filter_by(id=new_security_posture_form.id.data).first()
            except SQLAlchemyError:
                return Response("SQLAlchemyError when editing records", 500)
            if new_security_posture_form.validate_on_submit():
                to_edit_security_posture.q1_completedSRA = new_security_posture_form.q1_completedSRA.data
                to_edit_security_posture.q2_include_IS_SRA = new_security_posture_form.q2_include_IS_SRA.data
                to_edit_security_posture.q3_compliance = new_security_posture_form.q3_compliance.data
                to_edit_security_posture.q4_respond = new_security_posture_form.q4_respond.data
                to_edit_security_posture.q5_respond_personnel = new_security_posture_form.q5_respond_personnel.data
                to_edit_security_posture.q6_communicate_responses = new_security_posture_form.q6_communicate_responses.data
                to_edit_security_posture.q7_documented_policies = new_security_posture_form.q7_documented_policies.data
                to_edit_security_posture.q8_reflect_business_practices = new_security_posture_form.q8_reflect_business_practices.data
                to_edit_security_posture.q9_documentation_availability = new_security_posture_form.q9_documentation_availability.data
                to_edit_security_posture.q10_responsible = new_security_posture_form.q10_responsible.data
                to_edit_security_posture.q11_defined_access = new_security_posture_form.q11_defined_access.data
                to_edit_security_posture.q12_member_screening = new_security_posture_form.q12_member_screening.data
                to_edit_security_posture.q13_security_training = new_security_posture_form.q13_security_training.data
                to_edit_security_posture.q14_monitoring_login = new_security_posture_form.q14_monitoring_login.data
                to_edit_security_posture.q15_protection_malicious = new_security_posture_form.q15_protection_malicious.data
                to_edit_security_posture.q16_password_security = new_security_posture_form.q16_password_security.data
                to_edit_security_posture.q17_awareness_training = new_security_posture_form.q17_awareness_training.data
                to_edit_security_posture.q18_sanction_policy = new_security_posture_form.q18_sanction_policy.data
                to_edit_security_posture.q19_personnel_access = new_security_posture_form.q19_personnel_access.data
                to_edit_security_posture.q20_access_to_PHI = new_security_posture_form.q20_access_to_PHI.data
                to_edit_security_posture.q21_kind_of_access = new_security_posture_form.q21_kind_of_access.data
                to_edit_security_posture.q22_use_of_encryption = new_security_posture_form.q22_use_of_encryption.data
                to_edit_security_posture.q23_periodic_review_of_IS = new_security_posture_form.q23_periodic_review_of_IS.data
                to_edit_security_posture.q24_monitor_system_activity = new_security_posture_form.q24_monitor_system_activity.data
                to_edit_security_posture.q25_logoff_policy = new_security_posture_form.q25_logoff_policy.data
                to_edit_security_posture.q26_user_authentication_policy = new_security_posture_form.q26_user_authentication_policy.data
                to_edit_security_posture.q27_unauthorised_modification = new_security_posture_form.q27_unauthorised_modification.data
                to_edit_security_posture.q28_unauthorised_modification_transmitted = new_security_posture_form.q28_unauthorised_modification_transmitted.data
                to_edit_security_posture.q29_manage_facility_access = new_security_posture_form.q29_manage_facility_access.data
                to_edit_security_posture.q30_manage_device_access = new_security_posture_form.q30_manage_device_access.data
                to_edit_security_posture.q31_device_inventory = new_security_posture_form.q31_device_inventory.data
                to_edit_security_posture.q32_validate_facility_access = new_security_posture_form.q32_validate_facility_access.data
                to_edit_security_posture.q33_activity_on_IS_with_PHI = new_security_posture_form.q33_activity_on_IS_with_PHI.data
                to_edit_security_posture.q34_backup_PHI = new_security_posture_form.q34_backup_PHI.data
                to_edit_security_posture.q35_sanitise_disposed_devices = new_security_posture_form.q35_sanitise_disposed_devices.data
                to_edit_security_posture.q36_connected_devices = new_security_posture_form.q36_connected_devices.data
                to_edit_security_posture.q37_necessary_access_rules = new_security_posture_form.q37_necessary_access_rules.data
                to_edit_security_posture.q38_monitor_3rd_access = new_security_posture_form.q38_monitor_3rd_access.data
                to_edit_security_posture.q39_sanitise_new_devices = new_security_posture_form.q39_sanitise_new_devices.data
                to_edit_security_posture.q40_BAA = new_security_posture_form.q40_BAA.data
                to_edit_security_posture.q41_monitor_BA = new_security_posture_form.q41_monitor_BA.data
                to_edit_security_posture.q42_contingency_plan = new_security_posture_form.q42_contingency_plan.data
                to_edit_security_posture.q43_determine_critical_IS = new_security_posture_form.q43_determine_critical_IS.data
                to_edit_security_posture.q44_pdr_security_incidents = new_security_posture_form.q44_pdr_security_incidents.data
                to_edit_security_posture.q45_incident_response_plan = new_security_posture_form.q45_incident_response_plan.data
                to_edit_security_posture.q46_incident_response_team = new_security_posture_form.q46_incident_response_team.data
                to_edit_security_posture.q47_necessary_IS = new_security_posture_form.q47_necessary_IS.data
                to_edit_security_posture.q48_access_when_emergency = new_security_posture_form.q48_access_when_emergency.data
                to_edit_security_posture.q49_backup_plan = new_security_posture_form.q49_backup_plan.data
                to_edit_security_posture.q50_disaster_recovery_plan = new_security_posture_form.q50_disaster_recovery_plan.data


                db.session.commit()
                return redirect("/repo/security_posture/")
            else:
                return Response("SQLAlchemyError", 500)
        else:
            return Response("Not found", 500)
    else:
        if db.session.query(RepoOrganisationSecurityPosture.id).first():
            repo_organisation_security_posture = RepoOrganisationSecurityPosture.query.first()
        else:
            repo_organisation_security_posture = RepoOrganisationSecurityPosture()
            db.session.add(repo_organisation_security_posture)
            db.session.commit()
        new_security_posture_form = FormEditRepoOrganisationSecurityPosture()
        new_security_posture_form.id.data = repo_organisation_security_posture.id
        new_security_posture_form.q1_completedSRA.data = str(repo_organisation_security_posture.q1_completedSRA)
        new_security_posture_form.q2_include_IS_SRA.data = str(repo_organisation_security_posture.q2_include_IS_SRA)
        new_security_posture_form.q3_compliance.data = str(repo_organisation_security_posture.q3_compliance)
        new_security_posture_form.q4_respond.data = str(repo_organisation_security_posture.q4_respond)
        new_security_posture_form.q5_respond_personnel.data = str(repo_organisation_security_posture.q5_respond_personnel)

        new_security_posture_form.q6_communicate_responses.data =str(repo_organisation_security_posture.q6_communicate_responses)
        new_security_posture_form.q7_documented_policies.data =str(repo_organisation_security_posture.q7_documented_policies)
        new_security_posture_form.q8_reflect_business_practices.data =str(repo_organisation_security_posture.q8_reflect_business_practices)
        new_security_posture_form.q9_documentation_availability.data =str(repo_organisation_security_posture.q9_documentation_availability)
        new_security_posture_form.q10_responsible.data =str(repo_organisation_security_posture.q10_responsible)
        new_security_posture_form.q11_defined_access.data =str(repo_organisation_security_posture.q11_defined_access)
        new_security_posture_form.q12_member_screening.data =str(repo_organisation_security_posture.q12_member_screening)
        new_security_posture_form.q13_security_training.data =str(repo_organisation_security_posture.q13_security_training)
        new_security_posture_form.q14_monitoring_login.data =str(repo_organisation_security_posture.q14_monitoring_login)
        new_security_posture_form.q15_protection_malicious.data =str(repo_organisation_security_posture.q15_protection_malicious)
        new_security_posture_form.q16_password_security.data =str(repo_organisation_security_posture.q16_password_security)
        new_security_posture_form.q17_awareness_training.data =str(repo_organisation_security_posture.q17_awareness_training)
        new_security_posture_form.q18_sanction_policy.data =str(repo_organisation_security_posture.q18_sanction_policy)
        new_security_posture_form.q19_personnel_access.data =str(repo_organisation_security_posture.q19_personnel_access)
        new_security_posture_form.q20_access_to_PHI.data =str(repo_organisation_security_posture.q20_access_to_PHI)
        new_security_posture_form.q21_kind_of_access.data =str(repo_organisation_security_posture.q21_kind_of_access)
        new_security_posture_form.q22_use_of_encryption.data =str(repo_organisation_security_posture.q22_use_of_encryption)
        new_security_posture_form.q23_periodic_review_of_IS.data =str(repo_organisation_security_posture.q23_periodic_review_of_IS)
        new_security_posture_form.q24_monitor_system_activity.data =str(repo_organisation_security_posture.q24_monitor_system_activity)
        new_security_posture_form.q25_logoff_policy.data =str(repo_organisation_security_posture.q25_logoff_policy)
        new_security_posture_form.q26_user_authentication_policy.data =str(repo_organisation_security_posture.q26_user_authentication_policy)
        new_security_posture_form.q27_unauthorised_modification.data =str(repo_organisation_security_posture.q27_unauthorised_modification)
        new_security_posture_form.q28_unauthorised_modification_transmitted.data =str(repo_organisation_security_posture.q28_unauthorised_modification_transmitted)
        new_security_posture_form.q29_manage_facility_access.data =str(repo_organisation_security_posture.q29_manage_facility_access)
        new_security_posture_form.q30_manage_device_access.data =str(repo_organisation_security_posture.q30_manage_device_access)
        new_security_posture_form.q31_device_inventory.data =str(repo_organisation_security_posture.q31_device_inventory)
        new_security_posture_form.q32_validate_facility_access.data =str(repo_organisation_security_posture.q32_validate_facility_access)
        new_security_posture_form.q33_activity_on_IS_with_PHI.data =str(repo_organisation_security_posture.q33_activity_on_IS_with_PHI)
        new_security_posture_form.q34_backup_PHI.data =str(repo_organisation_security_posture.q34_backup_PHI)
        new_security_posture_form.q35_sanitise_disposed_devices.data =str(repo_organisation_security_posture.q35_sanitise_disposed_devices)
        new_security_posture_form.q36_connected_devices.data =str(repo_organisation_security_posture.q36_connected_devices)
        new_security_posture_form.q37_necessary_access_rules.data =str(repo_organisation_security_posture.q37_necessary_access_rules)
        new_security_posture_form.q38_monitor_3rd_access.data =str(repo_organisation_security_posture.q38_monitor_3rd_access)
        new_security_posture_form.q39_sanitise_new_devices.data =str(repo_organisation_security_posture.q39_sanitise_new_devices)
        new_security_posture_form.q40_BAA.data =str(repo_organisation_security_posture.q40_BAA)
        new_security_posture_form.q41_monitor_BA.data =str(repo_organisation_security_posture.q41_monitor_BA)
        new_security_posture_form.q42_contingency_plan.data =str(repo_organisation_security_posture.q42_contingency_plan)
        new_security_posture_form.q43_determine_critical_IS.data =str(repo_organisation_security_posture.q43_determine_critical_IS)
        new_security_posture_form.q44_pdr_security_incidents.data =str(repo_organisation_security_posture.q44_pdr_security_incidents)
        new_security_posture_form.q45_incident_response_plan.data =str(repo_organisation_security_posture.q45_incident_response_plan)
        new_security_posture_form.q46_incident_response_team.data =str(repo_organisation_security_posture.q46_incident_response_team)
        new_security_posture_form.q47_necessary_IS.data =str(repo_organisation_security_posture.q47_necessary_IS)
        new_security_posture_form.q48_access_when_emergency.data =str(repo_organisation_security_posture.q48_access_when_emergency)
        new_security_posture_form.q49_backup_plan.data =str(repo_organisation_security_posture.q49_backup_plan)
        new_security_posture_form.q50_disaster_recovery_plan.data =str(repo_organisation_security_posture.q50_disaster_recovery_plan)
        return render_template("templates_asset_repo/view_repo_organisation_security_posture.html",
                               new_security_posture_form=new_security_posture_form)


