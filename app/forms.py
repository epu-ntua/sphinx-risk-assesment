from flask_wtf import FlaskForm, Form
from wtforms import StringField, PasswordField, IntegerField, DateTimeField, BooleanField, SubmitField, FieldList, \
    FormField, SelectField
from wtforms.validators import DataRequired, Optional, InputRequired
from wtforms.widgets import HiddenInput
from wtforms_sqlalchemy.fields import QuerySelectField
from app.models import *


def query_generic_cve():
    return CommonVulnerabilitiesAndExposures.query


def query_generic_capec():
    return CommonAttackPatternEnumerationClassification.query


def query_generic_repo_actor():
    return RepoActor.query


def query_generic_repo_service():
    return RepoService.query


def query_generic_repo_net_group():
    return RepoNetGroup.query


def query_generic_repo_type():
    return RepoAssetsType.query


def query_generic_repo_vulnerability():
    return VulnerabilityReportVulnerabilitiesLink.query


def query_generic_repo_materialisation():
    return RepoMaterialisation.query


def query_generic_repo_impact():
    return RepoImpact.query


def query_generic_repo_objective():
    return RepoObjective.query


class FormAddRepoActor(FlaskForm):
    id = IntegerField('Id', widget=HiddenInput(), validators=[Optional()])
    name = StringField('Name', validators=[DataRequired()])
    submit = SubmitField("Add new actor")


class FormAddRepoNetGroup(FlaskForm):
    id = IntegerField('Id', widget=HiddenInput(), validators=[Optional()])
    name = StringField('Name', validators=[DataRequired()])
    submit = SubmitField("Add new net group")


class FormAddRepoService(FlaskForm):
    id = IntegerField('Id', widget=HiddenInput(), validators=[Optional()])
    name = StringField('Name', validators=[DataRequired()])
    submit = SubmitField("Add new service")


class FormAddRepoControl(FlaskForm):
    id = IntegerField('Id', widget=HiddenInput(), validators=[Optional()])
    name = StringField('Name', validators=[DataRequired()])
    vulnerability = QuerySelectField(query_factory=query_generic_repo_vulnerability, allow_blank=True, get_label='comments')
    description = StringField('Description')
    submit = SubmitField("Add new control")


class FormAddVulnerabilityReportVulnerabilitiesLink(FlaskForm):
    id = IntegerField('Id', widget=HiddenInput(), validators=[Optional()])
    cve_id = StringField('cve_id', validators=[DataRequired()])
    cve = QuerySelectField(query_factory=query_generic_cve, allow_blank=True, get_label='CVEId')
    VReport_id = StringField('VReport_id', validators=[Optional()])
    VReport_source_component = StringField('VReport_source_component', validators=[Optional()])
    VReport_CVSS_score = StringField('VReport_CVSS_score', validators=[Optional()])
    VReport_assetIp = StringField('VReport_assetIp', validators=[Optional()])
    date = DateTimeField('date', validators=[Optional()])
    submit = SubmitField("Add new Vulnerability")


class FormAddRepoObjectiveState(Form):
    class Meta:
        csrf = False

    id = IntegerField("Id", widget=HiddenInput(), validators=[Optional()])
    name = StringField('Name', validators=[DataRequired()])


class FormAddRepoObjective(FlaskForm):
    id = IntegerField('Id', widget=HiddenInput(), validators=[Optional()])
    name = StringField('Name', validators=[DataRequired()])
    description = StringField('Description')
    states = FieldList(FormField(FormAddRepoObjectiveState), min_entries=3, max_entries=10)
    submit = SubmitField("Add new Objective")


class FormAddRepoImpact(FlaskForm):
    id = IntegerField('Id', widget=HiddenInput(), validators=[Optional()])
    name = StringField('Name', validators=[DataRequired()])
    description = StringField('Description')
    submit = SubmitField("Add new Impact")


class FormAddRepoThreat(FlaskForm):
    id = IntegerField('Id', widget=HiddenInput(), validators=[Optional()])
    name = StringField('Name', validators=[DataRequired()])
    capec = QuerySelectField(query_factory=query_generic_capec, allow_blank=True, get_label='name')
    submit = SubmitField("Add new Threat")


class FormAddRepoMaterialisationConsequence(FlaskForm):
    id = IntegerField('Id', widget=HiddenInput(), validators=[Optional()])
    threat_id = IntegerField('Threat Id', widget=HiddenInput(), validators=[DataRequired()])
    name_materialisation = StringField('Name Materialisation', validators=[DataRequired()])
    name_consequence = StringField('Name Consequence', validators=[DataRequired()])
    submit = SubmitField("Add Materialisation Consequence Pair")


class FormAddRepoMaterialisation(FlaskForm):
    id = IntegerField('Id', widget=HiddenInput(), validators=[Optional()])
    threat_id = IntegerField('Threat Id', widget=HiddenInput(), validators=[DataRequired()])
    name_materialisation = StringField('Name Materialisation', validators=[DataRequired()])
    submit = SubmitField("Add Materialisation")


class FormAddRepoConsequence(FlaskForm):
    id = IntegerField('Id', widget=HiddenInput(), validators=[Optional()])
    threat_id = IntegerField('Threat Id', widget=HiddenInput(), validators=[DataRequired()])
    materialisation_fk = QuerySelectField(query_factory=query_generic_repo_materialisation, allow_blank=False, get_label='name',
                               validators=[DataRequired()])
    name_consequence = StringField('Name Consequence', validators=[DataRequired()])
    submit = SubmitField("Add Consequence")


class FormAddRepoServiceImpact(FlaskForm):
    id = IntegerField('Id', widget=HiddenInput(), validators=[Optional()])
    service_id = IntegerField('Threat Id', widget=HiddenInput(), validators=[DataRequired()])
    impact_fk = QuerySelectField(query_factory=query_generic_repo_impact, allow_blank=False, get_label='name',
                               validators=[DataRequired()])
    submit = SubmitField("Add Impact - Service connection")


class FormAddRepoVulnerabilityControl(FlaskForm):
    id = IntegerField('Id', widget=HiddenInput(), validators=[Optional()])
    vulnerability_id = IntegerField('Vulnerability Id', widget=HiddenInput(), validators=[DataRequired()])
    name_control = StringField('Name Control', validators=[DataRequired()])

    # impact_fk = QuerySelectField(query_factory=query_generic_repo_impact, allow_blank=False, get_label='name',
    #                            validators=[DataRequired()])
    submit = SubmitField("Add Control")


class FormAddRepoConsequenceImpact(FlaskForm):
    id = IntegerField('Id', widget=HiddenInput(), validators=[Optional()])
    impact_fk = QuerySelectField(query_factory=query_generic_repo_impact, allow_blank=False, get_label='name',
                               validators=[DataRequired()])
    submit = SubmitField("Add Impact - Consequence connection")


class FormAddRepoObjectiveImpact(FlaskForm):
    id = IntegerField('Id', widget=HiddenInput(), validators=[Optional()])
    impact_fk = QuerySelectField(query_factory=query_generic_repo_impact, allow_blank=False, get_label='name',
                               validators=[DataRequired()])
    submit = SubmitField("Add Impact - Objective connection")


class FormAddRepoResponse(FlaskForm):
    id = IntegerField('Id', widget=HiddenInput(), validators=[Optional()])
    threat_id = IntegerField('Threat Id', widget=HiddenInput(), validators=[DataRequired()])
    name = StringField('Name', validators=[DataRequired()])
    submit = SubmitField("Add Response")


class FormAddRepoUtility(FlaskForm):
    id = IntegerField('Id', widget=HiddenInput(), validators=[Optional()])
    name = StringField('Name', validators=[DataRequired()])
    submit_utility = SubmitField("Add Utility")


class FormAddRepoUtilityObjective(FlaskForm):
    id = IntegerField('Id', widget=HiddenInput(), validators=[Optional()])
    utility_id = IntegerField('Utility_id', widget=HiddenInput(), validators=[InputRequired()])
    objective = QuerySelectField(query_factory=query_generic_repo_objective, allow_blank=True, get_label='name')
    submit_utility_objective = SubmitField("Add Objective to Utility")


class FormAddRepoAsset(FlaskForm):
    id = IntegerField('Id', widget=HiddenInput(), validators=[Optional()])
    name = StringField('Name', validators=[InputRequired()])
    description = StringField('Description', validators=[Optional()])
    owner = QuerySelectField(query_factory=query_generic_repo_actor, allow_blank=True, get_label='name')
    location = StringField('Location', validators=[Optional()])
    verified = BooleanField('Verified', validators=[Optional()])
    verified_by = QuerySelectField(query_factory=query_generic_repo_actor, allow_blank=True, get_label='name',
                                   validators=[Optional()])
    mac_address = StringField("Mac Address", validators=[Optional()])
    has_static_ip = BooleanField('Has Static IP', validators=[Optional()])
    ip = StringField('IP', validators=[Optional()])
    net_group_fk = QuerySelectField(query_factory=query_generic_repo_net_group, allow_blank=True, get_label='name',
                                    validators=[Optional()])
    value = IntegerField("Value", validators=[Optional()])
    dropdown_dictionary = [('1', 'Low'), ('2', 'Medium'), ('3', 'High')]
    loss_of_revenue = SelectField("Loss of revenue", choices=dropdown_dictionary, default='1', validators=[Optional()])
    additional_expenses = SelectField('Repair time', choices=dropdown_dictionary, default='1', validators=[Optional()])
    dropdown_security_levels = [('1', 'No specific requirements or security protection necessary'), ('2', 'Protection against casual or coincidental violation'), ('3', 'Protection against intentional violation using simple means with low resources, generic skills and low motivation'), ('4', 'Protection against intentional violation using sophisticated means with moderate resources, specific skills and moderate motivation'), ('5', 'Protection against intentional violation using sophisticated means with extended resources, specific skills and high motivation')]
    security_levels = SelectField('Security Levels', choices=dropdown_security_levels, default='1', validators=[Optional()])
    customer_service = IntegerField("Customer Service", validators=[Optional()])
    dropdown_zone = [('1', 'Corporate Intranet'), ('2', 'Business Partners/Clients'), ('3', 'Employee Private networks'), ('4', 'Public space')]
    operating_zone = SelectField('Operating zone', choices=dropdown_zone, default='1', validators=[Optional()])
    last_touch_date = DateTimeField("Last Touch", validators=[Optional()])
    type_fk = QuerySelectField(query_factory=query_generic_repo_type, allow_blank=False, get_label='name',
                               validators=[Optional()])
    integrity = SelectField('Integrity', choices=dropdown_dictionary, default='1', validators=[Optional()])
    availability = SelectField('Availability', choices=dropdown_dictionary, default='1', validators=[Optional()])
    confidentiality = SelectField('Confidentiality', choices=dropdown_dictionary, default='1', validators=[Optional()])
    dropdown_current_status = [('1', 'Active'), ('2', 'Inactive'), ('3', 'Disposed'), ('4', 'Unknown')]
    current_status = SelectField('Status', choices=dropdown_current_status, default='1', validators=[Optional()])
    submit = SubmitField("Add new asset")


class FormEditRepoAsset(FlaskForm):
    edit_id = IntegerField('Id', widget=HiddenInput(), validators=[Optional()])
    edit_name = StringField('Name', validators=[InputRequired()])
    edit_description = StringField('Description', validators=[Optional()])
    edit_owner = QuerySelectField(query_factory=query_generic_repo_actor, allow_blank=True, get_label='name')
    edit_location = StringField('Location', validators=[Optional()])
    edit_verified = BooleanField('Verified', validators=[Optional()])
    edit_verified_by = QuerySelectField(query_factory=query_generic_repo_actor, allow_blank=True, get_label='name',
                                   validators=[Optional()])
    edit_mac_address = StringField("Mac Address", validators=[Optional()])
    edit_has_static_ip = BooleanField('Has Static IP', validators=[Optional()])
    edit_ip = StringField('IP', validators=[Optional()])
    edit_net_group_fk = QuerySelectField(query_factory=query_generic_repo_net_group, allow_blank=True, get_label='name',
                                    validators=[Optional()])
    edit_value = IntegerField("Value", validators=[Optional()])
    edit_dropdown_dictionary = [('1', 'Low'), ('2', 'Medium'), ('3', 'High')]
    edit_loss_of_revenue = SelectField("Loss of revenue", choices=edit_dropdown_dictionary, default='1', validators=[Optional()])
    edit_additional_expenses = SelectField('Repair time', choices=edit_dropdown_dictionary, default='1', validators=[Optional()])
    edit_dropdown_security_levels = [('1', 'No specific requirements or security protection necessary'),
                                ('2', 'Protection against casual or coincidental violation'),
                                ('3', 'Protection against intentional violation using simple means with low resources, generic skills and low motivation'),
                                ('4', 'Protection against intentional violation using sophisticated means with moderate resources, specific skills and moderate motivation'),
                                ('5', 'Protection against intentional violation using sophisticated means with extended resources, specific skills and high motivation')]
    edit_security_levels = SelectField('Security Levels', choices=edit_dropdown_security_levels, default='1',
                                  validators=[Optional()])
    edit_customer_service = IntegerField("Customer Service", validators=[Optional()])
    edit_dropdown_zone = [('1', 'Corporate Intranet'), ('2', 'Business Partners/Clients'), ('3', 'Employee Private networks'), ('4', 'Public space')]
    edit_operating_zone = SelectField('Operating zone', choices=edit_dropdown_zone, default='1', validators=[Optional()])
    edit_last_touch_date = DateTimeField("Last Touch", validators=[Optional()])
    edit_type_fk = QuerySelectField(query_factory=query_generic_repo_type, allow_blank=False, get_label='name',
                               validators=[Optional()])
    edit_integrity = SelectField('Integrity', choices=edit_dropdown_dictionary, default='1', validators=[Optional()])
    edit_availability = SelectField('Availability', choices=edit_dropdown_dictionary, default='1', validators=[Optional()])
    edit_confidentiality = SelectField('Confidentiality', choices=edit_dropdown_dictionary, default='1', validators=[Optional()])
    edit_dropdown_current_status = [('1', 'Active'), ('2', 'Inactive'), ('3', 'Disposed'), ('4', 'Unknown')]
    edit_current_status = SelectField('Status', choices=edit_dropdown_current_status, default='1', validators=[Optional()])
    edit_submit = SubmitField("Edit asset")
