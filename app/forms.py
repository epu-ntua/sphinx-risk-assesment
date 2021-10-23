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
    cve = QuerySelectField(query_factory=query_generic_cve, allow_blank=True, get_label='name')
    VReport_id = StringField('VReport_id', validators=[Optional()])
    VReport_CVSS_score = StringField('VReport_CVSS_score', validators=[Optional()])
    VReport_assetIp = StringField('VReport_assetIp', validators=[Optional()])
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
    loss_of_revenue = IntegerField("Loss of revenue", validators=[Optional()])
    additional_expenses = IntegerField("Additional Expenses", validators=[Optional()])
    regulatory_legal = IntegerField("Regulatory Legal", validators=[Optional()])
    customer_service = IntegerField("Customer Service", validators=[Optional()])
    goodwill = IntegerField("Goodwill", validators=[Optional()])
    last_touch_date = DateTimeField("Last Touch", validators=[Optional()])
    type_fk = QuerySelectField(query_factory=query_generic_repo_type, allow_blank=False, get_label='name',
                               validators=[Optional()])
    dropdown_dictionary = [('1', 'a'), ('2', 'b'), ('3', 'c')]
    integrity = SelectField('Integrity', choices=dropdown_dictionary, default='1', validators=[Optional()])
    submit = SubmitField("Add new asset")
