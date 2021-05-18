from flask_wtf import FlaskForm, Form
from wtforms import StringField, PasswordField, IntegerField, DateTimeField, BooleanField, SubmitField, FieldList, FormField
from wtforms.validators import DataRequired, Optional
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


# def query_generic_repo_type():
#     return RepoAssetsType.query

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


class FormAddRepoVulnerability(FlaskForm):
    id = IntegerField('Id', widget=HiddenInput(), validators=[Optional()])
    name = StringField('Name', validators=[DataRequired()])
    cve = QuerySelectField(query_factory=query_generic_cve, allow_blank=True, get_label='name')
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
    states = FieldList(FormField(FormAddRepoObjectiveState), min_entries=4, max_entries=10)
    submit = SubmitField("Add new Objective")


class FormAddRepoThreat(FlaskForm):
    id = IntegerField('Id', widget=HiddenInput(), validators=[Optional()])
    name = StringField('Name', validators=[DataRequired()])
    capec = QuerySelectField(query_factory=query_generic_capec, allow_blank=True, get_label='name')
    submit = SubmitField("Add new Threat")


class FormAddRepoAsset(FlaskForm):
    id = IntegerField('Id', widget=HiddenInput(), validators=[Optional()])
    name = StringField('Name', validators=[DataRequired()])
    description = StringField('Description', validators=[Optional()])
    owner = QuerySelectField(query_factory=query_generic_repo_actor, allow_blank=True, get_label='name')
    location = StringField('Location', validators=[Optional()])
    verified = BooleanField('Verified', validators=[Optional()])
    verified_by = QuerySelectField(query_factory=query_generic_repo_actor, allow_blank=True, get_label='name', validators=[Optional()])
    # verified_by = FieldList(
    #     QuerySelectField(query_factory=query_generic_repo_actor, allow_blank=True, get_label='name'), min_entries=3)
    mac_address = StringField("Mac Address", validators=[Optional()])
    has_static_ip = BooleanField('Has Static IP', validators=[Optional()])
    ip = StringField('IP', validators=[Optional()])
    net_group_fk = QuerySelectField(query_factory=query_generic_repo_net_group, allow_blank=True, get_label='name', validators=[Optional()])
    value = IntegerField("Value", validators=[Optional()])
    loss_of_revenue = IntegerField("Loss of revenue", validators=[Optional()])
    additional_expenses = IntegerField("Additional Expenses", validators=[Optional()])
    regulatory_legal = IntegerField("Regulatory Legal", validators=[Optional()])
    customer_service = IntegerField("Customer Service", validators=[Optional()])
    goodwill = IntegerField("Goodwill", validators=[Optional()])
    last_touch_date = DateTimeField("Last Touch", validators=[Optional()])
    type_fk = QuerySelectField(query_factory=query_generic_repo_type, allow_blank=True, get_label='name', validators=[Optional()])
    submit = SubmitField("Add new asset")
