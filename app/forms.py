from flask_wtf import FlaskForm, Form
from wtforms import StringField, PasswordField, IntegerField, DateTimeField, BooleanField, SubmitField, FieldList, \
    FormField, SelectField, RadioField
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


def query_generic_cve():
    return CommonVulnerabilitiesAndExposures.query

def query_generic_organisation_security_posture_questions():
    return RepoOrganisationSecurityPostureQuestions.query

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
    vulnerability = QuerySelectField(query_factory=query_generic_repo_vulnerability, allow_blank=True, get_label='cve_id')
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


class FormAddCVEtoAsset(FlaskForm):
    id = IntegerField('Id', widget=HiddenInput(), validators=[Optional()])
    cve = QuerySelectField(query_factory=query_generic_cve, allow_blank=False, get_label='CVEId')
    submit = SubmitField("Connect CVE to threat")


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
    edit_submit = SubmitField("Save asset")


class FormEditRepoOrganisationSecurityPosture(FlaskForm):
    id = IntegerField('Id', widget=HiddenInput(), validators=[Optional()])
    dropdown_completedSRA= [('1', 'Yes, once.'), ('2', 'Yes, and we review it periodically and in response to operational changes and/or security incidents.'), ('3', 'Yes, in Ad hoc basis, without regular frequency.'), ('4', 'No / Do not know.')]
    q1_completedSRA = RadioField("1 - Do you have a completed Security Risk Assessment?", choices=dropdown_completedSRA, default=1,
                     validators=[DataRequired()])
    q2_include_IS_SRA = RadioField("2 - Do yo include all information systems in SRA?",
                     choices=[('1', 'Yes. We maintain a complete and well documented inventory'),
                              ('2', 'Yes. Only basic informations.'),
                              ('3', 'No / Do not know.')], default='1', validators=[DataRequired()])
    q3_compliance = RadioField("3 - Have you ever assessed your compliance with security regulations?",
                     choices=[('1', 'Yes (successfully)'),
                              ('2', 'Yes (partially)'),
                              ('3', 'No / Do not know.')], default='1', validators=[DataRequired()])
    q4_respond = RadioField("4 - Do you respond to the threat and vulnerabilities identified in your business?",
                     choices=[('1', 'Yes. We try to act proactively and we also maintain the relevant documentation.'),
                              ('2', 'Yes. We try to act proactively.'),
                              ('3', 'No. We respond only if an incident occures.')], default='1', validators=[DataRequired()])
    q5_respond_personnel = RadioField("5 - Do you identify specific personnel to respond to the threats and vulnerabilities?",
                     choices=[('1', 'Yes, we have indicated specific workforce members to respond to and mitigate all threats and vulnerabilities.'),
                              ('2', 'Yes, individual efforts.'),
                              ('3', 'No / Do not know.')], default='1', validators=[DataRequired()])
    q6_communicate_responses = RadioField("6 - Do you communicate them the results?", choices=[('1', 'Yes'), ('2', 'No / Do not know.')], default='1', validators=[DataRequired()])
    q7_documented_policies = RadioField("7 - Do you maintain documentation of security policies and procedures?", choices=[('1', 'Yes, and we review it periodically as necessary.'), ('2', 'Yes, we have created a documentation once for the some policies/procedures.'), ('3', 'No / Do not know.')], default = '1', validators = [DataRequired()])
    q8_reflect_business_practices = RadioField("8 - Does the documentation reflect the actual business practices?", choices=[('1', 'Yes'), ('2', 'Yes, most of them.'), ('3', 'No / Do not know.')], default='1', validators=[DataRequired()])
    q9_documentation_availability = RadioField("9 - Do you secure that it is available to those who need it?", choices=[('1', 'Yes'), ('2', 'No / Do not know.')], default = '1', validators=[DataRequired()])
    q10_responsible = RadioField("10 - Who within your practice is responsible for developing and implmenting IS policies and procedures?", choices=[('1', 'Security officer.'), ('2', 'A member of IT department.'), ('3', 'No-one / Do not know.')], default='1', validators=[DataRequired()])
    q11_defined_access = RadioField("11 - How are roles and job duties defined to accessing Personal Health Information (PHI)?", choices=[('1', 'Clear documentation for all staff members'), ('2', 'Defined only per job roles'), ('3', 'No roles are defined.')], default='1', validators=[DataRequired()])
    q12_member_screening = RadioField("12 - Do you screen your workforce members to verify trustworthiness?", choices=[('1', 'Yes'), ('2', 'No / Do not know.')], default='1', validators=[DataRequired()])
    q13_security_training = RadioField("13 - Do you ensure that all workforce members are given security training?", choices=[('1', 'Yes, there is a list with all the completed security trainings per workforce member.'), ('2', 'Yes, only for IT department.'), ('3', 'No / Do not know.')], default='1', validators=[DataRequired()])
    q14_monitoring_login = RadioField("14 - Do you have procedures for monitoring log-in attempts and reporting discrepancies?", choices=[('1', 'Yes, using tools and having defined respond measures'), ('2', 'Yes, but not actively utilised.'), ('3', 'No / Do not know.')], default='1', validators=[DataRequired()])
    q15_protection_malicious = RadioField("15 - Is protection from malicious software (antivirus/security updates and malware protection) covered in your procedures?", choices=[('1', 'Yes, using tools and having defined respond measures'), ('2', 'Yes, but not actively utilised.'), ('3', 'No / Do not know.')], default='1', validators=[DataRequired()])
    q16_password_security = RadioField("16 - What password security policy do you implement in your security procedures?", choices=[('1', 'Strict, following best practices.'), ('2', 'Loose.'), ('3', 'Password security is not covered in security procedures.')], default='1', validators=[DataRequired()])
    q17_awareness_training = RadioField("17 - Do you have ongoing awareness trainings?", choices=[('1', 'Yes'), ('2', 'No / Do not know.')], default='1', validators=[DataRequired()])
    q18_sanction_policy = RadioField("18 - Do you have a sanction policy?", choices=[('1', 'Yes'), ('2', 'No / Do not know.')], default='1', validators=[DataRequired()])
    q19_personnel_access = RadioField("19 - How do you manage and control personnel access to PHI, IS and facilities?", choices=[('1', 'Detailed logs based on role'), ('2', 'Access by role.'), ('3', 'Other.')], default='1', validators=[DataRequired()])
    q20_access_to_PHI = RadioField("20 - Do you have a process for authorising, establishing and modifying access to PHI?", choices=[('1', 'Yes, designeted personnel provide the relevant access level, which is reviewed as needed'), ('2', 'No / Do not know.')], default='1', validators=[DataRequired()])
    q21_kind_of_access = RadioField("21 - What kind of access to PHI is granted?", choices=[('1', "The necessary access levels, based on the user's role."), ('2', 'Access based on duties and activities.'), ('3', 'No limit.')], default='1', validators=[DataRequired()])
    q22_use_of_encryption = RadioField("22 - Do you use encryption to control access to PHI?", choices=[('1', 'Yes, when deemed reasonable and appropriate.'), ('2', 'No / Do not know.')], default='1', validators=[DataRequired()])
    q23_periodic_review_of_IS = RadioField("23 - Do you periodically review your information systems for how security settings can be implemented to safeguard PHI?", choices=[('1', 'Yes'), ('2', 'No / Do not know.')], default='1', validators=[DataRequired()])
    q24_monitor_system_activity = RadioField("24 - How do you monitor systems activity?", choices=[('1', "Monitoring user's activity, access attempts and modifications"), ('2', "Identify only user's presence within the systems."), ('3', 'None, of the above.')], default='1', validators=[DataRequired()])
    q25_logoff_policy = RadioField("25 - Do you have automatic logoff on devices and platforms accessing PHI?", choices=[('1', 'Yes, on all devices'), ('2', 'Yes, in some devices.'), ('3', 'No / Do not know.')], default='1', validators=[DataRequired()])
    q26_user_authentication_policy = RadioField("26 - How do you ensure users accessing PHI are who they claim to be?", choices=[('1', 'Authentication based on our policies.'), ('2', 'Users do not always use unique authentication (sharing user id).')], default='1', validators=[DataRequired()])
    q27_unauthorised_modification = RadioField("27 - Do you protect PHI from unauthorised modification?", choices=[('1', 'Yes'), ('2', 'No / Do not know.')], default='1', validators=[DataRequired()])
    q28_unauthorised_modification_transmitted = RadioField("28 - Do you protect PHI from unauthorised modification when it is being transmitted?", choices=[('1', 'Yes'), ('2', 'No / Do not know.')], default='1', validators=[DataRequired()])
    q29_manage_facility_access = RadioField("29 - Do you manage access to and use of your facility ?", choices=[('1', 'Yes'), ('2', 'No / Do not know.')], default='1', validators=[DataRequired()])
    q30_manage_device_access = RadioField("30 - Do you manage access to electronic devices?", choices=[('1', 'Yes'), ('2', 'No / Do not know.')], default='1', validators=[DataRequired()])
    q31_device_inventory = RadioField("31 - Do you keep an inventory and a location record of all electronic devices?", choices=[('1', 'Yes'), ('2', 'No / Do not know.')], default='1', validators=[DataRequired()])
    q32_validate_facility_access = RadioField("32 - Do you validate a persons' access to facilities based on their role or function?", choices=[('1', 'Yes'), ('2', 'No / Do not know.')], default='1', validators=[DataRequired()])
    q33_activity_on_IS_with_PHI = RadioField("33 - Do you have mechanisms that record and examine activity on IS with access to PHI?", choices=[('1', 'Yes'), ('2', 'No / Do not know.')], default='1', validators=[DataRequired()])
    q34_backup_PHI = RadioField("34 - Do you maintain back up of PHI to ensure availability when devices are moved?", choices=[('1', 'Yes, centrally stored'), ('2', 'Yes, on portable storage devices.'), ('3', 'None, of the above.')], default='1', validators=[DataRequired()])
    q35_sanitise_disposed_devices = RadioField("35 - When disposing devices, do you ensure that are effectively sanitised?", choices=[('1', 'Yes'), ('2', 'No / Do not know.')], default='1', validators=[DataRequired()])
    q36_connected_devices = RadioField("36 - How do you determine what is considered appropriate use of connected network devices?", choices=[('1', 'Our well documented Policies and procedures define properly who and how each device access the network.'), ('2', 'We inform workforce about best practices.'), ('3', 'Do not have any policy.')], default='1', validators=[DataRequired()])
    q37_necessary_access_rules = RadioField("37 - Do you ensure access to PHI is terminated when workforce members do not meet the necessary access rules?", choices=[('1', 'Yes'), ('2', 'No / Do not know.')], default='1', validators=[DataRequired()])
    q38_monitor_3rd_access = RadioField("38 - Do you regularly check the third-party access to PHI, based on their contracts?", choices=[('1', 'Yes'), ('2', 'No / Do not know.')], default='1', validators=[DataRequired()])
    q39_sanitise_new_devices = RadioField("39 - Is there a process to ensure media is sanitised prior to enter the network?", choices=[('1', 'Yes'), ('2', 'No / Do not know.')], default='1', validators=[DataRequired()])
    q40_BAA = RadioField("40 - Do you secure a Business associates Agreement with business associates and/or third-party vendors, before they aquire access to your network and PHI?", choices=[('1', 'Yes'), ('2', 'No / Do not know.')], default='1', validators=[DataRequired()])
    q41_monitor_BA = RadioField("41 - Does your practice monitor access for each associate?", choices=[('1', 'Yes'), ('2', 'No / Do not know.')], default='1', validators=[DataRequired()])
    q42_contingency_plan = RadioField("42 - Does your practice have an up-to-date documented contingency plan in the event of an emergency?", choices=[('1', 'Yes'), ('2', 'No / Do not know.')], default='1', validators=[DataRequired()])
    q43_determine_critical_IS = RadioField("43 - Have you considered what kind of emergencies could damage critical IS or prevent access to PHI?", choices=[('1', 'Yes'), ('2', 'No / Do not know.')], default='1', validators=[DataRequired()])
    q44_pdr_security_incidents = RadioField("44 - Does your practice have policies and procedures in place to prevent, detect, and respond to security incidents?", choices=[('1', 'Yes'), ('2', 'No / Do not know.')], default='1', validators=[DataRequired()])
    q45_incident_response_plan = RadioField("45 - Does your practice have an up-to-date documented incident response plan?", choices=[('1', 'Yes'), ('2', 'No / Do not know.')], default='1', validators=[DataRequired()])
    q46_incident_response_team = RadioField("46 - Has your practice specified the members of incident response team?", choices=[('1', 'Yes'), ('2', 'No / Do not know.')], default='1', validators=[DataRequired()])
    q47_necessary_IS = RadioField("47 - Has your practice determined which IS are necessary for maintaining business-as-usual in the event of an emergency?", choices=[('1', 'Yes'), ('2', 'No / Do not know.')], default='1', validators=[DataRequired()])
    q48_access_when_emergency = RadioField("48 - How is your practice maintain access to PHI in the event of an emergency, system failure, or physical disaster?", choices=[('1', 'There are defined procedures and alternative mechanisms in place'), ('2', 'There is not a specific approach.')], default='1', validators=[DataRequired()])
    q49_backup_plan = RadioField("49 - Is there a plan for backing up and restoring critical data?", choices=[('1', 'Yes, there is a plan.'), ('2', 'No, there is not / Do not know.')], default='1', validators=[DataRequired()])
    q50_disaster_recovery_plan = RadioField("50 - Does your practice have an up-to-date documented disaster and recovery plan in the event of an emergency?", choices=[('1', 'Yes'), ('2', 'No / Do not know.')], default='1', validators=[DataRequired()])
    submit = SubmitField("Save")
