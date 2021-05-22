from app import db


# from app.mixins import ModelMixin

class VulnerabilityReport(db.Model):
    __tablename__ = 'vulnerability_report'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    reportId = db.Column(db.String(), index=True, unique=True)
    creation_time = db.Column(db.String())
    name = db.Column(db.String())
    comments = db.Column(db.String())

    # CVEs = db.relationship("VReportCVELink", back_populates="vreport_s")

    def __repr__(self):
        return '<VaasReport {}>'.format(self.reportId)


class CommonVulnerabilitiesAndExposures(db.Model):
    __tablename__ = 'common_vulnerabilities_and_exposures'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    CVEId = db.Column(db.String(), index=True, unique=True)
    description = db.Column(db.String(), index=True)
    status = db.Column(db.String())
    accessVector = db.Column(db.String())
    accessComplexity = db.Column(db.String())
    authentication = db.Column(db.String())
    confidentialityImpact = db.Column(db.String())
    integrityImpact = db.Column(db.String())
    availabilityImpact = db.Column(db.String())
    baseScore = db.Column(db.Float)
    severity = db.Column(db.String())
    exploitabilityScore = db.Column(db.Float)
    impactScore = db.Column(db.Float)
    obtainAllPrivilege = db.Column(db.Boolean)
    obtainUserPrivilege = db.Column(db.Boolean)
    obtainOtherPrivilege = db.Column(db.Boolean)
    userInteractionRequired = db.Column(db.Boolean)

    # # Relationships
    # VReports = db.relationship("VReportCVELink", back_populates="cve_s")

    def __repr__(self):
        return '<CVE {}>'.format(self.CVEId)


class VulnerabilityReportVulnerabilitiesLink(db.Model):
    __tablename__ = 'vulnerability_report_vulnerabilities_link'
    vreport_id = db.Column(db.Integer, db.ForeignKey('vulnerability_report.id'), primary_key=True)
    cve_id = db.Column(db.Integer, db.ForeignKey('common_vulnerabilities_and_exposures.id'), primary_key=True)
    VReport_assetID = db.Column(db.String())
    VReport_assetIp = db.Column(db.String())
    VReport_port = db.Column(db.String())
    comments = db.Column(db.String(50))

    #     cve_s = db.relationship("CVE", back_populates="VReports")
    #     vreport_s = db.relationship("VReport", back_populates="CVEs")

    def __repr__(self):
        return '<VulnerabilityReportVulnerabilitiesLink {}>'.format(self.vreport_id)


class CommonWeaknessEnumeration(db.Model):
    __tablename__ = 'common_weakness_enumeration'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    CWEId = db.Column(db.String(), index=True, unique=True)
    name = db.Column(db.String())
    weakness = db.Column(db.String())
    abstraction = db.Column(db.String())
    status = db.Column(db.String())
    description = db.Column(db.String())
    extendedDescription = db.Column(db.String())
    relatedWeaknesses = db.Column(db.String())
    weaknessOrdinalities = db.Column(db.String())
    applicablePlatforms = db.Column(db.String())
    backgroundDetails = db.Column(db.String())
    alternateTerms = db.Column(db.String())
    modesOfIntroduction = db.Column(db.String())
    exploitationFactors = db.Column(db.String())
    likelihoodOfExploit = db.Column(db.String())
    commonConsequences = db.Column(db.String())
    detectionMethods = db.Column(db.String())
    potentialMitigations = db.Column(db.String())
    observedExamples = db.Column(db.String())
    functionalAreas = db.Column(db.String())
    affectedResources = db.Column(db.String())
    taxonomyMappings = db.Column(db.String())
    relatedAttackPatterns = db.Column(db.String())
    notes = db.Column(db.String())

    def __repr__(self):
        return '<CWE {}>'.format(self.CWEId)


class CommonAttackPatternEnumerationClassification(db.Model):
    __tablename__ = 'common_attack_pattern_enumeration_classification'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    capecId = db.Column(db.String(), index=True, unique=True)
    name = db.Column(db.String())
    abstraction = db.Column(db.String())
    status = db.Column(db.String())
    description = db.Column(db.String())
    alternateTerms = db.Column(db.String())
    likelihoodOfAttack = db.Column(db.String())
    typicalSeverity = db.Column(db.String())
    relatedAttackpatterns = db.Column(db.String())
    executionFlow = db.Column(db.String())
    prerequisites = db.Column(db.String())
    skillsRequired = db.Column(db.String())
    resourcesRequired = db.Column(db.String())
    indicators = db.Column(db.String())
    consequences = db.Column(db.String())
    mitigations = db.Column(db.String())
    exampleInstances = db.Column(db.String())
    relatedWeaknesses = db.Column(db.String())
    taxonomyMappings = db.Column(db.String())
    notes = db.Column(db.String())

    def __repr__(self):
        return '<CAPEC {}>'.format(self.capecId)


# ---------------------------------------------------------------------------------------------------------------------
class VulnerabilitiesWeaknessLink(db.Model):
    __tablename__ = 'vulnerabilities_weakness_link'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    cve_id = db.Column(db.Integer, db.ForeignKey('common_vulnerabilities_and_exposures.id'), nullable=False)
    cwe_id = db.Column(db.Integer, db.ForeignKey('common_weakness_enumeration.id'), nullable=False)
    date = db.Column(db.DateTime)

    def __repr__(self):
        return '<cVecWe {}>'.format(self.id)


# class HardwareAsset(db.Model):
#     __tablename__ = 'hardware_asset'
#     id = db.Column(db.Integer, primary_key=True, autoincrement=True)
#     assetID = db.Column(db.String())
#     assetIp = db.Column(db.String())
#     date = db.Column(db.DateTime)
#     assetName = db.Column(db.String())
#     assetModel = db.Column(db.String())
#     assetSerialNumber = db.Column(db.String())
#     assetRecoveryKey = db.Column(db.String())
#     assetVendor = db.Column(db.String())
#     assetDomain = db.Column(db.String())
#     assetWarranty = db.Column(db.String())
#     assetWarrantyExpDate = db.Column(db.DateTime())
#     assetStatus = db.Column(db.Integer, db.ForeignKey('asset_hardware_status.AssetHardwareStatusID'))
#     assetType = db.Column(db.Integer, db.ForeignKey('asset_hardware_type.AssetHardwareTypeID'))
#     assetPurchasePrice = db.Column(db.Float())
#     assetPurchaseDate = db.Column(db.DateTime)
#     assetCreatedBy = db.Column(db.String())
#     assetCreatedDate = db.Column(db.DateTime)
#     assetAssignedTo = db.Column(db.String())
#     assetManagedBy = db.Column(db.String())
#     assetOwner = db.Column(db.String())
#     assetUsageType = db.Column(db.String())  # --add hoc or permanent
#     assetLocation = db.Column(db.String())
#     assetClassification = db.Column(db.Integer, db.ForeignKey('asset_classification.AssetClassificationID'))
#     assetInformationProcessed = db.Column(db.String())  # --Personal or Business
#
#     def __repr__(self):
#         return '<HardwareAsset {}>'.format(self.id)
#
#
# class AssetHardwareStatus(db.Model):
#     __tablename__ = 'asset_hardware_status'
#     AssetHardwareStatusID = db.Column(db.Integer, primary_key=True, autoincrement=True)
#     AssetHardwareStatusDescr = db.Column(db.String())
#     AssetHardwareStatusInsertedDate = db.Column(db.DateTime)
#
#     def __repr__(self):
#         return '<AssetHardwareStatus {}>'.format(self.AssetHardwareStatusID)
#
#
# class AssetHardwareType(db.Model):
#     __tablename__ = 'asset_hardware_type'
#     AssetHardwareTypeID = db.Column(db.Integer, primary_key=True, autoincrement=True)
#     AssetHardwareTypeDescr = db.Column(db.String())
#     AssetHardwareTypeInsertedDate = db.Column(db.DateTime)
#
#     def __repr__(self):
#         return '<AssetHardwareType {}>'.format(self.AssetHardwareTypeID)
#
#
# class AssetClassification(db.Model):
#     __tablename__ = 'asset_classification'
#     AssetClassificationID = db.Column(db.Integer, primary_key=True, autoincrement=True)
#     AssetClassificationDescr = db.Column(db.String())
#     AssetClassificationInsertedDate = db.Column(db.DateTime)
#
#     def __repr__(self):
#         return '<AssetClassification {}>'.format(self.AssetClassificationID)
#
#
# class SoftwareAsset(db.Model):
#     __tablename__ = 'software_asset'
#     id = db.Column(db.Integer, primary_key=True, autoincrement=True)
#     softwareName = db.Column(db.String())
#     softwareManufacturer = db.Column(db.String())
#     softwareCategory = db.Column(db.String())
#     softwareType = db.Column(db.Integer, db.ForeignKey('asset_software_type.AssetSoftwareTypeID'))
#     softwarePurchaseDate = db.Column(db.DateTime)
#     softwareInstalled = db.Column(db.String())
#
#     def __repr__(self):
#         return '<SoftwareAsset {}>'.format(self.id)
#
#
# class AssetSoftwareType(db.Model):
#     __tablename__ = 'asset_software_type'
#     AssetSoftwareTypeID = db.Column(db.Integer, primary_key=True, autoincrement=True)
#     AssetSoftwareTypeshortDescr = db.Column(db.String())
#     AssetSoftwareTypeDescr = db.Column(db.String())
#     AssetSoftwareTypeInsertedDate = db.Column(db.DateTime)
#
#     def __repr__(self):
#         return '<AssetSoftwareType {}>'.format(self.AssetSoftwareTypeID)

# ---------------------------------------------------------------------------------------------------------------------


# class RiskAssessment(db.Model):
#     __tablename__ = 'risk_assessment'
#     id = db.Column(db.Integer, primary_key=True, autoincrement=True)
#     # asset_id = db.Column(db.Integer, db.ForeignKey('hardware_asset.id'), nullable=False)
#     date = db.Column(db.DateTime)
#
#     def __repr__(self):
#         return '<Risk_Assessment {}>'.format(self.id)


# class RiskVulnerabilityThreat(db.Model):
#     __tablename__ = 'risk_vulnerability_threat'
#     id = db.Column(db.Integer, primary_key=True, autoincrement=True)
#     risk_id = db.Column(db.Integer, db.ForeignKey('risk_assessment.id'), nullable=False)
#     CVE_id = db.Column(db.Integer, db.ForeignKey('common_vulnerabilities_and_exposures.id'), nullable=False)
#     CAPEC_id = db.Column(db.Integer, db.ForeignKey('common_attack_pattern_enumeration_classification.id'),
#                          nullable=False)
#     date = db.Column(db.DateTime)
#
#     def __repr__(self):
#         return '<Risk_Vulnerability_Threat {}>'.format(self.id)
class RepoRiskThreatAssetMaterialisation(db.Model):
    __tablename__ = "repo_risk_threat_asset_materialisation"
    repo_asset_id = db.Column(db.Integer, db.ForeignKey('repo_asset.id'), primary_key=True)
    repo_threat_id = db.Column(db.Integer, db.ForeignKey('repo_threat.id'), primary_key=True)
    repo_response_id = db.Column(db.Integer, db.ForeignKey('repo_response.id'), primary_key=True)
    repo_materialisation_id = db.Column(db.Integer, db.ForeignKey('repo_materialisation.id'), primary_key=True)
    threat_occurrence = db.Column(db.Boolean(), primary_key=True)
    prob = db.Column(db.Integer)


class RepoRiskThreatAssetConsequence(db.Model):
    __tablename__ = "repo_risk_threat_asset_consequence"
    repo_asset_id = db.Column(db.Integer, db.ForeignKey('repo_asset.id'), primary_key=True)
    repo_threat_id = db.Column(db.Integer, db.ForeignKey('repo_threat.id'), primary_key=True)
    repo_response_id = db.Column(db.Integer, db.ForeignKey('repo_response.id'), primary_key=True)
    repo_consequence_id = db.Column(db.Integer, db.ForeignKey('repo_consequence.id'), primary_key=True)
    threat_occurrence = db.Column(db.Boolean(), primary_key=True)
    prob = db.Column(db.Integer)


class RepoAssetRepoThreatRelationship(db.Model):
    __tablename__ = 'repo_asset_repo_threat_relationship'
    repo_asset_id = db.Column(db.Integer, db.ForeignKey('repo_asset.id'), primary_key=True)
    repo_threat_id = db.Column(db.Integer, db.ForeignKey('repo_threat.id'), primary_key=True)
    asset = db.relationship('RepoAsset', back_populates='threats')
    threat = db.relationship('RepoThreat', back_populates='assets')
    skill_level = db.Column(db.Integer, nullable=True)
    motive = db.Column(db.Integer, nullable=True)
    opportunity = db.Column(db.Integer, nullable=True)
    ease_of_discovery = db.Column(db.Integer, nullable=True)
    ease_of_exploit = db.Column(db.Integer, nullable=True)
    awareness = db.Column(db.Integer, nullable=True)


# db.Table('repo_asset_repo_threat_association_table', db.Model.metadata,
#                                                     db.Column('repo_asset_id', db.Integer,
#                                                               db.ForeignKey('repo_asset.id')),
#                                                     db.Column('repo_threat_id', db.Integer,
#                                                               db.ForeignKey('repo_threat.id'))
#                                                     )

class RepoThreat(db.Model):
    __tablename__ = 'repo_threat'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String)
    CAPEC_id = db.Column(db.Integer, db.ForeignKey('common_attack_pattern_enumeration_classification.id'))
    assets = db.relationship("RepoAssetRepoThreatRelationship", back_populates="threat")
    prob = db.Column(db.Integer)
    user_prob = db.Column(db.Integer)


class RepoResponse(db.Model):
    """ Responses are intrinsically tied to the threats and therefore are unique for each one"""
    __tablename__ = 'repo_response'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String)
    threat_id = db.Column(db.Integer, db.ForeignKey('repo_threat.id'))


class RepoMaterialisation(db.Model):
    """ Materialisations are intrinsically tied to the threats and assets and therefore are unique for each one"""
    __tablename__ = 'repo_materialisation'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String)
    threat_id = db.Column(db.Integer, db.ForeignKey('repo_threat.id'))


class RepoConsequence(db.Model):
    """ Consequences are intrinsically tied to the threat materialisation and assets and therefore are unique for each one"""
    __tablename__ = 'repo_consequence'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String)
    threat_id = db.Column(db.Integer, db.ForeignKey('repo_threat.id'))
    materialisation_id = db.Column(db.Integer, db.ForeignKey('repo_materialisation.id'))


class RepoVulnerability(db.Model):
    __tablename__ = 'repo_vulnerability'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String)
    CVE_id = db.Column(db.Integer, db.ForeignKey('common_vulnerabilities_and_exposures.id'))


repo_asset_repo_service_association_table = db.Table('repo_asset_repo_service_association_table', db.Model.metadata,
                                                     db.Column('repo_asset_id', db.Integer,
                                                               db.ForeignKey('repo_asset.id')),
                                                     db.Column('repo_service_id', db.Integer,
                                                               db.ForeignKey('repo_service.id'))
                                                     )


class RepoAsset(db.Model):
    __tablename__ = 'repo_asset'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String)
    description = db.Column(db.String)
    owner = db.Column(db.Integer, db.ForeignKey('repo_actor.id'))
    location = db.Column(db.String)
    verified = db.Column(db.Boolean)
    verified_by = db.Column(db.Integer, db.ForeignKey('repo_actor.id'))
    mac_address = db.Column(db.String)
    has_static_ip = db.Column(db.Boolean)
    ip = db.Column(db.String)
    net_group_fk = db.Column(db.Integer, db.ForeignKey('repo_net_group.id'))
    value = db.Column(db.Integer)
    loss_of_revenue = db.Column(db.Integer)
    additional_expenses = db.Column(db.Integer)
    regulatory_legal = db.Column(db.Integer)
    customer_service = db.Column(db.Integer)
    goodwill = db.Column(db.Integer)
    last_touch_date = db.Column(db.DateTime)
    type_fk = db.Column(db.Integer, db.ForeignKey('repo_assets_type.id'))
    services = db.relationship("RepoService", secondary=repo_asset_repo_service_association_table,
                               back_populates="assets")
    threats = db.relationship("RepoAssetRepoThreatRelationship",
                              back_populates="asset")


class RepoAssetsType(db.Model):
    __tablename__ = 'repo_assets_type'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String)


class RepoActor(db.Model):
    __tablename__ = 'repo_actor'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String)

    # def keys(self):
    #     return super().keys()


class RepoNetGroup(db.Model):
    __tablename__ = 'repo_net_group'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String)


class RepoService(db.Model):
    __tablename__ = 'repo_service'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String)
    assets = db.relationship("RepoAsset", secondary=repo_asset_repo_service_association_table,
                             back_populates="services")


class RepoImpact(db.Model):
    __tablename__ = 'repo_impact'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    description = db.Column(db.String, nullable=True)
    name = db.Column(db.String, nullable=False)


class RepoObjective(db.Model):
    __tablename__ = 'repo_objective'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    description = db.Column(db.String, nullable=True)
    name = db.Column(db.String, nullable=False)
    # status = db.relationship('modelObjectivesOptions', backref='objective', lazy=True)
    # instances = db.relationship("ModelObjectiveAssociation", back_populates="objective")


class RepoObjectivesOptions(db.Model):
    __tablename__ = 'repo_objectives_options'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String, nullable=False)
    objective_fk = db.Column(db.Integer, db.ForeignKey('model_objective.id'), nullable=False)
    alert_level = db.Column(db.Integer, nullable=True,
                            default=0)  # 0-No Alert #1-Oddness3> #2-RareThanRare #3-Rare #4-Possible #5-Certain
    prob_likelihood = db.Column(db.Integer, nullable=True)


class ModelThreatExposure(db.Model):
    __tablename__ = 'model_threat_exposure'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String, nullable=False)
    probability = db.Column(db.Integer, nullable=False)  # Probability that this thread appears
    description = db.Column(db.String, nullable=True)

    instance = db.relationship("ModelInstance", uselist=False, back_populates="threat")


class ModelIncidentResponse(db.Model):
    __tablename__ = 'model_incident_response'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String, nullable=False)
    description = db.Column(db.String, nullable=True)
    default_effect = db.Column(db.Integer, nullable=True)

    instances = db.relationship("ModelIncidentResponseAssociation", back_populates="incident_response")


class ModelThreatMaterialisation(db.Model):
    __tablename__ = 'model_threat_materialisation'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String, nullable=False)
    # Default Probability that this materialisation appears maybe not needed/cant be sources
    probability = db.Column(db.Integer)
    description = db.Column(db.String, nullable=True)

    instances = db.relationship("ModelThreatMaterialisationAssociation", back_populates="threat_materialisation")


class ModelConsequence(db.Model):
    __tablename__ = 'model_consequence'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String, nullable=False)
    description = db.Column(db.String, nullable=True)
    instances = db.relationship("ModelConsequenceAssociation", back_populates="consequence")

    # TO be enabled when asset repository is finished
    # asset = db.Column(db.Integer, db.ForeignKey())


# model Asset status table has all the different status of a single model asset since they are dynamic
class ModelConsequenceStatus(db.Model):
    __tablename__ = 'model_consequence_status'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String, nullable=False)
    consequence_fk = db.Column(db.Integer, db.ForeignKey('model_consequence.id'), nullable=False)


# Table to store list of initial consequence status
# This isnt currently needed but may be in the future
# class ModelConsequenceStatusList(db.Model):
#     __tablename__ = 'model_consequence_status_list'
#     id = db.Column(db.Integer, primary_key=True, autoincrement=True)
#     name = db.Column(db.String, nullable=False)


# High level model assets describing business logic or high level assets like doctors or patients(not network assets)
class ModelAsset(db.Model):
    __tablename__ = 'model_asset'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String, nullable=False)


# model Asset status table has all the different status of a single model asset since they are dynamic
class ModelAssetStatus(db.Model):
    __tablename__ = 'model_asset_status'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String, nullable=False)
    asset_fk = db.Column(db.Integer, db.ForeignKey('model_asset.id'), nullable=False)
    prob_likelihood = db.Column(db.Integer, nullable=True)


class ModelImpact(db.Model):
    __tablename__ = 'model_impact'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String, nullable=False)
    instances = db.relationship("ModelImpactAssociation", back_populates="impact")


class ModelImpactStatus(db.Model):
    __tablename__ = 'model_impact_status'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String, nullable=False)
    impact_fk = db.Column(db.Integer, db.ForeignKey('model_impact.id'), nullable=False)
    prob_likelihood = db.Column(db.Integer, nullable=True)


class ModelObjective(db.Model):
    __tablename__ = 'model_objective'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String, nullable=False)
    # status = db.relationship('modelObjectivesOptions', backref='objective', lazy=True)
    instances = db.relationship("ModelObjectiveAssociation", back_populates="objective")


class ModelObjectivesOptions(db.Model):
    __tablename__ = 'model_objectives_options'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String, nullable=False)
    objective_fk = db.Column(db.Integer, db.ForeignKey('model_objective.id'), nullable=False)
    prob_likelihood = db.Column(db.Integer, nullable=True)


# endregion
#  region Dynamic model Models

# # This table serves as the main model for a single instance of a model model
# # Each Instance corresponds to a single threat and contains all the necessary links
# # To all the relevant nodes
class ModelInstance(db.Model):
    __tablename__ = 'model_instance'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)

    # Threat Exposure One To One Relationship
    threat_id = db.Column(db.Integer, db.ForeignKey('model_threat_exposure.id'))
    threat = db.relationship("ModelThreatExposure", back_populates="instance")

    # Threat Materialisation Many To Many Relationship
    threat_materialisations = db.relationship("ModelThreatMaterialisationAssociation", back_populates="instance")
    incident_responses = db.relationship("ModelIncidentResponseAssociation", back_populates="instance")
    consequences = db.relationship("ModelConsequenceAssociation", back_populates="instance")
    impacts = db.relationship("ModelImpactAssociation", back_populates="instance")
    objectives = db.relationship("ModelObjectiveAssociation", back_populates="instance")


class ModelThreatMaterialisationAssociation(db.Model):
    __tablename__ = "model_threat_materialisation_association"
    instance_id = db.Column(db.Integer, db.ForeignKey('model_instance.id'), primary_key=True)
    threat_materialisation_id = db.Column(db.Integer, db.ForeignKey('model_threat_materialisation.id'),
                                          primary_key=True)
    instance = db.relationship("ModelInstance", back_populates="threat_materialisations")
    threat_materialisation = db.relationship("ModelThreatMaterialisation", back_populates="instances")


class ModelIncidentResponseAssociation(db.Model):
    __tablename__ = "model_incident_response_association"
    instance_id = db.Column(db.Integer, db.ForeignKey('model_instance.id'), primary_key=True)
    incident_response_id = db.Column(db.Integer, db.ForeignKey('model_incident_response.id'), primary_key=True)
    instance = db.relationship("ModelInstance", back_populates="incident_responses")
    incident_response = db.relationship("ModelIncidentResponse", back_populates="instances")


class ModelConsequenceAssociation(db.Model):
    __tablename__ = "model_consequence_association"
    instance_id = db.Column(db.Integer, db.ForeignKey('model_instance.id'), primary_key=True)
    consequence_id = db.Column(db.Integer, db.ForeignKey('model_consequence.id'), primary_key=True)
    instance = db.relationship("ModelInstance", back_populates="consequences")
    consequence = db.relationship("ModelConsequence", back_populates="instances")


class ModelImpactAssociation(db.Model):
    __tablename__ = "model_impact_association"
    instance_id = db.Column(db.Integer, db.ForeignKey('model_instance.id'), primary_key=True)
    impact_id = db.Column(db.Integer, db.ForeignKey('model_impact.id'), primary_key=True)
    instance = db.relationship("ModelInstance", back_populates="impacts")
    impact = db.relationship("ModelImpact", back_populates="instances")


class ModelObjectiveAssociation(db.Model):
    __tablename__ = "model_objective_association"
    instance_id = db.Column(db.Integer, db.ForeignKey('model_instance.id'), primary_key=True)
    objective_id = db.Column(db.Integer, db.ForeignKey('model_objective.id'), primary_key=True)
    instance = db.relationship("ModelInstance", back_populates="objectives")
    objective = db.relationship("ModelObjective", back_populates="instances")


class ModelThreatMaterialisationInstanceEntry(db.Model):
    __tablename__ = "model_threat_materialisation_instance_entry"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    # Model instance
    instance = db.Column(db.Integer)

    # Specific response in table
    incident_response = db.Column(db.Integer)

    # Specific materialisation in table
    threat_materialisation = db.Column(db.Integer)

    # Actual Foreign Keys
    __table_args__ = (db.ForeignKeyConstraint([instance, incident_response],
                                              [ModelIncidentResponseAssociation.instance_id,
                                               ModelIncidentResponseAssociation.incident_response_id]),
                      db.ForeignKeyConstraint([instance, threat_materialisation],
                                              [ModelThreatMaterialisationAssociation.instance_id,
                                               ModelThreatMaterialisationAssociation.threat_materialisation_id])
                      , {})
    # Positive if threat materialisation is occurring in this entry
    is_threat_materialising = db.Column(db.Boolean, nullable=False)
    prob_threat_materialising = db.Column(db.Integer, nullable=False)
    # Also needs reverse

    prob_likelihood = db.Column(db.Integer, nullable=False)
    prob_likelihood_other = db.Column(db.Integer, nullable=False)
    prob_posterior = db.Column(db.Integer, nullable=False)


class ModelConsequenceInstanceEntry(db.Model):
    __tablename__ = "model_consequence_instance_entry"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    # Model instance
    instance = db.Column(db.Integer)

    # Specific response in table
    incident_response = db.Column(db.Integer)

    # Specific materialisation in table
    threat_materialisation = db.Column(db.Integer)

    # Specific consequence
    consequence = db.Column(db.Integer)

    # Specific consequence (option) in table
    consequence_status = db.Column(db.Integer, db.ForeignKey('model_consequence_status.id'), nullable=False)

    __table_args__ = (db.ForeignKeyConstraint([instance, incident_response],
                                              [ModelIncidentResponseAssociation.instance_id,
                                               ModelIncidentResponseAssociation.incident_response_id]),
                      db.ForeignKeyConstraint([instance, threat_materialisation],
                                              [ModelThreatMaterialisationAssociation.instance_id,
                                               ModelThreatMaterialisationAssociation.threat_materialisation_id]),
                      db.ForeignKeyConstraint([instance, consequence],
                                              [ModelConsequenceAssociation.instance_id,
                                               ModelConsequenceAssociation.consequence_id])
                      , {})
    # Probably unneded
    # Positive if threat materialisation is occurring in this entry
    # is_threat_materialising = db.Column(db.Boolean, nullable=False)
    # prob_threat_materialising = db.Column(db.Integer, nullable=False)
    # Also needs reverse

    prob_likelihood = db.Column(db.Integer, nullable=False)
    prob_likelihood_other = db.Column(db.Integer, nullable=False)
    prob_posterior = db.Column(db.Integer, nullable=False)


class ModelImpactInstanceEntry(db.Model):
    __tablename__ = "model_impact_instance_entry"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    # Model instance
    instance = db.Column(db.Integer)

    # Specific response in table
    incident_response = db.Column(db.Integer)

    # Specific materialisation in table
    threat_materialisation = db.Column(db.Integer)

    # Specific consequence
    consequence = db.Column(db.Integer)

    # Specific consequence (option) in table
    consequence_status = db.Column(db.Integer, db.ForeignKey('model_consequence_status.id'), nullable=False)

    # Specific impact
    impact = db.Column(db.Integer)

    # Specific impact (option) in table
    impact_status = db.Column(db.Integer, db.ForeignKey("model_impact_status.id"), nullable=False)

    __table_args__ = (db.ForeignKeyConstraint([instance, incident_response],
                                              [ModelIncidentResponseAssociation.instance_id,
                                               ModelIncidentResponseAssociation.incident_response_id]),
                      db.ForeignKeyConstraint([instance, threat_materialisation],
                                              [ModelThreatMaterialisationAssociation.instance_id,
                                               ModelThreatMaterialisationAssociation.threat_materialisation_id]),
                      db.ForeignKeyConstraint([instance, consequence],
                                              [ModelConsequenceAssociation.instance_id,
                                               ModelConsequenceAssociation.consequence_id]),
                      db.ForeignKeyConstraint([instance, impact],
                                              [ModelImpactAssociation.instance_id,
                                               ModelImpactAssociation.impact_id])
                      , {})

    prob_likelihood = db.Column(db.Integer, nullable=False)
    prob_likelihood_other = db.Column(db.Integer, nullable=False)
    prob_posterior = db.Column(db.Integer, nullable=False)


# endregion

class ModelObjectiveInstanceEntry(db.Model):
    __tablename__ = "model_objective_instance_entry"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    # Model instance
    instance = db.Column(db.Integer)

    # Specific objective
    objective = db.Column(db.Integer)

    impact_status = db.Column(db.Integer, db.ForeignKey("model_impact_status.id"), nullable=False)

    __table_args__ = (db.ForeignKeyConstraint([instance, objective],
                                              [ModelObjectiveAssociation.instance_id,
                                               ModelObjectiveAssociation.objective_id])
                      , {})
