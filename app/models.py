from app import db


# from app.mixins import ModelMixin

class VulnerabilityReport(db.Model):
    __tablename__ = 'vulnerability_report'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    reportId = db.Column(db.String(), index=True, unique=True)
    scan_start_time = db.Column(db.String())
    scan_end_time = db.Column(db.String())
    target_name = db.Column(db.String())
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


class RepoRiskThreatAssetMaterialisation(db.Model):
    """Each entry at this table servers as an entry to the risk assessment matrix risk materialisation node"""
    __tablename__ = "repo_risk_threat_asset_materialisation"
    repo_asset_id = db.Column(db.Integer, db.ForeignKey('repo_asset.id'), primary_key=True)
    repo_threat_id = db.Column(db.Integer, db.ForeignKey('repo_threat.id'), primary_key=True)
    repo_response_id = db.Column(db.Integer, db.ForeignKey('repo_response.id'), primary_key=True)
    repo_materialisation_id = db.Column(db.Integer, db.ForeignKey('repo_materialisation.id'), primary_key=True)
    threat_occurrence = db.Column(db.Boolean(), primary_key=True)
    prob = db.Column(db.Integer)


class RepoAssetThreatConsequenceServiceImpactRelationship(db.Model):
    """Each entry at this table servers as an entry to the risk assessment matrix risk impact node, it needs the
    corresponding entries for consequences and services to figure out which is which in the following table.
    RepoAssetThreatConsequenceServiceImpactRelationshipConsequenceManyToMany
    RepoAssetThreatConsequenceServiceImpactRelationshipServiceManyToMany
    """
    __tablename__ = 'repo_asset_threat_consequence_service_impact_relationship'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    repo_asset_id = db.Column(db.Integer, db.ForeignKey('repo_asset.id'))
    repo_threat_id = db.Column(db.Integer, db.ForeignKey('repo_threat.id'))
    repo_impact_id = db.Column(db.Integer, db.ForeignKey('repo_impact.id'))
    high_prob = db.Column(db.Integer)
    med_prob = db.Column(db.Integer)
    low_prob = db.Column(db.Integer)
    consequences_state = db.Column(db.String)
    services_state = db.Column(db.String)
    consequences = db.relationship("RepoAssetThreatConsequenceServiceImpactRelationshipConsequenceManyToMany",
                                   back_populates="repo_this_entry")
    services = db.relationship("RepoAssetThreatConsequenceServiceImpactRelationshipServiceManyToMany",
                               back_populates="repo_this_entry")


# Obsolete should be removed
class RepoAssetThreatConsequenceServiceImpactRelationshipConsequenceManyToMany(db.Model):
    __tablename__ = 'repo_asset_threat_consequence_service_impact_relationship_consequence_many_to_many'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    repo_this_entry_id = db.Column(db.Integer,
                                   db.ForeignKey('repo_asset_threat_consequence_service_impact_relationship.id'))
    repo_this_entry = db.relationship("RepoAssetThreatConsequenceServiceImpactRelationship",
                                      back_populates="consequences")
    repo_consequence_id = db.Column(db.Integer, db.ForeignKey('repo_consequence.id'))
    repo_consequence = db.relationship("RepoConsequence", back_populates="impact_risk_relationship")
    repo_consequence_state = db.Column(db.Boolean())

# Obsolete should be removed
class RepoAssetThreatConsequenceServiceImpactRelationshipServiceManyToMany(db.Model):
    __tablename__ = 'repo_asset_threat_consequence_service_impact_relationship_service_many_to_many'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    repo_this_entry_id = db.Column(db.Integer,
                                   db.ForeignKey('repo_asset_threat_consequence_service_impact_relationship.id'))
    repo_this_entry = db.relationship("RepoAssetThreatConsequenceServiceImpactRelationship",
                                      back_populates="services")
    repo_service_id = db.Column(db.Integer, db.ForeignKey('repo_service.id'))
    repo_service = db.relationship("RepoService", back_populates='impact_risk_relationship')
    repo_service_state = db.Column(db.Boolean())


class RepoObjectiveImpactRelationship(db.Model):
    """Each entry at this table servers as an entry to the risk assessment matrix risk objective node, it needs the
    corresponding entries for impacts to figure out which is which in the following table.
    RepoObjectiveImpactRelationshipImpactManyToMany
    """
    __tablename__ = 'repo_objective_impact_relationship'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    # repo_asset_id = db.Column(db.Integer, db.ForeignKey('repo_asset.id'))
    # repo_threat_id = db.Column(db.Integer, db.ForeignKey('repo_threat.id'))
    # repo_impact_id = db.Column(db.Integer, db.ForeignKey('repo_impact.id'))
    repo_objective_id = db.Column(db.Integer, db.ForeignKey('repo_objective.id'))
    high_prob = db.Column(db.Integer)
    med_prob = db.Column(db.Integer)
    low_prob = db.Column(db.Integer)
    impacts_state = db.Column(db.String)
    impacts = db.relationship("RepoObjectiveImpactRelationshipImpactManyToMany",
                              back_populates="repo_this_entry")


class RepoObjectiveImpactRelationshipImpactManyToMany(db.Model):
    __tablename__ = 'repo_objective_impact_relationship_impact_many_to_many'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    repo_this_entry_id = db.Column(db.Integer,
                                   db.ForeignKey('repo_objective_impact_relationship.id'))
    repo_this_entry = db.relationship("RepoObjectiveImpactRelationship",
                                      back_populates="impacts")
    repo_impact_id = db.Column(db.Integer, db.ForeignKey('repo_impact.id'))
    repo_impact = db.relationship("RepoImpact", back_populates='objective_risk_relationship')
    repo_impact_state = db.Column(db.Integer)


class RepoUtilityObjectiveRelationship(db.Model):
    __tablename__ = "repo_utility_objective_relationship"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    repo_utility_id = db.Column(db.Integer, db.ForeignKey('repo_utility.id'))
    objectives = db.relationship("RepoUtilityObjectiveRelationshipManyToMany", back_populates="repo_this_entry")
    utility_value = db.Column(db.Integer)

class RepoUtilityObjectiveRelationshipManyToMany(db.Model):
    __tablename__ = "repo_utility_objective_relationship_many_to_many"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    repo_this_entry_id = db.Column(db.Integer,
                                   db.ForeignKey('repo_utility_objective_relationship.id'))
    repo_this_entry = db.relationship("RepoUtilityObjectiveRelationship",
                                      back_populates="objectives")
    repo_objective_id = db.Column(db.Integer, db.ForeignKey('repo_objective.id'))
    repo_objective = db.relationship("RepoObjective", back_populates='utility_risk_relationship')
    repo_objective_state = db.Column(db.Integer)

class RepoRiskThreatAssetConsequence(db.Model):
    """Each entry at this table servers as an entry to the risk assessment matrix risk consequence node"""
    __tablename__ = "repo_risk_threat_asset_consequence"
    repo_asset_id = db.Column(db.Integer, db.ForeignKey('repo_asset.id'), primary_key=True)
    repo_threat_id = db.Column(db.Integer, db.ForeignKey('repo_threat.id'), primary_key=True)
    repo_response_id = db.Column(db.Integer, db.ForeignKey('repo_response.id'), primary_key=True)
    repo_consequence = db.relationship("RepoConsequence", back_populates="consequence_risk_relationship")
    repo_consequence_id = db.Column(db.Integer, db.ForeignKey('repo_consequence.id'), primary_key=True)
    threat_occurrence = db.Column(db.Boolean(), primary_key=True)
    prob = db.Column(db.Integer)


# RepoThreatExposureRelation could change name
class RepoAssetRepoThreatRelationship(db.Model):
    __tablename__ = 'repo_asset_repo_threat_relationship'
    repo_asset_id = db.Column(db.Integer, db.ForeignKey('repo_asset.id'), primary_key=True)
    repo_threat_id = db.Column(db.Integer, db.ForeignKey('repo_threat.id'), primary_key=True)
    asset = db.relationship('RepoAsset', back_populates='threats')
    threat = db.relationship('RepoThreat', back_populates='assets')
    risk_skill_level = db.Column(db.Integer, nullable=True)
    risk_motive = db.Column(db.Integer, nullable=True)
    risk_source = db.Column(db.Integer, nullable=True)
    risk_actor = db.Column(db.Integer, nullable=True)
    risk_opportunity = db.Column(db.Integer, nullable=True)


class RepoRiskAssessment(db.Model):
    __tablename__ = 'repo_risk_assessment'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    repo_threat_id = db.Column(db.Integer, db.ForeignKey('repo_threat.id'))
    repo_asset_id = db.Column(db.Integer, db.ForeignKey('repo_asset.id'))
    asset = db.relationship("RepoAsset", back_populates="risk_assessment")
    threat = db.relationship("RepoThreat", back_populates="risk_assessment")
    reports = db.relationship("RepoRiskAssessmentReports", back_populates="risk_assessment")

    # assets = db.relationship("RepoAsset", secondary=repo_risk_assessment_repo_asset_association_table,
    #                           back_populates="risk_assessment")

    # assets = db.relationship("RepoRiskAssessmentManyToMany", back_populates="repo_this_assessment")


#
# class RepoRiskAssessmentManyToMany(db.Model):
#     __tablename__ = 'repo_risk_assessment'
#     id = db.Column(db.Integer, primary_key=True, autoincrement=True)
#     repo_this_assessment = db.relationship("RepoRiskAssessment", back_populates="assets")
#     repo_threat_id = db.Column(db.Integer, db.ForeignKey('repo_threat.id'))
#     repo_asset_id = db.Column(db.Integer, db.ForeignKey('repo_asset.id'))


class RepoRiskAssessmentReports(db.Model):
    __tablename__ = 'repo_risk_assessment_reports'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    risk_assessment_id = db.Column(db.Integer, db.ForeignKey('repo_risk_assessment.id'))
    risk_assessment = db.relationship("RepoRiskAssessment", back_populates="reports")


class RepoThreat(db.Model):
    __tablename__ = 'repo_threat'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String)
    CAPEC_id = db.Column(db.Integer, db.ForeignKey('common_attack_pattern_enumeration_classification.id'))
    assets = db.relationship("RepoAssetRepoThreatRelationship", back_populates="threat")
    prob = db.Column(db.Integer)
    user_prob = db.Column(db.Integer)
    risk_assessment = db.relationship("RepoRiskAssessment", back_populates="threat")


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


repo_consequence_repo_impact_association_table = db.Table('repo_consequence_repo_impact_association_table',
                                                          db.Model.metadata,
                                                          db.Column('repo_consequence_id', db.Integer,
                                                                    db.ForeignKey('repo_consequence.id')),
                                                          db.Column('repo_impact_id', db.Integer,
                                                                    db.ForeignKey('repo_impact.id'))
                                                          )


class RepoConsequence(db.Model):
    """ Consequences are intrinsically tied to the threat materialisation and assets and therefore are unique for each one"""
    __tablename__ = 'repo_consequence'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String)
    threat_id = db.Column(db.Integer, db.ForeignKey('repo_threat.id'))
    materialisation_id = db.Column(db.Integer, db.ForeignKey('repo_materialisation.id'))
    impacts = db.relationship("RepoImpact", secondary=repo_consequence_repo_impact_association_table,
                              back_populates="consequences")
    consequence_risk_relationship = db.relationship("RepoRiskThreatAssetConsequence", back_populates="repo_consequence")
    impact_risk_relationship = db.relationship(
        "RepoAssetThreatConsequenceServiceImpactRelationshipConsequenceManyToMany", back_populates="repo_consequence")


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

repo_service_repo_impact_association_table = db.Table('repo_service_repo_impact_association_table', db.Model.metadata,
                                                      db.Column('repo_service_id', db.Integer,
                                                                db.ForeignKey('repo_service.id')),
                                                      db.Column('repo_impact_id', db.Integer,
                                                                db.ForeignKey('repo_impact.id'))
                                                      )

repo_objective_repo_impact_association_table = db.Table('repo_objective_repo_impact_association_table',
                                                        db.Model.metadata,
                                                        db.Column('repo_objective_id', db.Integer,
                                                                  db.ForeignKey('repo_objective.id')),
                                                        db.Column('repo_impact_id', db.Integer,
                                                                  db.ForeignKey('repo_impact.id'))
                                                        )

repo_utility_repo_objective_association_table = db.Table('repo_utility_repo_objective_association_table',
                                                         db.Model.metadata,
                                                         db.Column('repo_utility_id', db.Integer,
                                                                   db.ForeignKey('repo_utility.id'))
                                                         , db.Column('repo_objective_id', db.Integer,
                                                                     db.ForeignKey('repo_objective.id'))
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
    integrity = db.Column(db.Integer)
    services = db.relationship("RepoService", secondary=repo_asset_repo_service_association_table,
                               back_populates="assets")
    # risk_assessment = db.relationship("RepoRiskAssessment", secondary=repo_risk_assessment_repo_asset_association_table,
    #                            back_populates="assets")
    threats = db.relationship("RepoAssetRepoThreatRelationship",
                              back_populates="asset")
    risk_assessment = db.relationship("RepoRiskAssessment", back_populates="asset")


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
    impacts = db.relationship("RepoImpact", secondary=repo_service_repo_impact_association_table,
                              back_populates="services")
    impact_risk_relationship = db.relationship("RepoAssetThreatConsequenceServiceImpactRelationshipServiceManyToMany",
                                               back_populates='repo_service')


class RepoImpact(db.Model):
    __tablename__ = 'repo_impact'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    description = db.Column(db.String, nullable=True)
    name = db.Column(db.String, nullable=False)
    services = db.relationship("RepoService", secondary=repo_service_repo_impact_association_table,
                               back_populates="impacts")
    consequences = db.relationship("RepoConsequence", secondary=repo_consequence_repo_impact_association_table,
                                   back_populates="impacts")
    objectives = db.relationship("RepoObjective", secondary=repo_objective_repo_impact_association_table,
                                 back_populates="impacts")
    objective_risk_relationship = db.relationship("RepoObjectiveImpactRelationshipImpactManyToMany",
                                                  back_populates="repo_impact")


class RepoObjective(db.Model):
    __tablename__ = 'repo_objective'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    description = db.Column(db.String, nullable=True)
    name = db.Column(db.String, nullable=False)
    impacts = db.relationship("RepoImpact", secondary=repo_objective_repo_impact_association_table,
                              back_populates="objectives")
    utilities = db.relationship("RepoUtility", secondary=repo_utility_repo_objective_association_table,
                                back_populates="objectives")
    utility_risk_relationship = db.relationship("RepoUtilityObjectiveRelationshipManyToMany",
                                                  back_populates="repo_objective")
    # status = db.relationship('modelObjectivesOptions', backref='objective', lazy=True)
    # instances = db.relationship("ModelObjectiveAssociation", back_populates="objective")


class RepoObjectivesOptions(db.Model):
    __tablename__ = 'repo_objectives_options'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String, nullable=False)
    objective_fk = db.Column(db.Integer, db.ForeignKey('repo_objective.id'), nullable=False)
    alert_level = db.Column(db.Integer, nullable=True,
                            default=0)  # 0-No Alert #1-Oddness3> #2-RareThanRare #3-Rare #4-Possible #5-Certain
    prob_likelihood = db.Column(db.Integer, nullable=True)


class RepoUtility(db.Model):
    __tablename__ = 'repo_utility'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String, nullable=False)
    objectives = db.relationship("RepoObjective", secondary=repo_utility_repo_objective_association_table,
                                 back_populates="utilities")
