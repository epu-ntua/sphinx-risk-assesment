from app import db


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


class VulnerabilitiesWeaknessLink(db.Model):
    __tablename__ = 'vulnerabilities_weakness_link'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    cve_id = db.Column(db.Integer, db.ForeignKey('common_vulnerabilities_and_exposures.id'), nullable=False)
    cwe_id = db.Column(db.Integer, db.ForeignKey('common_weakness_enumeration.id'), nullable=False)
    date = db.Column(db.DateTime)

    def __repr__(self):
        return '<cVecWe {}>'.format(self.Id)


class Asset(db.Model):
    __tablename__ = 'assetTable'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    assetID = db.Column(db.String())
    assetIp = db.Column(db.String())
    date = db.Column(db.DateTime)
    assetName = db.Column(db.String())
    assetModel = db.Column(db.String())
    assetSerialNumber = db.Column(db.String())
    assetRecoveryKey = db.Column(db.String())
    assetVendor = db.Column(db.String())
    assetDomain = db.Column(db.String())
    assetWarranty = db.Column(db.String())
    assetWarrantyExpDate = db.Column(db.DateTime())
    assetStatus = db.Column(db.Integer, db.ForeignKey('AssetHardwareStatus.AssetHardwareStatusID'))
    assetType = db.Column(db.Integer, db.ForeignKey('AssetHardwareType.AssetHardwareTypeID'))
    assetPurchasePrice = db.Column(db.Float())
    assetPurchaseDate = db.Column(db.DateTime)
    assetCreatedBy = db.Column(db.String())
    assetCreatedDate = db.Column(db.DateTime)
    assetAssignedTo = db.Column(db.String())
    assetManagedBy = db.Column(db.String())
    assetOwner = db.Column(db.String())
    assetUsageType = db.Column(db.String()) #--add hoc or permanent
    assetLocation = db.Column(db.String())
    assetClassification = db.Column(db.Integer, db.ForeignKey('AssetClassification.AssetClassificationID'))
    assetInformationProcessed = db.Column(db.String()) #--Personal or Business
    def __repr__(self):
        return '<Asset {}>'.format(self.Id)

class AssetHardwareStatus(db.Model):
    __tablename__ = 'asset_hardware_status'
    AssetHardwareStatusID = db.Column(db.Integer, primary_key=True, autoincrement=True)
    AssetHardwareStatusDescr = db.Column(db.String())
    AssetHardwareStatusInsertedDate = db.Column(db.DateTime)
    def __repr__(self):
        return '<AssetHardwareStatus {}>'.format(self.AssetHardwareStatusID)
    
class AssetHardwareType(db.Model):
    __tablename__ = 'asset_hardware_type'
    AssetHardwareTypeID = db.Column(db.Integer, primary_key=True, autoincrement=True)
    AssetHardwareTypeDescr = db.Column(db.String())
    AssetHardwareTypeInsertedDate = db.Column(db.DateTime)
    def __repr__(self):
        return '<AssetHardwareType {}>'.format(self.AssetHardwareTypeID)

class AssetClassification(db.Model):
    __tablename__ = 'asset_classification'
    AssetClassificationID = db.Column(db.Integer, primary_key=True, autoincrement=True)
    AssetClassificationDescr = db.Column(db.String())
    AssetClassificationInsertedDate = db.Column(db.DateTime)
    def __repr__(self):
        return '<AssetHardwareType {}>'.format(self.AssetClassificationID)

class RiskAssessment(db.Model):
    __tablename__ = 'risk_assessment'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    asset_id = db.Column(db.Integer, db.ForeignKey('asset.id'), nullable=False)
    date = db.Column(db.DateTime)

    def __repr__(self):
        return '<Risk_Assessment {}>'.format(self.Id)

class RiskVulnerabilityThreat(db.Model):
    __tablename__ = 'risk_vulnerability_threat'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    risk_id = db.Column(db.Integer, db.ForeignKey('risk_assessment.id'), nullable=False)
    CVE_id = db.Column(db.Integer, db.ForeignKey('common_vulnerabilities_and_exposures.id'), nullable=False)
    CAPEC_id = db.Column(db.Integer, db.ForeignKey('common_attack_pattern_enumeration_classification.id'), nullable=False)
    date = db.Column(db.DateTime)

    def __repr__(self):
        return '<Risk_Vulnerability_Threat {}>'.format(self.Id)


# region Static GiraModels

# High level Gira assets describing business logic or high level assets like doctors or patients(not network assets)


# Gira Asset status table has all the different status of a single Gira asset since they are dynamic
class GiraIncidentResponse(db.Model):
    __tablename__ = 'gira_incident_response'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String, nullable=False)
    description = db.Column(db.String)

class GiraAsset(db.Model):
    __tablename__ = 'gira_asset'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String, nullable=False)
    number_of_options = db.Column(db.Integer)
    status = db.relationship('GiraAssetStatus', backref='asset', lazy=True)


class GiraAssetStatus(db.Model):
    __tablename__ = 'gira_asset_status'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String, nullable=False)
    asset_fk = db.Column(db.Integer, db.ForeignKey('gira_asset.id'), nullable=False)




# region Gira Consequences
scope_impact_table = db.Table('scope_impact_helper',
                               db.Column('scope_id', db.Integer, db.ForeignKey('gira_scope.id'), primary_key=True),
                               db.Column('impact_id', db.Integer, db.ForeignKey('gira_impact.id'), primary_key=True)
                               )

class GiraImpact(db.Model):
    __tablename__ = 'gira_impact'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String, nullable=False)
    note = db.Column(db.String)
    scopes = db.relationship('GiraScope', secondary=scope_impact_table, lazy=True,
                             backref = db.backref('impacts'))


class GiraScope(db.Model):
    __tablename__ = 'gira_scope'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String, nullable=False)




# endregion

#
class GiraObjective(db.Model):
    __tablename__ = 'gira_objective'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String, nullable=False)
    status = db.relationship('GiraObjectivesOptions', backref='objective', lazy=True)


class GiraObjectivesOptions(db.Model):
    __tablename__ = 'gira_objectives_options'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String, nullable=False)
    objective_fk = db.Column(db.Integer, db.ForeignKey('gira_objective.id'), nullable=False)


# endregion
