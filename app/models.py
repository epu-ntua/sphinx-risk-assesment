from app import db


class VReport(db.Model):
    __tablename__ = 'VReportTable'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    reportId = db.Column(db.String(), index=True, unique=True)
    creation_time = db.Column(db.String())
    name = db.Column(db.String())
    comments = db.Column(db.String())
    # CVEs = db.relationship("VReportCVELink", back_populates="vreport_s")

    def __repr__(self):
        return '<VaasReport {}>'.format(self.reportId)


class CVE(db.Model):
    __tablename__ = 'CVETable'
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


class VReportCVELink(db.Model):
    __tablename__ = 'vreport_cve_link'
    vreport_id = db.Column(db.Integer, db.ForeignKey('VReportTable.id'), primary_key=True)
    cve_id = db.Column(db.Integer, db.ForeignKey('CVETable.id'), primary_key=True)
    VReport_assetID = db.Column(db.String())
    VReport_assetIp = db.Column(db.String())
    VReport_port = db.Column(db.String())
    comments = db.Column(db.String(50))
#     cve_s = db.relationship("CVE", back_populates="VReports")
#     vreport_s = db.relationship("VReport", back_populates="CVEs")

    def __repr__(self):
        return '<VReportCVELink {}>'.format(self.vreport_id)


class CWE(db.Model):
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


class CAPEC(db.Model):
    __tablename__ = 'capecTable'
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


class cVecWe(db.Model):
    __tablename__ = 'cVecWeTable'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    cve_id = db.Column(db.Integer, db.ForeignKey('CVETable.id'), nullable=False)
    cwe_id = db.Column(db.Integer, db.ForeignKey('CWE.id'), nullable=False)
    date = db.Column(db.DateTime)

    def __repr__(self):
        return '<cVecWe {}>'.format(self.Id)


class Asset(db.Model):
    __tablename__ = 'assetTable'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    assetID = db.Column(db.String())
    assetIp = db.Column(db.String())
    date = db.Column(db.DateTime)

    def __repr__(self):
        return '<Asset {}>'.format(self.Id)


class Risk_Assessment(db.Model):
    __tablename__ = 'riskassessmentTable'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    asset_id = db.Column(db.Integer, db.ForeignKey('assetTable.id'), nullable=False)
    date = db.Column(db.DateTime)

    def __repr__(self):
        return '<Risk_Assessment {}>'.format(self.Id)


    class Risk_Vuln_Threat(db.Model):
        __tablename__ = 'riskvulnerabilitythreatTable'
        id = db.Column(db.Integer, primary_key=True, autoincrement=True)
        risk_id = db.Column(db.Integer, db.ForeignKey('riskassessmentTable.id'), nullable=False)
        CVE_id = db.Column(db.Integer, db.ForeignKey('CVETable.id'), nullable=False)
        CAPEC_id = db.Column(db.Integer, db.ForeignKey('capecTable.id'), nullable=False)
        date = db.Column(db.DateTime)

        def __repr__(self):
            return '<Risk_Vulnerability_Threat {}>'.format(self.Id)