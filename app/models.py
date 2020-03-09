from app import db
from datetime import datetime

class CVE(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    CVEId = db.Column(db.String(), index=True, unique=True)
    status = db.Column(db.String(), index=True)
    description = db.Column(db.String())
    references = db.Column(db.String())
    phase = db.Column(db.String())
    votes = db.Column(db.String())
    comments = db.Column(db.String())

    def __repr__(self):
        return '<CVE {}>'.format(self.CVEId)

class CWE(db.Model):
    id = db.Column(db.Integer, primary_key=True)
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
    exploitationFactors= db.Column(db.String())
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
    id = db.Column(db.Integer, primary_key=True)
    capecId = db.Column(db.String(), index=True, unique=True)
    name = db.Column(db.String())
    abstraction = db.Column(db.String())
    status = db.Column(db.String())
    description = db.Column(db.String())
    alternateTerms = db.Column(db.String())
    likelihoodOfAttack = db.Column(db.String())
    typicalSeverity = db.Column(db.String())
    relatedAttack = db.Column(db.String())
    patterns = db.Column(db.String())
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