from app.models import *
import json
import os
import stix2
import stix2validator
import app.utils.stix2_custom as stix2_custom

def sendDSSScore():
    asset = stix2.IPv4Address(
        # type="ipv4-addr",
        value="10.0.255.106"
    )
    attack = stix2.AttackPattern(
        # type="attack-pattern",
        name="Spear Phishing as Practiced by Adversary X",
        description="A particular form of spear phishing where the attacker claims that the target had won a contest, including personal details, to get them to click on a link.",
    )

    relationship = stix2.Relationship(
        # type="relationship",
        relationship_type="targets",
        source_ref=attack.id,
        target_ref=asset.id
    )

    scoring = {
        "score": "1",
        "impact": "high",
        "probability": "low"
    }
    rcra = stix2_custom.RCRAObjective(
        x_rcra_scoring=json.dumps(scoring)

    )

    bundle = stix2.Bundle(asset, attack, relationship, rcra)
    print(bundle, flush=True)
    stix2validator.validate_instance(bundle)
    SendKafkaReport(str(bundle), "rcra-report-topic")

    return 0


def sendDSSScoreTest():
    asset = stix2.IPv4Address(
        # type="ipv4-addr",
        value="10.0.255.106"
    )
    attack = stix2.AttackPattern(
        # type="attack-pattern",
        name="Spear Phishing as Practiced by Adversary X",
        description="A particular form of spear phishing where the attacker claims that the target had won a contest, including personal details, to get them to click on a link.",
    )

    relationship = stix2.Relationship(
        # type="relationship",
        relationship_type="targets",
        source_ref=attack.id,
        target_ref=asset.id
    )

    scoring = {
        "score": "20",
        "impact": "high",
        "probability": "low"
    }
    rcra = stix2_custom.RCRAObjective(
        x_rcra_scoring=json.dumps(scoring)

    )

    bundle = stix2.Bundle(asset, attack, relationship, rcra)
    print(bundle, flush=True)
    stix2validator.validate_instance(bundle)
    SendKafkaReport(str(bundle), "rcra-report-topic-test")

    return 0


def send_dss_alert():
    asset = stix2.IPv4Address(
        # type="ipv4-addr",
        value="10.0.255.106"
    )
    attack = stix2.AttackPattern(
        # type="attack-pattern",
        name="Spear Phishing as Practiced by Adversary X",
        description="A particular form of spear phishing where the attacker claims that the target had won a contest, including personal details, to get them to click on a link.",
    )

    relationship = stix2.Relationship(
        # type="relationship",
        relationship_type="targets",
        source_ref=attack.id,
        target_ref=asset.id
    )

    # scoring = {
    #     "score": "1",
    #     "impact": "high",
    #     "probability": "low"
    # }
    # rcra = stix2_custom.RCRAObjective(
    #     x_rcra_scoring=json.dumps(scoring)
    #
    # )

    bundle = stix2.Bundle(asset, attack, relationship)
    print(bundle, flush=True)
    stix2validator.validate_instance(bundle)
    # SendKafkaReport(str(bundle))
    return str(bundle)


def make_visualisation():
    """ Constructs example visualisation for Current Threats by impact level"""
    score = {
        "low_impact": "1",
        "medium_impact": "2",
        "high_impact": "2",
        "critical_impact": "1",
    }

    vis_1 = stix2_custom.RCRACurrentThreatsVis(
        x_rcra_threats=score
    )
    bundle = stix2.Bundle(vis_1)
    stix2validator.validate_instance(bundle)

    # print(bundle, flush=True)
    return str(bundle)


def make_visualisation_current_assets(assets):
    """ Constructs Visualisation for ID new-unverified asset alert """
    vis_1 = stix2_custom.RCRACurrentAssets(
        x_rcra_assets=assets
    )
    bundle = stix2.Bundle(vis_1)
    stix2validator.validate_instance(bundle)

    return str(bundle)


def send_asset_id_alert():
    """' Function Recieves New Detected Assets and Send new visualisation data to ID (all or uknown-unverified only?)"""
    return 1