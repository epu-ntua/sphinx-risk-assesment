from stix2 import CustomObject, properties


@CustomObject('x-rcra-objectives', [
    ('x_rcra_scoring', properties.StringProperty(required=True))
])
class RCRAObjective(object):
    def __init__(self, x_rcra_scoring, **kwargs):
        return


@CustomObject('x-rcra-current-threats',[
    ('x_rcra_threats', properties.StringProperty(required=True))
])
class RCRACurrentThreatsVis(object):
    def __init__(self, x_rcra_threats, **kwargs):
        return


@CustomObject('x-rcra-current-assets', [
    ('x_rcra_assets', properties.StringProperty(required=True))
])
class RCRACurrentAssets(object):
    def __init__(self, x_rcra_assets, **kwargs):
        return
