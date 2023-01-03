import ipaddress
import pathlib

from maltego_trx.maltego import MaltegoMsg
from maltego_trx.transform import DiscoverableTransform

from extensions import registry
from transform_sets import CrowdSecSet
from settings import api_key_setting, cache_ttl_setting
from utils import enriched_ip_with_cti_resp, extract_cti_resp_from_ip_ent

GREEN_ICON_PATH = (
    pathlib.Path(__file__).parent.resolve().parent.joinpath("assets/cs_green.png")
)


@registry.register_transform(
    display_name="CrowdSec Behaviours Transform",
    input_entity="maltego.IPv4Address",
    description="Adds behaviours by leveraging CrowdSec CTI data",
    settings=[api_key_setting, cache_ttl_setting],
    transform_set=CrowdSecSet,
)
class CrowdSecBehaviours(DiscoverableTransform):
    @classmethod
    def create_entities(cls, request: MaltegoMsg, response):
        try:
            ip_ent = enriched_ip_with_cti_resp(request, response)
        except Exception as e:
            response.addUIMessage(str(e))
        cti_resp = extract_cti_resp_from_ip_ent(ip_ent)
        for behaviour in cti_resp["behaviors"]:
            behaviour_ent = response.addEntity("crowdsec.behaviour", behaviour["name"])
            behaviour_ent.addProperty("label", value=behaviour["label"])
            behaviour_ent.addDisplayInformation(
                f"<h4> {behaviour['description']} </h4>", "Description"
            )
            behaviour_ent.setIconURL(f"file://{GREEN_ICON_PATH}")
