from maltego_trx.maltego import UIM_FATAL, MaltegoMsg
from maltego_trx.transform import DiscoverableTransform

from extensions import registry
from settings import api_key_setting, cache_ttl_setting
from transform_sets import CrowdSecSet
from utils import enriched_ip_with_cti_resp, extract_cti_resp_from_ip_ent


@registry.register_transform(
    display_name="CrowdSec Behaviour",
    input_entity="maltego.IPv4Address",
    description="Creates a behaviour entity for an IP by leveraging CrowdSec CTI data",
    settings=[api_key_setting, cache_ttl_setting],
    transform_set=CrowdSecSet,
    output_entities=["crowdsec.behaviour"],
)
class CrowdSecBehaviours(DiscoverableTransform):
    @classmethod
    def create_entities(cls, request: MaltegoMsg, response):
        try:
            ip_ent = enriched_ip_with_cti_resp(request, response)
        except Exception as e:
            response.addUIMessage(str(e), UIM_FATAL)
            return

        cti_resp = extract_cti_resp_from_ip_ent(ip_ent)
        for behaviour in cti_resp["behaviors"]:
            behaviour_ent = response.addEntity("crowdsec.behaviour", behaviour["name"])
            behaviour_ent.addProperty("label", value=behaviour["label"])
            behaviour_ent.addDisplayInformation(
                f"<h4> {behaviour['description']} </h4>", "Description"
            )
            behaviour_ent.setIconURL(
                "https://github.com/crowdsecurity/maltego-transforms/raw/master/assets/cs_green.png"
            )
