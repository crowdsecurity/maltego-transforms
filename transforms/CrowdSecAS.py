from maltego_trx.entities import ASNumber
from maltego_trx.maltego import UIM_FATAL, MaltegoMsg
from maltego_trx.transform import DiscoverableTransform

from extensions import registry
from settings import api_key_setting, cache_ttl_setting
from transform_sets import CrowdSecSet
from utils import enriched_ip_with_cti_resp, extract_cti_resp_from_ip_ent


@registry.register_transform(
    display_name="CrowdSec AS Transform",
    input_entity="maltego.IPv4Address",
    description="Adds AS entity for an IP by leveraging CrowdSec CTI data",
    settings=[api_key_setting, cache_ttl_setting],
    transform_set=CrowdSecSet,
    output_entities=[ASNumber],
)
class CrowdSecAS(DiscoverableTransform):
    @classmethod
    def create_entities(cls, request: MaltegoMsg, response):
        try:
            ip_ent = enriched_ip_with_cti_resp(request, response)
        except Exception as e:
            response.addUIMessage(str(e), UIM_FATAL)
            return

        cti_resp = extract_cti_resp_from_ip_ent(ip_ent)
        as_ent = response.addEntity(ASNumber, "")
        as_ent.addProperty("as.number", value=str(cti_resp["as_num"]))
        as_ent.addProperty("as.name", value=cti_resp["as_name"])
