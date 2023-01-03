from maltego_trx.maltego import MaltegoMsg
from maltego_trx.transform import DiscoverableTransform

from extensions import registry
from transform_sets import CrowdSecSet
from settings import api_key_setting, cache_ttl_setting
from utils import enriched_ip_with_cti_resp, extract_cti_resp_from_ip_ent


@registry.register_transform(
    display_name="CrowdSec Activity Details",
    input_entity="maltego.IPv4Address",
    description="Adds activity details IP using crowdsec data. ",
    settings=[api_key_setting, cache_ttl_setting],
    transform_set=CrowdSecSet,
)
class CrowdSecActivity(DiscoverableTransform):
    @classmethod
    def create_entities(cls, request: MaltegoMsg, response):
        try:
            ip_ent = enriched_ip_with_cti_resp(request, response)
        except Exception as e:
            response.addUIMessage(str(e))
            return

        cti_resp = extract_cti_resp_from_ip_ent(ip_ent)
        ip_ent.addProperty(
            "last_seen_by_crowdsec", value=cti_resp["history"]["last_seen"]
        )
        ip_ent.addProperty(
            "first_seen_by_crowdsec", value=cti_resp["history"]["first_seen"]
        )
