from maltego_trx.maltego import UIM_FATAL, MaltegoMsg
from maltego_trx.transform import DiscoverableTransform

from extensions import registry
from settings import api_key_setting, cache_ttl_setting
from transform_sets import CrowdSecSet
from utils import enriched_ip_with_cti_resp


@registry.register_transform(
    display_name="CrowdSec IP CTI",
    input_entity="maltego.IPv4Address",
    description="Attaches CrowdSec CTI API response as a property to IP entity.",
    settings=[api_key_setting, cache_ttl_setting],
    transform_set=CrowdSecSet,
)
class CrowdSecAddAPIResp(DiscoverableTransform):
    @classmethod
    def create_entities(cls, request: MaltegoMsg, response):
        try:
            enriched_ip_with_cti_resp(request, response)
        except Exception as e:
            response.addUIMessage(str(e), UIM_FATAL)
