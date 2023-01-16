import pycountry
from maltego_trx.maltego import MaltegoEntity, MaltegoMsg
from maltego_trx.transform import DiscoverableTransform

from extensions import registry
from settings import api_key_setting, cache_ttl_setting
from transform_sets import CrowdSecSet
from utils import enriched_ip_with_cti_resp, extract_cti_resp_from_ip_ent


@registry.register_transform(
    display_name="CrowdSec Target Country",
    input_entity="maltego.IPv4Address",
    description="Links IP entity with countries most attacked by it, using CrowdSec data.",
    settings=[api_key_setting, cache_ttl_setting],
    transform_set=CrowdSecSet,
    output_entities=["maltego.Country"],
)
class CrowdSecTargetCountries(DiscoverableTransform):
    @classmethod
    def create_entities(cls, request: MaltegoMsg, response):
        try:
            ip_ent = enriched_ip_with_cti_resp(request, response)
        except Exception as e:
            response.addUIMessage(str(e))
            return
        cti_resp = extract_cti_resp_from_ip_ent(ip_ent)
        for target_country, weight in cti_resp["target_countries"].items():
            country_name = pycountry.countries.get(alpha_2=target_country).name
            country: MaltegoEntity = response.addEntity("maltego.Country", country_name)
            country.addCustomLinkProperty("weightage", value=str(weight))
