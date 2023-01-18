from maltego_trx.maltego import UIM_FATAL, MaltegoMsg
from maltego_trx.transform import DiscoverableTransform

from extensions import registry
from settings import api_key_setting, cache_ttl_setting
from transform_sets import CrowdSecSet
from utils import enriched_ip_with_cti_resp, extract_cti_resp_from_ip_ent


@registry.register_transform(
    display_name="CrowdSec Scenario",
    input_entity="maltego.IPv4Address",
    description="Creates entites for scenarios triggered by IP using CrowdSec CTI data.",
    settings=[api_key_setting, cache_ttl_setting],
    transform_set=CrowdSecSet,
    output_entities=["crowdsec.scenario"],
)
class CrowdSecScenarios(DiscoverableTransform):
    @classmethod
    def create_entities(cls, request: MaltegoMsg, response):
        try:
            ip_ent = enriched_ip_with_cti_resp(request, response)
        except Exception as e:
            response.addUIMessage(str(e), UIM_FATAL)
            return

        cti_resp = extract_cti_resp_from_ip_ent(ip_ent)
        for attack in cti_resp["attack_details"]:
            scenario = response.addEntity("crowdsec.scenario", attack["name"])
            scenario.setIconURL(
                "https://github.com/crowdsecurity/maltego-transforms/raw/master/assets/cs_color.png"
            )
            scenario.addProperty("label", value=attack["label"])
            scenario.addDisplayInformation(
                "<h3>" + attack["description"] + "</h3>", "Description"
            )
