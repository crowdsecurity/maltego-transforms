from maltego_trx.maltego import MaltegoEntity, MaltegoMsg
from maltego_trx.transform import DiscoverableTransform

from extensions import registry
from settings import api_key_setting, cache_ttl_setting
from transform_sets import CrowdSecSet
from utils import enriched_ip_with_cti_resp, extract_cti_resp_from_ip_ent


@registry.register_transform(
    display_name="CrowdSec Classification",
    input_entity="maltego.IPv4Address",
    description="Creates classification details entities for an IP using CrowdSec data.",
    settings=[api_key_setting, cache_ttl_setting],
    transform_set=CrowdSecSet,
    output_entities=["crowdsec.classification"],
)
class CrowdSecClassification(DiscoverableTransform):
    @classmethod
    def create_entities(cls, request: MaltegoMsg, response):
        try:
            ip_ent = enriched_ip_with_cti_resp(request, response)
        except Exception as e:
            response.addUIMessage(str(e), UIM_FATAL)
            return
        cti_resp = extract_cti_resp_from_ip_ent(ip_ent)
        for classfication in cti_resp["classifications"]["classifications"]:
            c_ent: MaltegoEntity = response.addEntity(
                "crowdsec.classification", classfication["name"]
            )
            c_ent.addProperty("label", value=classfication["label"])
            c_ent.addDisplayInformation(f"<h3> {classfication['description']} </h3>")
            c_ent.setIconURL(
                "https://github.com/crowdsecurity/maltego-transforms/raw/master/assets/cs_red.png"
            )

        for classfication in cti_resp["classifications"]["false_positives"]:
            c_ent: MaltegoEntity = response.addEntity(
                "crowdsec.classification", classfication["name"]
            )
            c_ent.addProperty("label", value=classfication["label"])
            c_ent.addDisplayInformation(f"<h3> {classfication['description']} </h3>")
            c_ent.setIconURL(
                "https://github.com/crowdsecurity/maltego-transforms/raw/master/assets/cs_yellow.png"
            )
