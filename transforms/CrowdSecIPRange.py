import ipaddress

from maltego_trx.entities import Netblock
from maltego_trx.maltego import MaltegoMsg
from maltego_trx.transform import DiscoverableTransform

from extensions import registry
from settings import api_key_setting, cache_ttl_setting
from transform_sets import CrowdSecSet
from utils import enriched_ip_with_cti_resp, extract_cti_resp_from_ip_ent


def cidr_to_range(cidr):
    ip_net = ipaddress.ip_network("14.207.0.0/16")
    return f"{ip_net[0]}-{ip_net[-1]}"


@registry.register_transform(
    display_name="CrowdSec IP range Transform",
    input_entity="maltego.IPv4Address",
    description="Creates an IP range entity for an IP by leveraging CrowdSec CTI data",
    settings=[api_key_setting, cache_ttl_setting],
    transform_set=CrowdSecSet,
    output_entities=[Netblock],
)
class CrowdSecIPRange(DiscoverableTransform):
    @classmethod
    def create_entities(cls, request: MaltegoMsg, response):
        try:
            ip_ent = enriched_ip_with_cti_resp(request, response)
        except Exception as e:
            response.addUIMessage(str(e))
            return

        cti_resp = extract_cti_resp_from_ip_ent(ip_ent)
        netblock = response.addEntity(Netblock, "")
        netblock.addProperty("ipv4-range", value=cidr_to_range(cti_resp["ip_range"]))
        netblock.addProperty("ip_range_score", value=str(cti_resp["ip_range_score"]))
        netblock.addDisplayInformation(
            f"<h2> CrowdSec IP Range Score: {str(cti_resp['ip_range_score'])} </h2> <p>  Score of malevolence associated with an IP range, ranging from 0 (No IP reported) to 5 (massively reported). It is calculated based on the number of IPs belonging to this range that were reported by the community as malicious </p>"
        )
