import pycountry
from maltego_trx.entities import GPS, Location
from maltego_trx.maltego import MaltegoMsg
from maltego_trx.transform import DiscoverableTransform

from extensions import registry
from settings import api_key_setting
from transforms.utils import (enriched_ip_with_cti_resp,
                              extract_cti_resp_from_ip_ent)


@registry.register_transform(
    display_name="CrowdSec Location Transform",
    input_entity="maltego.IPv4Address",
    description="Adds location entities by leveraging CrowdSec CTI data",
    settings=[api_key_setting],
)
class CrowdSecLocation(DiscoverableTransform):
    @classmethod
    def create_entities(cls, request: MaltegoMsg, response):
        try:
            ip_ent = enriched_ip_with_cti_resp(request, response)
        except Exception as e:
            response.addUIMessage(str(e))

        cti_resp = extract_cti_resp_from_ip_ent(ip_ent)
        country_name = pycountry.countries.get(
            alpha_2=cti_resp["location"]["country"]
        ).name
        location = response.addEntity(
            Location, f'{cti_resp["location"]["city"]}, {country_name}'
        )
        location.addProperty("country", value=country_name)
        location.addProperty("city", value=cti_resp["location"]["city"])

        gps = response.addEntity(GPS, "")
        gps.addProperty("longitude", value=cti_resp["location"]["longitude"])
        gps.addProperty("latitude", value=cti_resp["location"]["latitude"])
