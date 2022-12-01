import re

import requests

from maltego_trx.maltego import MaltegoMsg
from maltego_trx.transform import DiscoverableTransform
from settings import api_key_setting
from extensions import registry

CVE_REGEX = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
find_all_cve = CVE_REGEX.findall

@registry.register_transform(display_name="CrowdSec IP Enricher",
                             input_entity="maltego.IPv4Address",
                             description="Enriches IP addresses with CrowdSec's Intelligence",
                             settings=[api_key_setting])
class CrowdSec(DiscoverableTransform):
    @classmethod
    def create_entities(cls, request: MaltegoMsg, response):
        ip = request.Value
        api_url = f"https://cti.api.crowdsec.net/v2/smoke/{ip}"
        api_key = request.TransformSettings.get("CS_api_key")
        if not api_key:
            response.addUIMessage(f"Error: CS_api_key is missing")
            return
        crowdsec_cti = requests.get(
            api_url,
            headers={"x-api-key": api_key},
        )
        try:
            crowdsec_cti.raise_for_status()
        except Exception as e:
            response.addUIMessage(f"Error: {e} while calling CrowdSec CTI API")
            return

        crowdsec_cti = crowdsec_cti.json()
        if not crowdsec_cti:
            response.addUIMessage("No intelligence found for this IP in CrowdSec CTI API")
            return
    
        # make a precise copy of the input to avoid creating a new graph entity
        type_name = "maltego.IPv4Address"
        extra_props = {}
        if request.Genealogy:
            type_name = request.Genealogy[0]["Name"]
            extra_props = request.Properties
        input_ip = response.addEntity(type_name, request.Value)
        for k, v in extra_props.items():
            input_ip.addProperty(fieldName=k, value=v, matchingRule="loose")

        for scenario in crowdsec_cti["attack_details"]:
            scenario_name = scenario["name"]
            response.addEntity("crowdsec.scenario", scenario_name)
            cves = find_all_cve(scenario_name)
            for cve in cves:
                response.addEntity("crowdsec.cve", cve.upper())

        response.addEntity("crowdsec.last_seen", crowdsec_cti["history"]["last_seen"])
        response.addEntity("crowdsec.first_seen", crowdsec_cti["history"]["first_seen"])

        if crowdsec_cti["location"]["city"]:
            response.addEntity("crowdsec.location.city", crowdsec_cti["location"]["city"])
        
        if crowdsec_cti["location"]["country"]:
            response.addEntity("crowdsec.location.country", crowdsec_cti["location"]["country"])

        if crowdsec_cti["location"]["latitude"]:
            response.addEntity("crowdsec.location.latitude", crowdsec_cti["location"]["latitude"])

        if crowdsec_cti["location"]["longitude"]:
            response.addEntity("crowdsec.location.longitude", crowdsec_cti["location"]["longitude"])
        
        response.addEntity("crowdsec.background_noise_score", str(crowdsec_cti["background_noise_score"]))
        response.addEntity("crowdsec.ip_range_score", str(crowdsec_cti["ip_range_score"]))
        response.addEntity("crowdsec.ip_range", crowdsec_cti["ip_range"])
        response.addEntity("crowdsec.as_name", crowdsec_cti["as_name"])
        response.addEntity("crowdsec.as_num", str(crowdsec_cti["as_num"]))
        response.addEntity("crowdsec.scores.aggressiveness", str(crowdsec_cti["scores"]["overall"]["aggressiveness"]))
        response.addEntity("crowdsec.scores.threat", str(crowdsec_cti["scores"]["overall"]["threat"]))
        response.addEntity("crowdsec.scores.trust", str(crowdsec_cti["scores"]["overall"]["trust"]))
        response.addEntity("crowdsec.scores.anomaly", str(crowdsec_cti["scores"]["overall"]["anomaly"]))
        response.addEntity("crowdsec.scores.total", str(crowdsec_cti["scores"]["overall"]["total"]))