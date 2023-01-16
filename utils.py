import datetime
import json
from typing import Any, Dict

import requests
from dateutil.parser import parse as datetime_parse
from maltego_trx.maltego import MaltegoEntity, MaltegoMsg


def getProperty(entity: MaltegoEntity, propertyName: str) -> Any | None:
    for fieldName, displayName, matchingRule, value in entity.additionalFields:
        if fieldName == propertyName:
            return value
    return None


def clone_ip_entity(request: MaltegoMsg, response) -> MaltegoEntity:
    type_name = "maltego.IPv4Address"
    extra_props = {}
    if request.Genealogy:
        type_name = request.Genealogy[0]["Name"]
    extra_props = request.Properties
    input_ip = response.addEntity(type_name, request.Value)
    for k, v in extra_props.items():
        input_ip.addProperty(fieldName=k, value=v, matchingRule="loose")
    return input_ip


def cti_resp_present(ip_entity: MaltegoEntity):
    return getProperty(ip_entity, "crowdsec_cti_resp") is not None


def cti_expired_ttl(ip_entity: MaltegoEntity, cache_ttl_in_seconds: int):
    if not cache_ttl_in_seconds:
        cache_ttl_in_seconds = 120
    cti_resp = extract_cti_resp_from_ip_ent(ip_entity)
    return datetime.datetime.now() - datetime_parse(
        cti_resp["fetch_ts"]
    ) > datetime.timedelta(seconds=int(cache_ttl_in_seconds))


def enriched_ip_with_cti_resp(request: MaltegoMsg, response):
    ip_entity = clone_ip_entity(request, response)
    cache_ttl_in_seconds = request.TransformSettings.get("CS_api_cache_ttl_in_seconds")
    if cti_resp_present(ip_entity) and not cti_expired_ttl(
        ip_entity, cache_ttl_in_seconds
    ):
        return ip_entity
    api_url = f"https://cti.api.crowdsec.net/v2/smoke/{ip_entity.value}"
    api_key = request.TransformSettings.get("CS_api_key")
    if not api_key:
        raise Exception("Error: CS_api_key is missing")
    crowdsec_cti = requests.get(
        api_url,
        headers={"x-api-key": api_key},
    )
    try:
        crowdsec_cti.raise_for_status()
    except Exception as e:
        raise Exception(f"Error: {e} while calling CrowdSec CTI API")

    crowdsec_cti = crowdsec_cti.json()
    if not crowdsec_cti:
        raise Exception("No intelligence found for this IP in CrowdSec CTI API")
    crowdsec_cti["fetch_ts"] = str(datetime.datetime.now())
    ip_entity.addProperty("crowdsec_cti_resp", value=json.dumps(crowdsec_cti))
    return ip_entity


def extract_cti_resp_from_ip_ent(ip_entity: MaltegoEntity) -> Dict:
    return json.loads(getProperty(ip_entity, "crowdsec_cti_resp"))
