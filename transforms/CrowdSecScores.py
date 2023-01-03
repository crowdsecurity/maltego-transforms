from maltego_trx.maltego import MaltegoMsg
from maltego_trx.transform import DiscoverableTransform

from extensions import registry
from transform_sets import CrowdSecSet
from settings import api_key_setting, cache_ttl_setting
from utils import (
    clone_ip_entity,
    enriched_ip_with_cti_resp,
    extract_cti_resp_from_ip_ent,
)


@registry.register_transform(
    display_name="CrowdSec Attack Detail Split",
    input_entity="maltego.IPv4Address",
    description="Splits Attack Entity into scenarios",
    settings=[api_key_setting, cache_ttl_setting],
    transform_set=CrowdSecSet,
)
class CrowdSecScores(DiscoverableTransform):
    @classmethod
    def create_entities(cls, request: MaltegoMsg, response):
        try:
            ip_ent = enriched_ip_with_cti_resp(request, response)
        except Exception as e:
            response.addUIMessage(str(e))
            return
        cti_resp = extract_cti_resp_from_ip_ent(ip_ent)
        ip_ent.addDisplayInformation(
            f"""
        <table>
            <tr>
                <th>CrowdSec Score Type</th>
                <th>Value</th>
            </tr>
            <tr>
                <td>  Background Noise</td>
                <td> {cti_resp['background_noise_score']}</td>
            </tr>
            <tr>
                <td> Overall Aggressiveness </td>
                <td> {cti_resp["scores"]['overall']['aggressiveness']}</td>
            </tr>
            <tr>
                <td> Overall Threat </td>
                <td> {cti_resp["scores"]['overall']['threat']}</td>
            </tr>
            <tr>
                <td> Overall Trust</td>
                <td> {cti_resp["scores"]['overall']['trust']}</td>
            </tr>
            <tr>
                <td> Overall Anomaly</td>
                <td> {cti_resp["scores"]['overall']['trust']}</td>
            </tr>
            <tr>
                <td> Overall Total</td>
                <td> {cti_resp["scores"]['overall']['total']}</td>
            </tr>
            <tr>
                <td> Last Day Aggressiveness</td>
                <td> {cti_resp["scores"]['last_day']['aggressiveness']}</td>
            </tr>
            <tr>
                <td> Last Day Threat</td>
                <td> {cti_resp["scores"]['last_day']['threat']}</td>
            </tr>
            <tr>
                <td> Last Day Trust</td>
                <td> {cti_resp["scores"]['last_day']['trust']}</td>
            </tr>
            <tr>
                <td> Last Day Anomaly</td>
                <td> {cti_resp["scores"]['last_day']['trust']}</td>
            </tr>
            <tr>
                <td> Last Day Total</td>
                <td> {cti_resp["scores"]['last_day']['total']}</td>
            </tr>
            <tr>
                <td> Last Week Aggressiveness</td>
                <td> {cti_resp["scores"]['last_week']['aggressiveness']}</td>
            </tr>
            <tr>
                <td> Last Week Threat</td>
                <td> {cti_resp["scores"]['last_week']['threat']}</td>
            </tr>
            <tr>
                <td> Last Week Trust</td>
                <td> {cti_resp["scores"]['last_week']['trust']}</td>
            </tr>
            <tr>
                <td> Last Week Anomaly</td>
                <td> {cti_resp["scores"]['last_week']['trust']}</td>
            </tr>
            <tr>
                <td> Last Week Total</td>
                <td> {cti_resp["scores"]['last_week']['total']}</td>
            </tr>
            <tr>
                <td> Last Month Aggressiveness</td>
                <td> {cti_resp["scores"]['last_month']['aggressiveness']}</td>
            </tr>
            <tr>
                <td> Last Month Threat</td>
                <td> {cti_resp["scores"]['last_month']['threat']}</td>
            </tr>
            <tr>
                <td> Last Month Trust</td>
                <td> {cti_resp["scores"]['last_month']['trust']}</td>
            </tr>
            <tr>
                <td> Last Month Anomaly</td>
                <td> {cti_resp["scores"]['last_month']['trust']}</td>
            </tr>
            <tr>
                <td> Last Month Total</td>
                <td> {cti_resp["scores"]['last_month']['total']}</td>
            </tr>
        </table>
        """,
            "CrowdSec Scores",
        )
