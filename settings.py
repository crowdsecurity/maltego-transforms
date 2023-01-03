from maltego_trx.decorator_registry import TransformSetting

api_key_setting = TransformSetting(
    name="CS_api_key",
    display_name="API Key",
    setting_type="string",
    optional=False,
)

cache_ttl_setting = TransformSetting(
    name="CS_api_cache_ttl_in_seconds",
    display_name="CrowdSec Cache",
    setting_type="int",
    optional=True,
    default_value="120",
)

language_setting = TransformSetting(
    name="language",
    display_name="Language",
    setting_type="string",
    default_value="en",
    optional=True,
    popup=True,
)
