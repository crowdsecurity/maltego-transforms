import sys
import transforms
from extensions import registry
from maltego_trx.handler import handle_run
from maltego_trx.registry import register_transform_classes
from maltego_trx.server import app as application

register_transform_classes(transforms)

registry.write_transforms_config()
registry.write_settings_config()
registry.write_local_mtz(
    mtz_path= "./local.mtz", # path to the local .mtz file
    working_dir= ".",
    command= "/Users/shivamsandbhor/work/crowdsec_maltego/venv/bin/python", # for a venv you might want to use `./venv/bin/python3`
    params= "project.py",
    debug = True
)
if __name__ == '__main__':
    handle_run(__name__, sys.argv, application)
