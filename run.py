import logging.config
import os
import yaml

from service.rest import create_app
from settings import config_by_name

config = config_by_name[os.getenv('sysenv', 'prod')]()
app = create_app(config)

path = os.path.dirname(os.path.abspath(__file__)) + '/' + 'logging.yml'
value = os.getenv('LOG_CFG', None)
if value:
    path = value
if os.path.exists(path):
    with open(path, 'rt') as f:
        lconfig = yaml.safe_load(f.read())
    logging.config.dictConfig(lconfig)
else:
    logging.basicConfig(level=logging.INFO)
logging.raiseExceptions = True

if __name__ == '__main__':
    app.run(debug=True)
