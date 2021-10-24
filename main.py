from libs import fmc_library as fmc, fmc_config as cfg
from pprint import pprint
import urllib3
from decouple import config
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

fmc = fmc.Fmc(config('FMC_URL'),
              config('API_USERNAME'),
              config('API_PASSWD'))

o = fmc.getObjects(cfg.URL_NETGRP, limit=1000)

print(fmc.formatTable(fmc.SearchObject(o, "SAP")))

pprint(fmc.SearchObject(o, "SAP"))

print(fmc.formatASA(fmc.SearchObject(o, "SAP")))
