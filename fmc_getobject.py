from libs import fmc_library as fmc
from pprint import pprint
import urllib3
from decouple import config
import argparse
import traceback


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

parser = argparse.ArgumentParser(description='Search for object in FMC Object database')
parser.add_argument('--type', '-t', help='Object type: HOSTS, NETGRP, NETS', required=True)
parser.add_argument('--format', '-f', help='Output format', default='table')
parser.add_argument('--offline', action='store_true', help='Try to perform search with offline cache', default=False)
parser.add_argument('string', help='search string')

args = parser.parse_args()

fmc = fmc.Fmc(config('FMC_URL'),
              config('API_USERNAME'),
              config('API_PASSWD'))

try:
    o = fmc.getObjects(args.type, limit=1000, offline=args.offline)
    search = fmc.SearchObject(o, args.string)

    if args.format == 'table':
        print(fmc.formatTable(search))
    elif args.format == 'asa':
        print(fmc.formatASA(search))
    elif args.format == 'json':
        pprint(search)

    fmc.saveCache()

except Exception as e:
    print(traceback.format_exc())
