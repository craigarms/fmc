import argparse
from libs import fmc_library as fmc
from pprint import pprint
import urllib3
from decouple import config
import traceback
import ipaddress

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def search_object(args):
    try:
        if args.ip:
            if "/" in args.ip or "-" in args.ip:
                net = args.ip.replace("-", "/")
                search_type = 'NETS'
                string = net
            else:
                search_type = 'HOSTS'
                string = args.ip
        elif args.group:
            search_type = 'NETGRP'
            string = args.group
        elif args.service:
            search_type = 'PORTS'
            string = args.service
        elif args.fqdn:
            pass

        o = fmc.getObjects(search_type, limit=1000, offline=args.offline)
        search = fmc.SearchObject(o, string)

        if args.output == 'table':
            print(fmc.formatTable(search))
        elif args.output == 'asa':
            print(fmc.formatASA(search))
        elif args.output == 'json':
            pprint(search)

        fmc.saveCache()

    except Exception as e:
        print(traceback.format_exc())
        pprint(args)


def add_object(args):
    try:
        if args.ip:
            if "/" in args.ip or "-" in args.ip:
                net = args.ip.replace("-", "/")
                if ipaddress.IPv4Network(net):
                    name = args.name if args.name else ""
                    description = args.description if args.description else ""
                    result = fmc.insertNet(net, name, description)
                    args.offline = False
                    args.output = 'table'
                    search_object(args)
            else:
                if ipaddress.IPv4Address(args.ip):
                    name = args.name if args.name else ""
                    description = args.description if args.description else ""
                    result = fmc.insertHost(args.ip, name, description)
                    args.offline = False
                    args.output = 'table'
                    search_object(args)
        elif args.group:
            if '=' in args.group:
                name = args.group.split('=')[0]
                description = args.description if args.description else ""
                if ',' in args.group.split('=')[1]:
                    members = args.group.split('=')[1].split(',')
                    fmc.insertGroup(members, name, description)
                    args.offline = False
                    args.output = 'table'
                    args.group = name
                    search_object(args)
        elif args.service:
            name = args.name if args.name else ""
            description = args.description if args.description else ""
            if '/' in args.service:
                if isinstance(int(args.service.split('/')[0]), int):
                    port = args.service.split('/')[0]
                    protocol = args.service.split('/')[1]
                elif isinstance(int(args.service.split('/')[1]), int):
                    port = args.service.split('/')[1]
                    protocol = args.service.split('/')[0]
                fmc.insertService(port, protocol, name, description)
                args.offline = False
                args.output = 'table'
                args.service = name if name else args.service
                search_object(args)
        elif args.fqdn:
            pass
    except ipaddress.AddressValueError:
        print(f"Given IP address parameter {args.ip} is not correct")

    except Exception as e:
        print(traceback.format_exc())


def main():
    parser = argparse.ArgumentParser(description="FMC Utils to manage objects in CLI")
    parser.add_argument('--debug', '-d', action='store_true')

    subparsers = parser.add_subparsers()

    searchparser = subparsers.add_parser('search', help="Search for a rule or object")
    searchgroup = searchparser.add_mutually_exclusive_group(required=True)
    searchgroup.add_argument('--ip', '-i')
    searchgroup.add_argument('--service', '-s')
    searchgroup.add_argument('--group', '-g')
    searchgroup.add_argument('--fqdn', '-f')
    searchparser.add_argument('--output', '-o', choices=['asa', 'table', 'json'], default='table')
    searchparser.add_argument('--offline', action='store_true', help='Try to perform search with offline cache', default=False)
    searchparser.set_defaults(func=search_object)

    addparser = subparsers.add_parser('add', help="Add rule or object")
    addgroup = addparser.add_mutually_exclusive_group(required=True)
    addgroup.add_argument('--ip', '-i')
    addgroup.add_argument('--service', '-s')
    addgroup.add_argument('--group', '-g')
    addgroup.add_argument('--fqdn', '-f')
    addparser.add_argument('--name', '-n')
    addparser.add_argument('--description', '-d')
    addparser.set_defaults(func=add_object)

    args = parser.parse_args()
    if 'func' in args:
        args.func(args)
    else:
        parser.print_help()


try:
    fmc = fmc.Fmc(config('FMC_URL'),
                      config('API_USERNAME'),
                      config('API_PASSWD'))
    main()
except decouple.UndefinedValueError:
    print(".env file needs to contain:"
          " - FMC_URL"
          " - API_USERNAME"
          " - API_PASSWD")
