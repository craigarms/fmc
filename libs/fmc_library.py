from . import fmc_config as cfg
import requests
import json
import time
from requests.auth import HTTPBasicAuth
import logging
from tabulate import tabulate
import os
from pprint import pprint


class Fmc:
    def __init__(self, server, username, password):
        self.server = server
        self.username = username
        self.password = password
        self.token = {}
        self.cache = {}
        self.setLoggingLevel("WARN")

    def setLoggingLevel(self, level):
        FORMAT = '[%(asctime)s] %(levelname)s %(funcName)s %(message)s'
        if level == "WARN":
            logging.basicConfig(format=FORMAT, level=logging.DEBUG)
        elif level == "DEBUG":
            logging.basicConfig(format=FORMAT, level=logging.DEBUG)

    def getAuthToken(self):
        if self.token:
            return self.token

        stime = time.time()
        logging.info('Starting Auth process with '+ self.server)
        auth = {}
        r = None
        headers = {'Content-Type': 'application/json'}
        api_auth_path = self.getAPIPath('TOKEN')
        auth_url = self.server + api_auth_path
        try:
            r = requests.post(auth_url, headers=headers, auth=requests.auth.HTTPBasicAuth(self.username, self.password), verify=False)
            auth_headers = r.headers
            auth['token'] = auth_headers.get('X-auth-access-token', default=None)
            auth['domain'] = auth_headers.get('domain_uuid', default=None)
        except Exception as err:
            logging.error('Error in generating auth token: ' + str(err))
        logging.debug('Auth token acquired')
        logging.info('Auth token successfully acquired in %s seconds', str(time.time() - stime))
        self.token = auth
        return auth

    def getQuery(self, path, domain=""):
        stime = time.time()
        logging.debug('Building Get Query for ' + self.server + ' to ' + path)
        if not domain:
            domain = self.getAuthToken()['domain']

        headers = {'Content-Type': 'application/json'}

        headers['X-auth-access-token'] = self.getAuthToken()['token']
        api_path = cfg.FMC_API_BASE + domain + path

        url = self.server + api_path
        if url[-1] == '/':
            url = url[:-1]

        try:
            r = requests.get(url, headers=headers, verify=False)
            status_code = r.status_code
            resp = r.text
            if (status_code == 200):
                json_resp = json.loads(resp)
                logging.debug('Returning JSON response for status code ' + str(status_code))
                logging.info('Successfully got query response for %s in %s seconds', path, str(time.time() - stime))
                return json_resp
            else:
                r.raise_for_status()
                logging.error('Error occurred in GET: ' + resp)
                return None
        except requests.exceptions.HTTPError as err:
            logging.error('Error in connection: ' + str(err))
            return None
        finally:
            if r: r.close()

    def postQuery(self, path, data, domain=""):
        stime = time.time()
        logging.debug('Building Post Query for ' + self.server + ' to ' + path)
        logging.debug(data)
        if not domain:
            domain = self.getAuthToken()['domain']

        headers = {'Content-Type': 'application/json'}

        headers['X-auth-access-token'] = self.getAuthToken()['token']
        api_path = cfg.FMC_API_BASE + domain + path

        url = self.server + api_path
        if url[-1] == '/':
            url = url[:-1]

        try:
            r = requests.post(url, data=json.dumps(data), headers=headers, verify=False)
            status_code = r.status_code
            resp = r.text
            if (status_code == 201 or status_code == 202):
                json_resp = json.loads(resp)
                logging.debug('Returning JSON response for status code ' + str(status_code))
                logging.info('Successfully posted query response for %s in %s seconds', path, str(time.time() - stime))
                return json_resp
            else:
                r.raise_for_status()
                logging.error('Error occurred in POST: ' + json.loads(resp))
                return json.loads(resp)
        except requests.exceptions.HTTPError as err:
            logging.error('Error in connection: ' + str(err))
            logging.error('Error occurred in POST: ' + resp)
            return json.loads(resp)
        finally:
            if r: r.close()

    def getPaginatedQuery(self, auth, path, domain=""):
        stime = time.time()
        logging.debug('Building Paginated Get Query for ' + self.server + ' to ' + path)
        response = self.getQuery(path, domain)
        result = response

        if response:
            if 'paging' in response:
                while 'next' in response['paging']:
                    base = self.server + cfg.FMC_API_BASE + domain
                    url = response['paging']['next'][0].replace(base, '')
                    response = self.getQuery(url, domain)
                    if 'items' in response:
                        result['items'].extend(response['items'])

        return result

    def getDomains(self):
        stime = time.time()
        api_path = self.getAPIPath('DOMAINS')
        headers = {'Content-Type': 'application/json'}
        headers['X-auth-access-token'] = self.getAuthToken()['token']
        url = self.server + api_path

        try:
            r = requests.get(url, headers=headers, verify=False)
            status_code = r.status_code
            resp = r.text
            if status_code == 200:
                json_resp = json.loads(resp)
                logging.debug('Returning JSON response for status code ' + str(status_code))
                logging.info('Successfully got query response for %s in %s seconds', "domains", str(time.time() - stime))
                return json_resp
            else:
                r.raise_for_status()
                logging.error('Error occurred in GET: ' + resp)
                return None
        except requests.exceptions.HTTPError as err:
            logging.error('Error in connection: ' + str(err))
            return None
        finally:
            if r: r.close()

    def getAPIPath(self, object_type):
        for k, v in cfg.api_path.items():
            if object_type in k:
                return v

    def getOfflineObject(self, objet, tombstone):
        logging.debug(f'Retrieving {objet} from cache')
        if objet in self.cache:
            logging.debug(f'Cache age for {objet} is {time.time() - self.cache[objet]["tombstone"]}')
            if time.time() - self.cache[objet]["tombstone"] < tombstone:
                return self.cache[objet]

        logging.debug(f'Loading {objet} from saved cache')
        self.loadCache(objet)

        if objet in self.cache:
            logging.debug(f'Loading {objet} saved cache into live cache')
            logging.debug(f'Cache age for {objet} is {time.time() - self.cache[objet]["tombstone"]}')
            if time.time() - self.cache[objet]["tombstone"] < tombstone:
                return self.cache[objet]

        return self.cache[objet]

    def getObjects(self, api, domain="", limit="100", offline=False, tombstone=300):
        api_path = self.getAPIPath(api)

        if offline:
            object = self.getOfflineObject(api, tombstone)
            if object:
                return object

        objects = {'items': []}
        if not domain:
            domains = self.getDomains()
            for d in domains['items']:
                result = self.getPaginatedQuery(self.server, f"{api_path}&limit={limit}", d['uuid'])
                if result:
                    if 'items' in result:
                        objects['items'].extend(result['items'])
        else:
            objects = self.getPaginatedQuery(self.server, f"{api_path}&limit={limit}", domain)

        self.cache[api] = objects
        self.cache[api]["tombstone"] = time.time()
        return objects

    def getAllDevices(self, domain=""):
        named_devices = {}
        devices = self.getObjects('DEVICES', domain)

        # Sort devices so that they are accessible by name
        if 'items' in devices:
            for device in devices["items"]:
                named_devices[device["name"]] = device.copy()

        return named_devices

    def SearchObject(self, object, search):
        result = []
        for item in object['items']:
            if 'readOnly' in item['metadata']:
                continue
            if search in item['name']:
                result.append(item)
            elif 'value' in item:
                if search in item['value']:
                    result.append(item)
            elif 'literals' in item:
                for l in item['literals']:
                    if 'value' in l:
                        if search in l['value']:
                            result.append(item)
            elif 'protocol' in item and 'port' in item:
                if '/' in search:
                    search_split = search.split('/')
                    if search_split[0].upper() in item['protocol']:
                        if search_split[1] in item['port']:
                            result.append(item)
                    elif search_split[1].upper() in item['protocol']:
                        if search_split[0] in item['port']:
                            result.append(item)
        return result

    def formatASA(self, object):
        text = ""
        for o in object:
            if o['type'] == 'Host':
                text += f"object network {o['name']}\r\n" \
                    f"  host {o['value']}\r\n" \
                    f"  description {o['description']}\r\n"
            if o['type'] == 'Network':
                text += f"object network {o['name']}\r\n" \
                    f"  subnet {o['value']}\r\n" \
                    f"  description {o['description']}\r\n"
            if o['type'] == 'NetworkGroup':
                text += f"object-group network {o['name']}\r\n" \
                    f"  description {o['description']}\r\n"
                if 'literals' in o:
                    for l in o['literals']:
                        if l['type'] == 'Host':
                            text += f"  network-object host {l['value']}\r\n"
                if 'objects' in o:
                    for oo in o['objects']:
                        text += f"  network-object object {oo['name']}\r\n"
        return text

    def formatTable(self, object):
        items = []
        columns = []
        for o in object:
            if o['type'] == 'Host':
                columns = ['Name', 'Description', 'Value', 'Domain']
                item = [o['name'], o['description'], o['value'], o['metadata']['domain']['name']]
                items.append(item)
            if o['type'] == 'Network':
                columns = ['Name', 'Description', 'Value', 'Domain']
                item = [o['name'], o['description'], o['value'], o['metadata']['domain']['name']]
                items.append(item)
            if o['type'] == 'NetworkGroup':
                columns = ['Name', 'Description', 'Members', 'Domain']
                if 'literals' in o:
                    o['value'] = ""
                    for l in o['literals']:
                        o['value'] += f"{l['type']}: {l['value']}\r\n"
                if 'objects' in o:
                    o['value'] = ""
                    for oo in o['objects']:
                        o['value'] += f"{oo['type']}: {oo['name']}\r\n"
                item = [o['name'], o['description'], o['value'], o['metadata']['domain']['name']]
                items.append(item)
            if o['type'] == "AccessPolicy":
                columns = ['Name', 'Description', 'Default', 'Domain']
                item = [o['name'], (o['description'] if 'description' in o else ""), o['defaultAction']['action'], o['metadata']['domain']['name']]
                items.append(item)
            if o['type'] == "ProtocolPortObject":
                columns = ['Name', 'Port', 'Protocol', 'Description', 'Domain']
                item = [o['name'], o['port'], o['protocol'], (o['description'] if 'description' in o else ""), o['metadata']['domain']['name']]
                items.append(item)
        return tabulate(items, columns, tablefmt="grid")

    def saveCache(self):
        for api in self.cache:
            with open(f'{api}.json', 'w') as fp:
                json.dump(self.cache[api], fp)

    def loadCache(self, api):
        if os.path.isfile(f'{api}.json'):
            with open(f'{api}.json', 'r') as fp:
                self.cache[api] = json.load(fp)

    def updateCache(self, api):
        self.getObjects(api)
        self.saveCache()

    def ExtractUrlDomain(self, url):
        regex = r"\/domain\/([^\/]+)"

    def getAccessRules(self, policies):
        for policy in policies:
            if 'rules' in policy:
                base = self.server + cfg.FMC_API_BASE
                url = policy['rules']['links']['self'].replace(base, '')
                acl = self.getPaginatedQuery(self.server, url)

                return acl

    def buildName(self, type, data, reverse=False):
        if type == "host":
            return f"G_srv-{data}"
        elif type == "net":
            return f"G_net-{data}".replace("/","-")
        elif type == "fqdn":
            return f"G_fqdn-{data}"
        elif type == "service":
            return f"G_svc-{data.upper()}".replace("/","-")

    def insertHost(self, host, name="", description=""):
        path = "/object/hosts"
        if not name:
            name = self.buildName("host", host)
        post_data = {
            'name': name,
            'type': "host",
            'value': host,
            'description': description
        }

        return self.postQuery(path, post_data)

    def insertNet(self, net, name="", description=""):
        path = "/object/networks"
        if not name:
            name = self.buildName("net", net)
        post_data = {
            'name': name,
            'type': "Network",
            'value': net,
            'description': description
        }

        return self.postQuery(path, post_data)

    def insertGroup(self, members, name, description=""):
        path = '/object/networkgroups'
        post_data = {
            'name': name,
            'type': "NetworkGroup",
            'description': description,
            'literals': []
        }

        for member in members:
            item = {
                "value": member,
                "type": "Network" if '/' in member else "Host"
            }
            post_data['literals'].append(item)

        return self.postQuery(path, post_data)

    def insertService(self, port, protocol, name="", description=""):
        path = '/object/protocolportobjects'
        if not name:
            name = self.buildName("service", f"{port}/{protocol}")
        post_data = {
            'type': "ProtocolPortObject",
            'description': description,
            'name': name,
            'port': port,
            'protocol': protocol
        }
        return self.postQuery(path, post_data)

    def insertServiceGroup(self, members, name, description=""):
        self.updateCache("PORTS")
        path = '/object/portobjectgroups'
        post_data = {
            'name': name,
            'type': "PortObjectGroup",
            'description': description,
            'objects': []
        }

        for member in members:
            service = self.SearchObject(self.cache["PORTS"],
                                        self.buildName("service", f"{member['port']}/{member['protocol']}"))
            if len(service) == 1:
                if "id" in service[0]:
                    service = service[0]
            else:
                service = self.insertService(member['port'], member['protocol'])

            if "id" in service:
                post_data['objects'].append({"id": service['id'], 'type': "ProtocolPortObject"})

        return self.postQuery(path, post_data)
