from . import fmc_config as cfg
import requests
import json
import time
from requests.auth import HTTPBasicAuth
import logging
from tabulate import tabulate
import os


class Fmc:
    def __init__(self, server, username, password):
        self.server = server
        self.token = self.getAuthToken(username, password)
        self.cache = {}

    FORMAT = '[%(asctime)s] %(levelname)s %(funcName)s %(message)s'
    logging.basicConfig(format=FORMAT, level=logging.INFO)

    def getAuthToken(self, username, password):
        stime = time.time()
        logging.info('Starting Auth process with '+ self.server)
        auth = {}
        r = None
        headers = {'Content-Type': 'application/json'}
        api_auth_path = self.getAPIPath('TOKEN')
        auth_url = self.server + api_auth_path
        try:
            r = requests.post(auth_url, headers=headers, auth=requests.auth.HTTPBasicAuth(username, password), verify=False)
            auth_headers = r.headers
            auth['token'] = auth_headers.get('X-auth-access-token', default=None)
            auth['domain'] = auth_headers.get('domain_uuid', default=None)
        except Exception as err:
            logging.error('Error in generating auth token: ' + str(err))
        logging.debug('Auth token acquired')
        logging.info('Auth token successfully acquired in %s seconds', str(time.time() - stime))
        return auth

    def getQuery(self, path, domain=""):
        stime = time.time()
        logging.debug('Building Get Query for ' + self.server + ' to ' + path)
        if not domain:
            domain = self.token['domain']

        headers = {'Content-Type': 'application/json'}
        headers['X-auth-access-token'] = self.token['token']
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

    def getPaginatedQuery(self, auth, path, domain=""):
        stime = time.time()
        logging.debug('Building Paginated Get Query for ' + self.server + ' to ' + path)
        response = self.getQuery(path, domain)
        result = response

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
        headers['X-auth-access-token'] = self.token['token']
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
        logging.debug(f'Retrieving {object} from cache')
        if objet in self.cache:
            logging.debug(f'Cache age for {object} is {time.time() - self.cache[objet]["tombstone"]}')
            if time.time() - self.cache[objet]["tombstone"] < tombstone:
                return self.cache[objet]

        data = {}
        logging.debug(f'Loading {object} from saved cache')
        if os.path.isfile('data.json'):
            with open('data.json', 'r') as fp:
                data = json.load(fp)

        if objet in data:
            logging.debug(f'Loading {objet} saved cache into live cache')
            self.cache[objet] = data[objet]

        return data[objet]

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
                if 'items' in result:
                    objects['items'].extend(result['items'])
        else:
            objects = self.getPaginatedQuery(self.server, f"{api_path}&limit={limit}", domain)

        self.cache[api] = objects
        self.cache[api]["tombstone"] = time.time()
        return objects

    def getAllDevices(self, domain=""):
        api_path = self.getAPIPath('DEVICES')
        named_devices = {}
        devices = self.getObjects(api_path, domain)

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
        return tabulate(items, columns, tablefmt="grid")

    def saveCache(self):
        with open('data.json', 'w') as fp:
            json.dump(self.cache, fp)