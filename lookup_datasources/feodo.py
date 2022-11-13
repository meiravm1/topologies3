import requests
import datetime
import json
import pathlib
from cachetools import cached, TTLCache
from lookup_datasources.lookup_datasources import LookupDatasources
from utils import Utils

_CACHE_INVALIDATE_TIME = 60


class Feodo(LookupDatasources):
    '''get malicious ips from feodo'''

    def __init__(self):
        LookupDatasources.__init__(self)
        self.conf = Utils.load_conf()['Feodo']
        self.black_list_cache = []

    @cached(cache=TTLCache(maxsize=1, ttl=_CACHE_INVALIDATE_TIME))
    def cache_refresh(self):
        try:
            x = requests.get(self.conf['url'])
            # TODO logger
            print(f"{datetime.datetime.now()} feodo cache refresh!!!!")

            if x.status_code == 200:
                response = x.json()
                for item in response:
                    if Feodo._validate_response(item):
                        if item['ip_address'] not in self.black_list_cache:
                            self.black_list_cache.append(item['ip_address'])
                            # TODO update cache file to overcome feodo unavailability
                    else:
                        print("WARNING! feodo response is not in the expected format")
        except requests.exceptions.RequestException as e:
            if len(self.black_list_cache):
                print("ERROR refreshing cache, load cache from saved file")
                # load stale cache from file

    @staticmethod
    def _validate_response(item: dict) -> bool:
        directory_path = pathlib.Path(__file__).resolve().parent
        with (directory_path / "feodo_template.json").open("r") as template_file:
            template = json.load(template_file)
        return set(item.keys()) \
            .issubset(template.keys())

    ''' check whether ip in message in not malicious'''
    def check(self, message) -> bool:
        try:
            Feodo.cache_refresh(self)
            if message['source_ip'] in self.black_list_cache:
                LookupDatasources.alerts(type(self).__name__, message, message['source_ip'])
                return False
            elif message['destination_ip'] in self.black_list_cache:
                LookupDatasources.alerts(type(self).__name__, message, message['destination_ip'])
                return False
            return True
        except Exception as e:
            print(f"failed checking message {message} ({type(self).__name_}) ")

