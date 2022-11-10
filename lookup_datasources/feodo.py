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



    # TODO handle maxsize ,
    @cached(cache=TTLCache(maxsize=100000, ttl=_CACHE_INVALIDATE_TIME))
    def cache_refresh(self):

        x = requests.get(self.conf['url'])
        # TODO logger
        print(f"{datetime.datetime.now()} feodo cache refresh!!!!")

        if x.status_code == 200:
            response = x.json()
            for item in response:
                if Feodo._validate_response(item):
                    if item['ip_address'] not in self.black_list_cache:
                        self.black_list_cache.append(item['ip_address'])
                else:
                    print("WARNING! feodo response is not in the expected format")

        # TODO logger debug
        # for item in self.black_list_cache:
        #     print(item)


    @staticmethod
    def _validate_response(item: dict) -> bool:
        directory_path = pathlib.Path(__file__).resolve().parent
        with (directory_path / "feodo_template.json").open("r") as template_file:
            template = json.load(template_file)
        return set(template.keys()) \
            .issubset(item.keys())

    def check(self, message):
        Feodo.cache_refresh(self)
        if message['source_ip'] in self.black_list_cache:
            LookupDatasources.alerts(type(self).__name__, message, message['source_ip'])
        elif message['destination_ip'] in self.black_list_cache:
            LookupDatasources.alerts(type(self).__name__, message, message['destination_ip'])


