from lookup_datasources.lookup_datasources import LookupDatasources
import re
import requests
import datetime
from cachetools import cached, TTLCache
from utils import Utils

_CACHE_INVALIDATE_TIME = 60

class Tor(LookupDatasources):
    '''get malicious ips from tor'''

    def __init__(self):
        LookupDatasources.__init__(self)
        self.conf = Utils.load_conf()['Tor']
        self.black_list_cache = []

    def check(self, message) -> bool:

        Tor.cache_refresh(self)
        if message['source_ip'] in self.black_list_cache:
            LookupDatasources.alerts(type(self).__name__, message, message['source_ip'])
            return False
        elif message['destination_ip'] in self.black_list_cache:
            LookupDatasources.alerts(type(self).__name__, message, message['destination_ip'])
            return False
        return True

    @staticmethod
    def _validate_response(item) -> bool:
        ip = re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", item)
        if ip:
            return True
        else:
            return False

    @cached(cache=TTLCache(maxsize=100000, ttl=_CACHE_INVALIDATE_TIME))
    def cache_refresh(self):

        x = requests.get(self.conf['url'])
        # TODO logger
        print(f"{datetime.datetime.now()} tor cache refresh!!!!")

        if x.status_code == 200:
            for item in x.iter_lines():
                if Tor._validate_response(item.decode()):
                    if item not in self.black_list_cache:
                        self.black_list_cache.append(item.decode())
                else:
                    print("WARNING! tor response is not in the expected format")


