from lookup_datasources.lookup_datasources import LookupDatasources
import requests
import datetime

from cachetools import cached, TTLCache



class MyLookupSource(LookupDatasources):
    def __init__(self):
        LookupDatasources.__init__(self)

    black_list_cache = []

    def check(self, message):

        if message['source_ip'] in self.black_list_cache:
            LookupDatasources.alerts(type(self).__name__, message, message['source_ip'])
        elif message['destination_ip'] in self.black_list_cache:
            LookupDatasources.alerts(type(self).__name__, message, message['destination_ip'])

    @staticmethod
    def _validate_response(item) -> bool:
        return False

    @cached(cache=TTLCache(maxsize=100000, ttl=60))
    def cache_refresh(self, conf):

        x = requests.get('https://check.torproject.org/torbulkexitlist')
        # TODO logger
        print(f"{datetime.datetime.now()} my cache refreshed!!!!")

        if x.status_code == 200:
            for item in x.iter_lines():
                if MyLookupSource._validate_response(item.decode()):
                    if item not in self.black_list_cache:
                        self.black_list_cache.append(item.decode())
                else:
                    print("WARNING! tor response is not in the known format")
