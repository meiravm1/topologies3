from cachetools import cached, TTLCache
from lookup_datasources.lookup_datasources import LookupDatasources
from lookup_datasources.feodo_cache import FeodoCache
from utils import Utils

_CACHE_INVALIDATE_TIME = 60


class Feodo(LookupDatasources):
    '''get malicious ips from feodo'''

    def __init__(self):
        LookupDatasources.__init__(self)
        self.conf = Utils.load_conf()['Feodo']
        self.feodo_cache = FeodoCache()

    @staticmethod
    def get_source_desc():
        return "Feodo"

    ''' check whether ip in message in not malicious'''

    def check(self, message) -> bool:
        source_name = Feodo.get_source_desc()
        try:
            black_list_cache = self.feodo_cache.get_cache()

            if message['source_ip'] in black_list_cache:
                LookupDatasources.alerts(source_name, message, message['source_ip'])
                return False
            elif message['destination_ip'] in black_list_cache:
                LookupDatasources.alerts(source_name, message, message['destination_ip'])
                return False
            return True
        except Exception as e:
            print(f"failed checking message {message} ({source_name}) ")
