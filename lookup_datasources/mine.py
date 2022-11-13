
import json
import datetime
import pathlib
from cachetools import cached, TTLCache

from lookup_datasources.lookup_datasources import LookupDatasources
from utils import Utils


class Mine(LookupDatasources):
    def __init__(self):
        LookupDatasources.__init__(self)
        self.conf = Utils.load_conf()['Mine']
        self.black_list_cache = []

    def check(self, message) -> bool:
        # TODO in other datasource
        try:
            Mine.cache_refresh(self)
            if message['source_ip'] in self.black_list_cache:
                LookupDatasources.alerts(type(self).__name__, message, message['source_ip'])
                return False
            elif message['destination_ip'] in self.black_list_cache:
                LookupDatasources.alerts(type(self).__name__, message, message['destination_ip'])
                return False
            return True
        except Exception as e:
            print(f"failed checking message {message} ({type(self).__name_}) ")
            return False

    @staticmethod
    def _validate_response(item) -> bool:
        return True

    @cached(cache=TTLCache(maxsize=1, ttl=10))
    def cache_refresh(self):
        # TODO maybe transfer conf to init

        print(self.conf)
        path = pathlib.Path(__file__).resolve().parent

        with (path / "mine.txt").open(
                "r") as ips:
            for ip in ips:
                if ip.strip() not in self.black_list_cache:
                    self.black_list_cache.append(ip.strip())

        # TODO logger
        print(f"{datetime.datetime.now()} my cache refreshed!!!!")

        for ip in self.black_list_cache:
            print(ip)

