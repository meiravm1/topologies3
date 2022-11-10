import requests
import datetime
import json
from cachetools import cached, TTLCache
import pathlib
import re
from abc import ABC, abstractmethod
from alert_sinks import AlertSinks


class LookupDatasources(ABC):
    '''check'''

    @abstractmethod
    def check(self, message):
        pass

    @staticmethod
    def alerts(source, message, ip):
        for sink in AlertSinks.__subclasses__():
            sink.alert(source, message, ip)


class Feodo(LookupDatasources):
    '''get malicious ips from fedor'''
    black_list_cache = []

    # TODO handle maxsize ,
    @cached(cache=TTLCache(maxsize=100000, ttl=60))
    def cache_refresh(self, conf):
        print("refreshing cache..")
        x = requests.get('https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json')
        # TODO logger
        print(f"{datetime.datetime.now()} feodo cache refresh!!!!")

        if x.status_code == 200:
            response = x.json()
            for item in response:
                if Feodo._validate_response(item):
                    if item['ip_address'] not in self.black_list_cache:
                        self.black_list_cache.append(item['ip_address'])
                else:
                    print("WARNING! feodo response is not in the known format")

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

        if message['source_ip'] in self.black_list_cache:
            LookupDatasources.alerts(type(self).__name__, message, message['source_ip'])
        elif message['destination_ip'] in self.black_list_cache:
            LookupDatasources.alerts(type(self).__name__, message, message['destination_ip'])


class Tor(LookupDatasources):
    '''get malicious ips from tor'''

    black_list_cache = []

    def check(self, message):

        if message['source_ip'] in self.black_list_cache:
            LookupDatasources.alerts(type(self).__name__, message, message['source_ip'])
        elif message['destination_ip'] in self.black_list_cache:
            LookupDatasources.alerts(type(self).__name__, message, message['destination_ip'])

    @staticmethod
    def _validate_response(item) -> bool:
        ip = re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", item)
        if ip:
            return True
        else:
            return False

    @cached(cache=TTLCache(maxsize=100000, ttl=60))
    def cache_refresh(self, conf):

        x = requests.get('https://check.torproject.org/torbulkexitlist')
        # TODO logger
        print(f"{datetime.datetime.now()} tor cache refresh!!!!")

        if x.status_code == 200:
            for item in x.iter_lines():
                if Tor._validate_response(item.decode()):
                    if item not in self.black_list_cache:
                        self.black_list_cache.append(item.decode())
                else:
                    print("WARNING! tor response is not in the known format")


class Main:
    '''Main'''

    @abstractmethod
    def get_checks(json):
        # __subclasses__ will found all classes inheriting from Operations
        for check in LookupDatasources.__subclasses__():
            check.check(json)


if __name__ == "__main__":
    Main.get_checks({
        "source_ip": "192.168.74.150",
        "source_port": 35688,
        "destination_ip": "5.45.104.141",
        "destination_port": 80,
        "transport": "TCP"
    })
