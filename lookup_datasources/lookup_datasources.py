from abc import ABC, abstractmethod
from alert_sinks import AlertSinks
import requests
import datetime
import json
from cachetools import cached, TTLCache

class LookupDatasources(ABC):
    '''check'''

    @abstractmethod
    def check(self):
        pass

    def alerts(json, ip):
        for sink in AlertSinks.__subclasses__():
            sink.alert(json, ip)


class Feodo(LookupDatasources):
    '''get malicious ips from fedor'''
    black_list_cache = []

    #TODO handle maxsize
    @cached(cache=TTLCache(maxsize=100000,ttl=60))
    def cache_refresh(self):
        print("refreshing cache..")
        x = requests.get('https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json')
        # TODO logger
        print(f"{datetime.datetime.now()} feodo cache refresh")

        if x.status_code == 200:
            response = x.json()
            for item in response:
                if Feodo._validate_response(item):
                    if item['ip_address'] not in self.black_list_cache:
                        self.black_list_cache += item['ip_address']
                else:
                    print("WARNING! feodo response is not in the known format")

    @staticmethod
    def _validate_reponse(feodo_response: dict) -> bool:
        with "feodo_template.json".open("r") as feodo_template_file:
            feodo_template = json.load(feodo_template_file)
        return feodo_template.keys() \
            .issubset(feodo_response.keys())

    def check(self, json):

        if json['source_ip'] in self.black_list_cache:
            LookupDatasources.alerts(json, json['source_ip'])
        elif json['source_ip'] in self.black_list_cache:
            LookupDatasources.alerts(json, json['destination_ip'])

        print(f"Feodo saw is {json['source_ip']}")

    class Tor(LookupDatasources):
        '''get malicious ips from tor'''

        cache = dict()

        def check(json):
            print(f"Tor saw {json['source_ip']}")
            black_list = ["33.3.118.172", "152.234.105.93"]

            if json['source_ip'] in black_list:
                LookupDatasources.alerts(json, json['source_ip'])
            elif json['source_ip'] in black_list:
                LookupDatasources.alerts(json, json['destination_ip'])


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
