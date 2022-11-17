import requests
from cachetools import cached, TTLCache
import requests
from datetime import datetime, timedelta

import json
import pathlib
from time import sleep
import threading

from utils import Utils

_CACHE_INVALIDATE_TIME = timedelta(seconds=10).seconds


class FeodoCache:

    def __init__(self):
        self.conf = Utils.load_conf()['Feodo']
        self.black_list_cache = []
        self.cache_refresh()
        print(*self.black_list_cache)

    def _cache_refresh(self):
        try:
            x = requests.get(self.conf['url'])
            # TODO logger
            print(f"{datetime.now()} Feodo cache refresh!!!!")

            if x.status_code == 200:
                response = x.json()
                for item in response:
                    if FeodoCache._validate_response(item):
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

    def task1(self):
        print("Task 1 assigned to thread: {}".format(threading.current_thread().name))
        while True:
            self._cache_refresh()
            print(*self.black_list_cache)
            sleep(_CACHE_INVALIDATE_TIME)


    def cache_refresh(self):
        t1 = threading.Thread(target=self.task1, name='t1')
        t1.start()

    def get_cache(self):
        return self.black_list_cache

