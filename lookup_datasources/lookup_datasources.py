
from abc import ABC, abstractmethod
from alert_sinks import AlertSinks


class LookupDatasources(ABC):
    """ check whether ip in message in not malicious"""

    @abstractmethod
    def check(self, message):
        pass

    @staticmethod
    @abstractmethod
    def get_source_desc():
        pass

    @staticmethod
    def alerts(source, message, ip):
        for sink in AlertSinks.__subclasses__():
            sink().alert(source, message, ip)
