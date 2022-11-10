from datetime import  timedelta
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
