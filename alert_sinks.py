from abc import ABC,abstractmethod
from utils import Utils
class AlertSinks(ABC):

    '''check'''
    @abstractmethod
    def check(self):
        pass

    def alert_message(source,output_type,json,ip):
        Utils.eprint(f"alert to {output_type} , malicious ip detected {ip} ({source}) at packet {json}")

class DBSink(AlertSinks):
    '''get malicious ips from tor'''
    def alert(source,json,ip):
        AlertSinks.alert_message(source,'db',json,ip)

class KafkaSink(AlertSinks):
    '''get malicious ips from fedor'''
    def alert(source,json,ip):
        AlertSinks.alert_message(source,'kafka',json,ip)

class Main:
    '''Main'''
    @abstractmethod
    def get_alerts(json):
        # __subclasses__ will found all classes inheriting from Operations
        for sink in AlertSinks.__subclasses__():
            sink.alert(json)


if __name__ == "__main__":
    Main.get_alerts({
    "source_ip": "192.168.74.150",
    "source_port": 35688,
    "destination_ip": "5.45.104.141",
    "destination_port": 80,
    "transport": "TCP"
  })