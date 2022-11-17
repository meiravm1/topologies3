from abc import ABC, abstractmethod
from utils import Utils


class AlertSinks(ABC):
    """check"""

    @abstractmethod
    def alert(self, source, json, ip):
        pass

    @staticmethod
    @abstractmethod
    def alert_message(source, output_type, json, ip):
        pass


class DBSink(AlertSinks):
    """alert to db"""
    def __init__(self):
        conn = "jdbc://"

    def alert(self, source, json, ip):
        DBSink.alert_message(source, 'db', json, ip)

    @staticmethod
    def alert_message(source, output_type, json, ip):
        Utils.eprint(f"alert to {output_type} , malicious ip detected {ip} ({source}) at packet {json}")


class KafkaSink(AlertSinks):
    """ alert to kafka """
    def __init__(self):
        conn = "9092://"

    def alert(self, source, json, ip):
        KafkaSink.alert_message(source, 'kafka', json, ip)

    @staticmethod
    def alert_message(source, output_type, json, ip):
        Utils.eprint(f"alert to {output_type} , malicious ip detected {ip} ({source}) at packet {json}")
