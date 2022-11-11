import unittest
from unittest import TestCase
from lookup_datasources.feodo import Feodo


class TestFeodo(TestCase):
    def test__validate_response_OK(self):
        item = {
            "ip_address": "51.178.161.32",
            "port": 4643,
            "status": "online",
            "hostname": "srv-web.ffconsulting.com",
            "as_number": 16276,
            "as_name": "OVH",
            "country": "FR",
            "first_seen": "2021-01-17 07:44:46",
            "last_online": "2022-11-10",
            "malware": "Dridex"
        }

        assert Feodo._validate_response(item)

    def test__validate_response_WRONG(self):
        item = {
            "ip_address": "51.178.161.32",
            "port": 4643,
            "status": "online",
            "hostname": "srv-web.ffconsulting.com",
            "as_number": 16276,
            "as_name": "OVH",
            "country": "FR",
            "first_seen": "2021-01-17 07:44:46",
            "last_online": "2022-11-10",
            "malware": "Dridex",
            "impersonator" : "yes"
        }

        assert Feodo._validate_response(item) == False
#
