import unittest
from unittest import TestCase
from lookup_datasources.tor import Tor


class TestFeodo(TestCase):
    def test__validate_response_OK(self):
        item = "51.178.161.32"

        assert Tor._validate_response(item)

    def test__validate_response_WRONG(self):
        item = "51.178.16132"

        assert Tor._validate_response(item) == False

    def test_check_OK(self):
        item = {
            "source_ip": "192.168.74.150",
            "source_port": 35688,
            "destination_ip": "5.45.104.18",
            "destination_port": 80,
            "transport": "TCP"
        }
        t = Tor()
        assert t.check(item) == True

    def test_check_WRONG(self):
        item = {
            "source_ip": "192.168.74.150",
            "source_port": 35688,
            "destination_ip": "5.45.104.141",
            "destination_port": 80,
            "transport": "TCP"
        }
        t = Tor()
        assert t.check(item) == False
#
