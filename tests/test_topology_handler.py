from unittest import TestCase
from topology_handler import TopologyHandler


class TestTopologyHandler(TestCase):

    def test__handle_topology(self):
        topologies_datasource = [{
            "source_ip": "192.168.74.150",
            "source_port": 35688,
            "destination_ip": "5.45.104.18",
            "destination_port": 80,
            "transport": "TCP"
        }]
        t = TopologyHandler(topologies_datasource)

        for datasource in t._lookup_datasources:
            assert datasource.check(topologies_datasource[0]) == True
