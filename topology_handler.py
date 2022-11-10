import pathlib
import json
from typing import Iterable

from topologies_generation.topology_generator import create_topologies_datasource
from lookup_datasources.lookup_datasources import LookupDatasources



class TopologyHandler:
    def __init__(self, topologies_datasource: Iterable[dict], conf):
        self._topologies_datasource = topologies_datasource
        self._lookup_datasources = []
        for datasource in LookupDatasources.__subclasses__():
            lookup_ds = datasource()
            print(datasource)
            self._lookup_datasources.append(lookup_ds)
            lookup_ds.cache_refresh(conf)

    def _handle_topology(self, topology: dict):
        # pass
        # for datasource in LookupDatasources.__subclasses__():
        #     datasource().check(topology)
        for datasource in self._lookup_datasources:
            datasource.check(topology)

    @staticmethod
    def _validate_topology(topology: dict) -> bool:
        return {"source_ip", "source_port", "destination_ip", "destination_port", "topology_timestamp"} \
            .issubset(topology.keys())

    def handle_topologies(self):
        filtered_topologies = (topology for topology in self._topologies_datasource if
                               self._validate_topology(topology))

        for topology in filtered_topologies:
            print("Handling topology.")
            self._handle_topology(topology)
            print("Done handling topology.")

    @staticmethod
    def load_conf():
        path = pathlib.Path(__file__).resolve().parent

        with (path / "conf.json").open(
                "r") as conf_file:
            conf = "bla"  # json.load(conf_file)

        return conf


def main():
    conf = TopologyHandler.load_conf()
    topologies_datasource = create_topologies_datasource()
    # TODO handle conf parsing
    TopologyHandler(topologies_datasource, conf).handle_topologies()


if __name__ == "__main__":
    main()
