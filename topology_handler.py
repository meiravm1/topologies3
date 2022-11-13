import pathlib
import json
from typing import Iterable

from topologies_generation.topology_generator import create_topologies_datasource
from utils import Utils


class TopologyHandler:

    def __init__(self, topologies_datasource: Iterable[dict]):
        self._topologies_datasource = topologies_datasource
        self._lookup_datasources = []

        conf = Utils.load_conf()
        for datasource in conf.keys():
            # load datasource modules of package
            lookup_ds = TopologyHandler.load_modules(f'lookup_datasources.{datasource.lower()}.{datasource}')
            self._lookup_datasources.append(lookup_ds)
            lookup_ds.cache_refresh()

    # dynamic loading of modules
    @staticmethod
    def load_modules(name):
        import importlib
        package = name.split('.')[0]
        module = name.split('.')[1]
        classname = name.split('.')[2]

        module = importlib.import_module(f"{package}.{module}")
        my_class = getattr(module, classname)
        my_instance = my_class()
        return my_instance

    # check whether topology's ip is valid
    def _handle_topology(self, topology: dict):
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


def main():
    topologies_datasource = create_topologies_datasource()
    TopologyHandler(topologies_datasource).handle_topologies()


if __name__ == "__main__":
    main()
