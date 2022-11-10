import pathlib
import json
class Utils:
    @staticmethod
    def eprint(*args, **kwargs):
        print(*args)

    @staticmethod
    def load_conf():
        path = pathlib.Path(__file__).resolve().parent

        with (path / "conf.json").open(
                "r") as conf_file:
            conf = json.load(conf_file)

        return conf