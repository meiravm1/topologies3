from unittest import TestCase
from utils import Utils


class TestUtils(TestCase):
    def test_load_conf(self):
        assert type(Utils.load_conf()) == dict
