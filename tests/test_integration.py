import copy
import json
import unittest

from scripts.integration import compare_host_configuration


def state():
    return {"routes": json.dumps([{"dst": "default", "gateway": "192.0.2.1", "dev": "eth0"}]),
            "forwarding": "1\n", "firewall": json.dumps({"nftables": [
                {"rule": {"family": "ip", "table": "filter", "chain": "OUTPUT", "expr": [
                    {"counter": {"packets": 645, "bytes": 264494}}, {"accept": None}]}}]})}


class HostConfigurationTests(unittest.TestCase):
    def test_packet_counters_can_advance_without_configuration_change(self):
        before, after = state(), state()
        rules = json.loads(after["firewall"])
        rules["nftables"][0]["rule"]["expr"][0]["counter"].update(packets=921, bytes=328574)
        after["firewall"] = json.dumps(rules)
        result = compare_host_configuration(before, after)
        self.assertTrue(result["unchanged"])
        self.assertFalse(result["raw_state_equal"])
        self.assertNotEqual(before["firewall"], after["firewall"])

    def test_firewall_verdict_change_is_not_ignored(self):
        before, after = state(), state()
        after["firewall"] = after["firewall"].replace('"accept"', '"drop"')
        self.assertFalse(compare_host_configuration(before, after)["unchanged"])

    def test_route_or_forwarding_changes_are_not_ignored(self):
        before = state()
        for key, value in (("routes", before["routes"].replace("192.0.2.1", "192.0.2.2")), ("forwarding", "0\n")):
            with self.subTest(key=key):
                after = copy.deepcopy(before)
                after[key] = value
                self.assertFalse(compare_host_configuration(before, after)["unchanged"])

    def test_named_counter_configuration_is_preserved(self):
        before, after = state(), state()
        first = {"nftables": [{"counter": {"name": "first", "table": "filter", "packets": 1, "bytes": 2}}]}
        second = copy.deepcopy(first)
        second["nftables"][0]["counter"].update(packets=3, bytes=4)
        before["firewall"], after["firewall"] = json.dumps(first), json.dumps(second)
        self.assertTrue(compare_host_configuration(before, after)["unchanged"])
        second["nftables"][0]["counter"]["name"] = "changed"
        after["firewall"] = json.dumps(second)
        self.assertFalse(compare_host_configuration(before, after)["unchanged"])

    def test_rule_order_and_comment_changes_are_preserved(self):
        before, after = state(), state()
        first = {"nftables": [{"rule": {"comment": "counter packets 1 bytes 2"}}, {"rule": {"comment": "second"}}]}
        second = {"nftables": list(reversed(first["nftables"]))}
        before["firewall"], after["firewall"] = json.dumps(first), json.dumps(second)
        self.assertFalse(compare_host_configuration(before, after)["unchanged"])
        second = copy.deepcopy(first)
        second["nftables"][0]["rule"]["comment"] = "counter packets 3 bytes 4"
        after["firewall"] = json.dumps(second)
        self.assertFalse(compare_host_configuration(before, after)["unchanged"])

    def test_missing_or_invalid_observations_cannot_establish_unchanged_config(self):
        for invalid in ({}, {**state(), "firewall": "not JSON"}, {**state(), "routes": "{}"}):
            with self.assertRaises((KeyError, ValueError)):
                compare_host_configuration(state(), invalid)
