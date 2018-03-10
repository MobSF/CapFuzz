'''
API Related Checks
1. Rate Limiting
'''
import re
import os
import json
import random

import settings

from fuzzer.plugins.utils.helper import (
    is_valid_flow
)


class ApiFuzz:
    """
    Path Traversal Fuzzer
    """

    def __init__(self, fuzzer_options, scan_mode="fast", scope=["url", "body"]):
        """
        scan_mode: Fuzzing speed:  slow, fast <str>
        scope: What to Fuzz : url, body <list>
        """

        self.scan_mode = scan_mode
        self.scope = scope
        self.script_path = os.path.dirname(os.path.realpath(__file__))
        self.fuzzer_options = fuzzer_options
        self.write = fuzzer_options["write"]
        self.api_fuzz_flows = []
        self.auth_apis = {}

    def api_fuzzer(self, flows):
        """
        API Fuzz Request
        """
        if not any(x in self.fuzzer_options["active_fuzzers"] for x in ["fuzz_api", "all"]):
            return
        self.auth_apis = self.get_api_flows(flows)
        self.write("Generating API Rate Limit Fuzz Flows")
        for api_name, flow in self.auth_apis.items():
            if not is_valid_flow(flow, self.fuzzer_options):
                continue
            self.generate_rate_limit_flws(api_name, flow)
        return self.api_fuzz_flows

    def get_api_flows(self, flows):
        """
        Get Flow for Login, Pin and Register
        """
        apis = {}
        for flow in flows:
            if flow.id == self.fuzzer_options["api_login"]:
                apis["api_login"] = flow
            if flow.id == self.fuzzer_options["api_pin"]:
                apis["api_pin"] = flow
            if flow.id == self.fuzzer_options["api_register"]:
                apis["api_register"] = flow
        return apis

    def generate_rate_limit_flws(self, api_name, flow):
        """Mutuate Post Body"""
        request = flow.request
        for i in range(settings.RATELIMIT_REQ_NOS):
            if request.content:
                meta = {"api_rate_limit": i, "api_name": api_name, "fuzz_type": "body"}
                tmp_flow = flow.copy()
                mutated_content = self.mutate_body(api_name, tmp_flow)
                if mutated_content:
                    tmp_flow.request.content = mutated_content
                    tmp_flow.metadata["fuzz_api"] = meta
                    self.api_fuzz_flows.append(tmp_flow)

    def mutate_body(self, api_name, flow):
        """Mutate Body"""
        mutate = False
        content = flow.request.content
        if api_name == "api_pin":
            if self.has_number(content.decode("utf-8")):
                content = content.replace(b"1", b"2").replace(b"3", b"0").replace(b"4", b"9").replace(
                    b"0", b"5").replace(b"2", b"8").replace(b"5", b"2").replace(b"6", b"1").replace(
                    b"7", b"0").replace(b"8", b"5").replace(b"9", b"3")
                mutate = True
        elif api_name == "api_login" or api_name == "api_register":
            # email in username
            if re.findall(b"%40|@", content):
                content = content.replace(b"%40", b"%40x").replace(b"@", b"@x")
                mutate = True
            # name value pair
            elif b"=" in content and b"&" in content:
                params = content.split(b"&")
                for itm in params:
                    tmp_key_val = itm.split(b"=")
                    if b"user" in tmp_key_val[0] or b"pass" in tmp_key_val[0]:
                        mutate_str = self.shuffle_string(
                            tmp_key_val[1].decode("utf-8"))
                        content = content.replace(
                            b"=" + tmp_key_val[1], b"=" + mutate_str)
                        mutate = True
            # json
            elif b":" in content:
                # try:
                data = json.loads(content)
                vals = self.recursively_parse_json(
                    data, ["user", "pass", "login", "token", "secret"])
                if vals:
                    for val in vals:
                        content = content.replace(val.encode(
                            "utf-8"), self.shuffle_string(val))
                    mutate = True
                # except Exception as exp:
                #    print (exp)
                #    pass
            if not mutate:
                return False
        return content

    def recursively_parse_json(self, input_json, keys):
        """JSON Walking"""
        vals = []
        if type(input_json) is dict and input_json:
            for key in input_json:
                if any(ky in key for ky in keys):
                    vals.append(input_json[key])
                self.recursively_parse_json(input_json[key], keys)

        elif type(input_json) is list and input_json:
            for entity in input_json:
                self.recursively_parse_json(entity, keys)
        return vals

    def has_number(self, strn):
        return any(char.isdigit() for char in strn)

    def shuffle_string(self, string):
        chars = list(string)
        random.shuffle(chars)
        shuf = ''.join(chars)
        return shuf.encode("utf-8")
