"""
To add header fuzzing
"""
import os
import uuid
import urllib.parse

import capfuzz.settings as settings

from capfuzz.fuzzer.plugins.utils.helper import (
    get_md5,
    is_valid_flow
)
from capfuzz.fuzzer.plugins.utils.net import (
    get_url_match,
    get_ipport_match
)


class SSRF:
    """
    SSRF Fuzzer
    """

    def __init__(self, fuzzer_options, scan_mode="fast", scope=["body"]):
        """
        scan_mode: Fuzzing speed:  slow, fast <str>
        scope: What to Fuzz : body <list>
        """

        self.scan_mode = scan_mode
        self.scope = scope
        self.script_path = os.path.dirname(os.path.realpath(__file__))
        self.fuzzer_options = fuzzer_options
        self.write = fuzzer_options["write"]
        self.ssrf_fuzz_flows = []

    def ssrf_fuzzer(self, flows):
        """
        SSRF Fuzzing Request
        """
        if not any(x in self.fuzzer_options["active_fuzzers"] for x in ["fuzz_ssrf", "all"]):
            return
        self.write("Generating SSRF Fuzz Flows")
        for flow in flows:
            if not is_valid_flow(flow, self.fuzzer_options):
                continue
            # Fuzz Body
            if flow.request.content:
                self.body_fuzz(flow)
            # Fuzz Query
            self.query_fuzz(flow)
        return self.ssrf_fuzz_flows

    def query_fuzz(self, flow):
        for _, value in flow.request.query.items():
            # Fuzz Query if URLS are found
            urls = get_url_match(value)
            if urls:
                for url in urls:
                    tmp_flow = flow.copy()
                    # Replace Query Value
                    md5, payload = self.get_final_payload_url()
                    tmp_flow.request.path = tmp_flow.request.path.replace(
                        url, urllib.parse.quote_plus(payload))
                    tmp_flow.metadata["fuzz_ssrf"] = {"url": True,
                                                      "md5": md5, "fuzz_type": "query", "payload": bytes(payload, "utf-8", "ignore")}
                    self.ssrf_fuzz_flows.append(tmp_flow)
            # Fuzz Query if IP and PORT are found
            ipports = get_ipport_match(value)
            if ipports:
                for ipport in ipports:
                    tmp_flow = flow.copy()
                    # Replace Query Value
                    payload = self.get_final_payload_ipport()
                    # For IP Based SSRF Check
                    tmp_flow.request.path = tmp_flow.request.path.replace(
                        ipport, urllib.parse.quote_plus(payload))
                    tmp_flow.metadata["fuzz_ssrf"] = {
                        "ip": True, "fuzz_type": "query", "payload": bytes(payload, "utf-8", "ignore")}
                    self.ssrf_fuzz_flows.append(tmp_flow)
                    # For Count based SSRF Check
                    for _ in range(10):
                        tt = flow.copy()
                        tt.request.path = tt.request.path.replace(
                            ipport, urllib.parse.quote_plus(payload))
                        tt.metadata["fuzz_ssrf"] = {
                            "count": True, "fuzz_type": "query", "payload": bytes(payload, "utf-8", "ignore")}
                        self.ssrf_fuzz_flows.append(tt)

    def body_fuzz(self, flow):
        req = flow.request
        # Fuzz Body if URLS are found
        urls = get_url_match(req.content.decode("utf-8", "ignore"))
        if urls:
            for url in urls:
                tmp_flow = flow.copy()
                # Replace Body Value
                md5, payload = self.get_final_payload_url()
                tmp_flow.request.content = tmp_flow.request.content.replace(
                    bytes(url, "utf-8", "ignore"), bytes(payload, "utf-8", "ignore"))
                tmp_flow.metadata["fuzz_ssrf"] = {"url": True,
                                                  "md5": md5, "fuzz_type": "body", "payload": bytes(payload, "utf-8", "ignore")}
                self.ssrf_fuzz_flows.append(tmp_flow)
        ipports = get_ipport_match(req.content.decode("utf-8", "ignore"))
        if ipports:
            for ipport in ipports:
                tmp_flow = flow.copy()
                # Replace Body Value
                payload = self.get_final_payload_ipport()
                # For IP Based SSRF Check
                tmp_flow.request.content = tmp_flow.request.content.replace(
                    bytes(ipport, "utf-8", "ignore"), bytes(payload, "utf-8", "ignore"))
                tmp_flow.metadata["fuzz_ssrf"] = {
                    "ip": True, "fuzz_type": "body", "payload": bytes(payload, "utf-8", "ignore")}
                self.ssrf_fuzz_flows.append(tmp_flow)
                # For Count based SSRF Check
                for _ in range(10):
                    tt = flow.copy()
                    tt.request.content = tt.request.content.replace(
                        bytes(ipport, "utf-8", "ignore"), bytes(payload, "utf-8", "ignore"))
                    tt.metadata["fuzz_ssrf"] = {
                        "count": True, "fuzz_type": "body", "payload": bytes(payload, "utf-8", "ignore")}
                    self.ssrf_fuzz_flows.append(tt)

    def get_final_payload_url(self):
        md5 = get_md5(uuid.uuid4().hex.encode('utf-8'))
        oob_url = settings.OUT_OF_BAND_SERVER + "/" + md5
        return md5, oob_url

    def get_final_payload_ipport(self):
        oob_domain = settings.OUT_OF_BAND_SERVER.replace(
            "http://", "").replace("https://", "").replace("/", "")
        return oob_domain
