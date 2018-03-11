"""
to do xxe via file upload
XXE will make use of oob validator for a generic payload not required
"""
import os
import uuid
import urllib.parse

import capfuzz.settings as settings

from capfuzz.fuzzer.plugins.utils.helper import (
    get_md5,
    is_json_content_type,
    is_xml_content_type,
    is_valid_flow,
    get_content_type_lower,
)


class XXE:
    """
    XXE Fuzzer
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
        self.xxe_fuzz_flows = []

    def xxe_fuzzer(self, flows):
        """
        XXE Fuzzing Request
        """
        if not any(x in self.fuzzer_options["active_fuzzers"] for x in ["fuzz_xxe", "all"]):
            return
        self.write("Generating XXE Fuzz Flows")
        for flow in flows:
            if not is_valid_flow(flow, self.fuzzer_options):
                continue
            # Fuzz Query
            self.query_fuzz(flow)
            # Fuzz Body
            if flow.request.content or is_xml_content_type(get_content_type_lower(flow.request)):
                self.body_fuzz(flow)
        return self.xxe_fuzz_flows

    def get_xxe_payloads(self):
        """
        Get XXE Payloads
        """
        payloads = os.path.join(self.script_path, 'xxe.txt')
        try:
            with open(payloads) as file_handler:
                while True:
                    yield next(file_handler).replace("\n", "").replace("{{validate_str}}", settings.VALIDATE_STRING)
        except (IOError, OSError):
            self.write("Error opening / processing file")
        except StopIteration:
            pass

    def query_fuzz(self, flow):
        for _, value in flow.request.query.items():
            for payload in self.get_xxe_payloads():
                # Fuzz Query if XML Like values are present
                if ("<" in value and ">" in value) or ("%3C" in value and "%3E" in value):
                    tmp_flow = flow.copy()
                    # Replace Query Value
                    xxe_md5, payload = self.get_final_payload(payload)
                    tmp_flow.request.path = tmp_flow.request.path.replace(
                        value, urllib.parse.quote_plus(payload))
                    tmp_flow.metadata["fuzz_xxe"] = {
                        "md5": xxe_md5, "fuzz_type": "query", "payload": bytes(payload, "utf-8", "ignore")}
                    self.xxe_fuzz_flows.append(tmp_flow)

                    # Preppend to Query Value
                    xxe_md5, payload = self.get_final_payload(payload)
                    tmp_flow2 = flow.copy()
                    tmp_flow2.request.path = tmp_flow2.request.path.replace(
                        value, urllib.parse.quote_plus(payload) + value)
                    tmp_flow2.metadata["fuzz_xxe"] = {
                        "md5": xxe_md5, "fuzz_type": "query", "payload": bytes(payload, "utf-8", "ignore")}
                    self.xxe_fuzz_flows.append(tmp_flow2)

    def body_fuzz(self, flow):
        req = flow.request
        for payload in self.get_xxe_payloads():
            tmp_flow = flow.copy()
            if is_xml_content_type(get_content_type_lower(req)):
                """
                Proper XML Request
                """
                # Replace Body
                xxe_md5, payload = self.get_final_payload(payload)
                tmp_flow.request.content = bytes(payload, "utf-8", "ignore")
                tmp_flow.metadata["fuzz_xxe"] = {
                    "md5": xxe_md5, "fuzz_type": "body", "payload": bytes(payload, "utf-8", "ignore")}
                self.xxe_fuzz_flows.append(tmp_flow)

                # Append Body
                xxe_md5, payload = self.get_final_payload(payload)
                tmp_flow2 = flow.copy()
                tmp_flow2.request.content = tmp_flow2.request.content + \
                    bytes(payload, "utf-8", "ignore")
                tmp_flow2.metadata["fuzz_xxe"] = {
                    "md5": xxe_md5, "fuzz_type": "body", "payload": bytes(payload, "utf-8", "ignore")}
                self.xxe_fuzz_flows.append(tmp_flow2)

            elif req.content and self.scan_mode == "slow" and is_json_content_type(get_content_type_lower(req)):
                """
                Fuzz by replacing JSON body and altering Content-Type
                """
                xxe_md5, payload = self.get_final_payload(payload)
                tmp_flow.request.content = bytes(payload, "utf-8", "ignore")
                tmp_flow.request.headers["content-type"] = "application/xml"
                tmp_flow.metadata["fuzz_xxe"] = {
                    "md5": xxe_md5, "fuzz_type": "body", "payload": bytes(payload, "utf-8", "ignore")}
                self.xxe_fuzz_flows.append(tmp_flow)

    def get_final_payload(self, payload):
        xxe_md5 = get_md5(uuid.uuid4().hex.encode('utf-8'))
        oob_url = settings.OUT_OF_BAND_SERVER + "/" + xxe_md5
        payload = payload.replace("[CLOUD_SERVER_URL]", oob_url)
        return xxe_md5, payload
