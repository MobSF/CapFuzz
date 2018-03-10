"""
Issues in payload substitution. Adding more than one payload
"""
import os

from fuzzer.plugins.utils.helper import (
    is_valid_flow,
)


class XSS:
    """
    XSS Fuzzer
    """

    def __init__(self, fuzzer_options, scan_mode="fast", scope=["url", "body"]):
        """
        scan_mode: Fuzzing speed:  slow, fast <str>
        scope: What to Fuzz : url, header, body <list>
        """
        self.scan_mode = scan_mode
        self.scope = scope
        self.script_path = os.path.dirname(os.path.realpath(__file__))
        self.fuzzer_options = fuzzer_options
        self.write = fuzzer_options["write"]
        self.xss_fuzz_flows = []

    def xss_fuzzer(self, flows):
        """
        XSS Fuzzing Request
        """
        if not any(x in self.fuzzer_options["active_fuzzers"] for x in ["fuzz_xss", "all"]):
            return
        self.write("Generating XSS Fuzz Flows")
        for flow in flows:
            if not is_valid_flow(flow, self.fuzzer_options):
                continue
            if "url" in self.scope and flow.request.query:
                self.query_fuzz(flow)
        return self.xss_fuzz_flows

    def get_xss_payloads(self):
        """
        Get XSS Payloads
        """
        payloads = os.path.join(self.script_path, 'xss.txt')
        try:
            with open(payloads) as file_handler:
                i = 0
                while True:
                    if i == 5 and self.scan_mode == "fast":
                        break
                    yield next(file_handler).replace("\n", "")
                    i += 1
        except (IOError, OSError):
            self.write("Error opening / processing file")
        except StopIteration:
            pass

    def query_fuzz(self, flow):
        """improve """
        for _, value in flow.request.query.items():
            for payload in self.get_xss_payloads():
                tmp_flow = flow.copy()

                tmp_flow.request.path = tmp_flow.request.path.replace(
                    value, value + payload)
                tmp_flow.metadata["fuzz_xss"] = {
                    "fuzzed_value": value, "fuzz_type": "query", "payload": bytes(payload, "utf-8", "ignore")}
                self.xss_fuzz_flows.append(tmp_flow)
