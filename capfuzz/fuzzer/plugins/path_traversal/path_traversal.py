'''
Perform path Traversal checks on Request URI and Body
'''
import os

from capfuzz.fuzzer.plugins.utils.helper import (
    is_valid_flow
)


class PathTraversal:
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
        self.pathtraversal_fuzz_flows = []

    def pathtraversal_fuzzer(self, flows):
        """
        Path Traversal Fuzzing Request
        """
        if not any(x in self.fuzzer_options["active_fuzzers"] for x in ["fuzz_path_traversal", "all"]):
            return
        self.write("Generating Path Traversal Fuzz Flows")
        for flow in flows:
            if not is_valid_flow(flow, self.fuzzer_options):
                continue
            if "url" in self.scope and flow.request.query:
                self.query_fuzz(flow)
        return self.pathtraversal_fuzz_flows

    def get_pt_payloads(self):
        """
        Get Path Traversal Payloads
        """
        payloads = os.path.join(self.script_path, 'path_traversal.txt')
        try:
            with open(payloads) as file_handler:
                i = 0
                while True:
                    if i == 5 and self.scan_mode == "fast":
                        break
                    yield next(file_handler).replace("\n", "").replace("{FILE}", "etc/passwd")
                    i += 1
        except (IOError, OSError):
            self.write("Error opening / processing file")
        except StopIteration:
            pass

    def query_fuzz(self, flow):
        for _, value in flow.request.query.items():
            for payload in self.get_pt_payloads():
                # Fuzz only filename like values
                _, ext = os.path.splitext(value)
                if ext:
                    tmp_flow = flow.copy()
                    tmp_flow.request.path = tmp_flow.request.path.replace(
                        value, payload)
                    tmp_flow.metadata["fuzz_pathtraversal"] = {
                        "fuzzed_value": value, "fuzz_type": "query", "payload": bytes(payload, "utf-8", "ignore")}
                    self.pathtraversal_fuzz_flows.append(tmp_flow)
