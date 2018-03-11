import os
import sys

import capfuzz.settings as settings

from mitmproxy import (
    http
)

from capfuzz.fuzzer.plugins.utils.helper import (
    get_filename
)

from capfuzz.fuzzer.plugins.xss import xss_resp
from capfuzz.fuzzer.plugins.xxe import xxe_resp
from capfuzz.fuzzer.plugins.ssrf import ssrf_resp
from capfuzz.fuzzer.plugins.path_traversal import pt_resp
from capfuzz.fuzzer.plugins.deserialization import deserialize_resp
from capfuzz.fuzzer.plugins.api import api_resp
from capfuzz.web.controllers.fuzz_progress import ScanProgress


class FuzzResponseAnalyzer:

    def response(self, flow: http.HTTPFlow) -> None:
        flow_file = flow.metadata["flow_file"]
        project_name = get_filename(flow_file)
        options = {}
        options["report_file"] = os.path.join(settings.LOGS_DIR, project_name)
        options["write"] = ScanProgress.write
        if "fuzz_xss" in flow.metadata:
            xss_resp.response_analyzer(flow, options)
        if "fuzz_pathtraversal" in flow.metadata:
            pt_resp.response_analyzer(flow, options)
        if "fuzz_xxe" in flow.metadata:
            xxe_resp.response_analyzer(flow, options)
        if "fuzz_ssrf" in flow.metadata:
            ssrf_resp.response_analyzer(flow, options)
        if "fuzz_deserialize" in flow.metadata:
            deserialize_resp.response_analyzer(flow, options)
        if "fuzz_api" in flow.metadata:
            api_resp.response_analyzer(flow, options)
        if "kill_flow" in flow.metadata:
            sys.exit(0)
