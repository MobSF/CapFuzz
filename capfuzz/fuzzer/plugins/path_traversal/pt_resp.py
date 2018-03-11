import re

import capfuzz.settings as settings

from capfuzz.core.utils import (
    HTTPDumper
)


def response_analyzer(flow, options): 
    meta = flow.metadata["fuzz_pathtraversal"]
    res = flow.response
    write = options["write"]
    if re.findall(b"root:|nobody:", res.content):
        write ("\n[VULN] Path Traversal via Query Params - %s" %(flow.request.url), type="danger")
        http_dumper = HTTPDumper(options["report_file"], False)
        http_dumper.dump("====================================")
        http_dumper.dump("Path Traversal via Query Params")
        http_dumper.dump("====================================")
        http_dumper.save_http(flow)