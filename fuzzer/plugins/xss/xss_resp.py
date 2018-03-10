import settings
from core.utils import (
    HTTPDumper
)
from fuzzer.plugins.utils.helper import (
    get_content_type_lower
)

def response_analyzer(flow, options):
    meta = flow.metadata["fuzz_xss"]
    res = flow.response
    write = options["write"]
    if meta["payload"] in res.content and "text/html" in get_content_type_lower(res):
        write ("\n[VULN] Cross Site Scripting via Query Params - %s" %(flow.request.url), type="danger")
        http_dumper = HTTPDumper(options["report_file"], False)
        http_dumper.dump("====================================")
        http_dumper.dump("Cross Site Scipting via Query Params")
        http_dumper.dump("====================================")
        http_dumper.save_http(flow)
