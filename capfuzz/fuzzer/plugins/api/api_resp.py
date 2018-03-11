import capfuzz.settings as settings
from capfuzz.core.utils import (
    HTTPDumper
)
from capfuzz.fuzzer.plugins.utils.helper import (
    get_content_type_lower
)
api_reason = {}
api_code = {}

def response_analyzer(flow, options):
    """
    Totally Async
    Reimplement
    print (api_req)
    """

    global api_reason, api_code
    meta = flow.metadata["fuzz_api"]
    res = flow.response
    write = options["write"]
    api_req = meta["api_rate_limit"]
    api_name = meta["api_name"]
    #Why 5 we are not sure whats the order
    if api_req in [1, 2, 3, 4, 5]:
        api_reason[api_name] = flow.response.reason
        api_code[api_name] = flow.response.status_code
    if api_req == settings.RATELIMIT_REQ_NOS - 1:
        if api_reason[api_name] == flow.response.reason or api_code[api_name] == flow.response.status_code:
            write("\n[VULN] API may not be rate limited (Requests %s) - %s" %
                  (str(api_req + 1), flow.request.url), type="danger")
            http_dumper = HTTPDumper(options["report_file"], False)
            http_dumper.dump("===========================")
            http_dumper.dump("API may not be rate limited")
            http_dumper.dump("===========================")
            http_dumper.save_http(flow)

