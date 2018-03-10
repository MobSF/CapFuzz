import settings
from fuzzer.plugins.utils.oob_validator import (
    OOBValidator
)
from core.utils import (
    HTTPDumper,
)


def response_analyzer(flow, options):
    meta = flow.metadata["fuzz_ssrf"]
    res = flow.response
    oob_validator = OOBValidator(settings.OUT_OF_BAND_SERVER)
    write = options["write"]
    if "url" in meta:
        md5 = meta["md5"]
        # OOB URL SSRF
        if oob_validator.get_status_by_md5(md5):
            write("\n[VULN] SSRF via OOB Hash Method - %s" %
                         (flow.request.url), type="danger")
            http_dumper = HTTPDumper(options["report_file"], False)
            http_dumper.dump("=========================")
            http_dumper.dump("SSRF via OOB Hash Method")
            http_dumper.dump("=========================")
            http_dumper.save_http(flow)
    if "ip" in meta:
        if oob_validator.get_status_by_ip(flow.request.url):
            write("\nVULN] SSRF via OOB IP Method - %s" %
                         (flow.request.url), type="danger")
            http_dumper = HTTPDumper(options["report_file"], True)
            http_dumper.dump("=======================")
            http_dumper.dump("SSRF via OOB IP Method")
            http_dumper.dump("=======================")
            http_dumper.save_http(flow)
    if "count" in meta:
        if oob_validator.get_status_by_count(9):
            write("\n[VULN] SSRF via OOB Request Count Method - %s" %
                         (flow.request.url), type="danger")
            http_dumper = HTTPDumper(options["report_file"], True)
            http_dumper.dump("=================================")
            http_dumper.dump("SSRF via OOB Request Count Method")
            http_dumper.dump("=================================")
            http_dumper.save_http(flow)
