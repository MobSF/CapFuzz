import os

import capfuzz.settings as settings
from capfuzz.core.utils import (
    HTTPDumper
)

from capfuzz.fuzzer.plugins.utils.oob_validator import (
    OOBValidator
)


def get_xxe_exceptions():
    """
    Get XXE Parser Exceptions
    """
    payloads = os.path.join(os.path.dirname(
        os.path.realpath(__file__)), 'exceptions.txt')
    try:
        with open(payloads) as file_handler:
            while True:
                yield next(file_handler).replace("\n", "")
    except (IOError, OSError):
        print("Error opening / processing file")
    except StopIteration:
        pass


def response_analyzer(flow, options):
    meta = flow.metadata["fuzz_xxe"]
    res = flow.response
    md5 = meta["md5"]
    write = options["write"]
    # Reflection XXE
    if bytes(settings.VALIDATE_STRING, "utf-8") in res.content:
        write("\n[VULN] Generic XML External Entity (XXE) via Request Body - %s" %
                     (flow.request.url), type="danger")
        http_dumper = HTTPDumper(options["report_file"], False)
        http_dumper.dump(
            "====================================================")
        http_dumper.dump(
            "Generic XML External Entity (XXE) Payload Reflection")
        http_dumper.dump(
            "====================================================")
        http_dumper.save_http(flow)

    # OOB XXE
    oob_validator = OOBValidator(settings.OUT_OF_BAND_SERVER)
    if oob_validator.get_status_by_md5(md5):
        write("\n[VULN] XML External Entity (XXE) via OOB Hash Method- %s" %
                     (flow.request.url), type="danger")
        http_dumper = HTTPDumper(options["report_file"], True)
        http_dumper.dump("==============================================")
        http_dumper.dump("XML External Entity (XXE) via OOB Hash Method")
        http_dumper.dump("==============================================")
        http_dumper.save_http(flow)

    # Error Based
    if any(bytes(exp, "utf-8") in res.content for exp in get_xxe_exceptions()):
        write("\n[VULN] Possible XML External Entity (XXE) via XML exception- %s" %
                     (flow.request.url), type="danger")
        http_dumper = HTTPDumper(options["report_file"], False)
        http_dumper.dump(
            "====================================================")
        http_dumper.dump(
            "Possible XML External Entity (XXE) via XML exception")
        http_dumper.dump(
            "====================================================")
        http_dumper.save_http(flow)
