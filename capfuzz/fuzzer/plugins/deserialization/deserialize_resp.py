import re
import time

import capfuzz.settings as settings

from capfuzz.core.utils import (
    HTTPDumper
)
from capfuzz.fuzzer.plugins.utils.helper import (
    get_content_type_lower
)

from capfuzz.fuzzer.plugins.utils.oob_validator import (
    OOBValidator
)


def error_rep(flow, lang, write):
    write("\n[VULN] Possible Deserialization Vulnerability via Error Response in %s - %s" %
                 (flow.request.url, lang), type="danger")
    http_dumper = HTTPDumper(options["report_file"], False)
    http_dumper.dump(
        "========================================================================")
    http_dumper.dump(
        "Possible Deserialization Vulnerability via Error Response in %s" % lang)
    http_dumper.dump(
        "========================================================================")
    http_dumper.save_http(flow)


def response_analyzer(flow, options):
    meta = flow.metadata["fuzz_deserialize"]
    res = flow.response
    req = flow.request
    write = options["write"]
    # Error Based
    if re.findall(b"pickle\.|<module>", res.content):
        error_rep(flow, "Python", write)
    elif re.findall(b"incompatible marshal|`load'|control characters|`parse'", res.content):
        error_rep(flow, "Ruby")
    elif re.findall(b"E_NOTICE", res.content):
        error_rep(flow, "PHP", write)
    elif re.findall(b"InvalidClassException|Exception in|at com\.", res.content):
        error_rep(flow, "Java", write)

    # Response Based Validator

    if re.findall(b"root:|nobody:", res.content):
        write ("\n[VULN] Deserialization Vulnerability by Response - %s" %(flow.request.url), type="danger")
        http_dumper = HTTPDumper(options["report_file"], True)
        http_dumper.dump("=========================================")
        http_dumper.dump("Deserialization Vulnerability by Response")
        http_dumper.dump("=========================================")
        http_dumper.save_http(flow)

    # OOB
    oob_validator = OOBValidator(settings.OUT_OF_BAND_SERVER)
    if "md5" in meta:
        md5 = meta["md5"]
        if oob_validator.get_status_by_md5(md5):
            write(
                "\n[VULN] Deserialization Vulnerability via Body by OOB Method - %s" % (flow.request.url), type="danger")
            http_dumper = HTTPDumper(options["report_file"], True)
            http_dumper.dump(
                "===========================================")
            http_dumper.dump(
                "Deserialization Vulnerability by OOB Method")
            http_dumper.dump(
                "===========================================")
            http_dumper.save_http(flow)
    # Blind
    if "blind" in meta:
        tms = meta["tms"]
        ctms = time.time()
        if (ctms - tms) > 8:
            write(
                "\n[VULN] Deserialization Vulnerability via Body by Blind Sleep Method - %s" % (flow.request.url), type="danger")
            http_dumper = HTTPDumper(options["report_file"], False)
            http_dumper.dump(
                "=====================================================")
            http_dumper.dump(
                "Deserialization Vulnerability via Blind Sleep Method ")
            http_dumper.dump(
                "=====================================================")
            http_dumper.save_http(flow)
