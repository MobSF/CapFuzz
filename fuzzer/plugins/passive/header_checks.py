import os
import re

from fuzzer.plugins.utils.helper import (
    is_valid_flow,
)

from fuzzer.plugins.utils.net import (
    get_protocol_domain
)
from fuzzer.plugins.utils.helper import (
    get_filename
)
from core.utils import (
    HTTPDumper
)



import settings


class HeaderChecks:
    """
    Passive Response Header Check
    """

    def __init__(self, fuzzer_options, scan_mode="fast"):
        """
        scan_mode: Fuzzing speed:  slow, fast <str>
        scope: What to Fuzz : url, header, body <list>
        """
        self.scan_mode = scan_mode
        self.script_path = os.path.dirname(os.path.realpath(__file__))
        self.fuzzer_options = fuzzer_options
        self.write = fuzzer_options["write"]
        self.missing_headers = []
        self.report_file = ""

    def header_checker(self, flows):

        """
        Check for Security Headers
        """
        if not any(x in self.fuzzer_options["active_fuzzers"] for x in ["fuzz_header_checks", "all"]):
            return
        self.write("Passive Header Checks")
        project_name = get_filename(self.fuzzer_options["flow_file"])
        self.report_file = os.path.join(settings.LOGS_DIR, project_name)
        for flow in flows:
            if is_valid_flow(flow, self.fuzzer_options):
                self.security_headers(flow)

    def report(self, msg, flow, identifier):
        if identifier not in self.missing_headers:
            self.write("\n[VULN] %s - %s" % (msg, flow.request.url), type="danger")
            http_dumper = HTTPDumper(self.report_file, False)
            http_dumper.dump("====================================")
            http_dumper.dump("%s" % (msg))
            http_dumper.dump("====================================")
            http_dumper.save_http(flow)
            self.missing_headers.append(identifier)

    def security_headers(self, flow):
        request = flow.request
        headers = flow.response.headers
        if "x-xss-protection" not in headers:
            msg = "X-XSS Protection Header is not present."
            self.report(msg, flow, {get_protocol_domain(request.url): "xss"})
        else:
            value = headers["x-xss-protection"]
            if re.findall("(\s)*0(\s)*", value.lower()):
                msg = "X-XSS Protection Header is set to 0. This will disable browsers Anti-XSS Filters."
                self.report(
                    msg, flow, {get_protocol_domain(request.url): "xss"})
        if "strict-transport-security" not in headers and request.url.startswith("https://"):
            msg = "Strict Transport Security Header is not present. This header ensure that all the networking calls made form the browser are strictly (https)."
            self.report(msg, flow, {get_protocol_domain(request.url): "hsts"})
        if "public-key-pins" not in headers and request.url.startswith("https://"):
            msg = "Public Key Pinning Header is not present. This header tells the browser to perform certificate pinning."
            self.report(msg, flow, {get_protocol_domain(request.url): "hkpk"})
        if "x-frame-options" not in headers:
            msg = "X-Frame-Options Header is not present. This header restrict other websites from creating IFRAME(s) of this domain."
            self.report(
                msg, flow, {get_protocol_domain(request.url): "x-frame"})
        if "x-content-type-options" not in headers:
            msg = "X-Content-Type-Options Header is not present. This header prevents browser from MIME-sniffing a response away from the declared content-type."
            self.report(msg, flow, {get_protocol_domain(request.url): "x-cnt"})
        if "content-security-policy" not in headers:
            msg = "Content-Security-Policy Header is not present. This header enables extra security features of the browser and prevents browser based client side attacks."
            self.report(msg, flow, {get_protocol_domain(request.url): "csp"})
        if "access-control-allow-origin" in headers:
            value = headers["access-control-allow-origin"].strip()
            if value == "*":
                msg = "CORS Headers is configured insecurely. Anyone can make CORS request to this endpoint"
                self.report(msg, flow, {request.url: "cors"})
