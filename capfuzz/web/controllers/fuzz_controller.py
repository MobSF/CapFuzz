import tornado.web
from threading import Thread

from capfuzz.fuzzer.fuzz_engine import run_fuzzer

from capfuzz.core.utils import (
    get_flow_file,
    get_report_file
)

from capfuzz.web.controllers.fuzz_progress import ScanProgress


class FuzzHandler(tornado.web.RequestHandler):

    def post(self):
        operation = self.request.headers.get('X-Operation', '')
        flow_file = get_flow_file(self.get_argument("project", default=""))
        if not operation == "Start-Fuzz" or not flow_file:
            self.write({"error": "Operation or Project not found!"})
            return
        options = {}
        options["mode"] = "fuzz"
        options["include_scope"] = self.get_arguments("include_scope[]")
        options["exclude_scope"] = self.get_arguments("exclude_scope[]")
        options["active_fuzzers"] = self.get_arguments("active_fuzzers[]")
        options["exclude_url_match"] = self.get_argument(
            "exclude_url_match", default="on",)
        options["exclude_extensions"] = self.get_argument(
            "exclude_extensions", default="on",)
        options["exclude_response_code"] = self.get_argument(
            "exclude_response_code", default="on",)
        options["flow_file"] = flow_file
        options["write"] = ScanProgress.write
        options["api_login"] = self.get_argument("api_login")
        options["api_pin"] = self.get_argument("api_pin")
        options["api_register"] = self.get_argument("api_register")
        self.write({"status": "ok"})

        trd = Thread(target=run_fuzzer, args=(options,))
        trd.setDaemon(True)
        trd.start()

class FuzzReportHandler(tornado.web.RequestHandler):

    def get(self, project="default"):
        try:
            report = ""
            if not project:
                project = "default"
            if not get_report_file(project):
                self.write("[ERROR] Report not Found!")
                return
            with open(get_report_file(project), "r") as flip:
                report = flip.read()
            context = {"title": "Fuzz Report",
                       "project": project,
                       "report": report.encode("utf-8", "ignore"),
                      }
            self.render("report.html", **context)
        except Exception as exp:
            print("[ERROR]", str(exp))
            self.write({"error": str(exp)})

