import os
import tornado.web

from capfuzz.core.utils import (
    get_flow_file,
    rreplace
)

from capfuzz.web.helpers.flow_tools import (
    load_flows,
    get_flow_meta,
    get_sorted_flows
)

import capfuzz.settings as settings


def slugify(dat):
    return dat.lower().replace(" ", "_").strip()


class DashboardHandler(tornado.web.RequestHandler):

    def get(self, project="default"):
        try:
            if not project:
                project = "default"
            if not get_flow_file(project):
                self.write("[ERROR] Flow File not Found!")
                return
            flows = load_flows(get_flow_file(project))
            sorted_flows = get_sorted_flows(flows)
            exclude_matches = settings.SKIP_URL_MATCH
            exclude_file_ext = settings.SKIP_FILE_EXTS
            exclude_resp_code = settings.EXCLUDE_RESP_CODE
            fuzzers = settings.FUZZERS
            projects = []
            flows_dir = settings.FLOWS_DIR
            for file in os.listdir(flows_dir):
                if file.endswith(".flows"):
                    projects.append(rreplace(file, ".flows", "", 1))
            context = {"title": "Fuzz Dashboard",
                       "project": project,
                       "projects": projects,
                       "exclude_matches": exclude_matches,
                       "exclude_ext": exclude_file_ext.keys(),
                       "exlude_rs_code": exclude_resp_code,
                       "sorted_flows": sorted_flows,
                       "fuzzers": fuzzers,
                       "f_slugify": slugify}
            self.render("dashboard.html", **context)
        except Exception as exp:
            print("[ERROR] ", str(exp))
            self.write({"error": str(exp)})


class FlowMetaHandler(tornado.web.RequestHandler):

    def post(self):
        try:
            flow_id = self.request.headers.get('X-Flow-ID', '')
            flow_file = get_flow_file(self.get_argument("project", default=""))
            if not flow_id or not flow_file:
                self.write({"id": ""})
                return
            flows = load_flows(flow_file)
            for flow in flows:
                if flow.id == flow_id:
                    self.write(get_flow_meta(flow))
        except Exception as exp:
            print("[ERROR] ", str(exp))
            self.write({"error": str(exp)})
