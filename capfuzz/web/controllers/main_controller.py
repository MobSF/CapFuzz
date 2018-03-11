import os
import tornado.web


from capfuzz.web.controllers.flows_controller import (
    DashboardHandler,
    FlowMetaHandler,
)

from capfuzz.web.controllers.fuzz_controller import (
    FuzzHandler,
    FuzzReportHandler,
)

from capfuzz.web.controllers.fuzz_progress import (
    ScanProgress
)

import capfuzz.settings as settings

class Application(tornado.web.Application):

    def __init__(self):
        handlers = [
            (r"/", MainHandler),
            (r"/dashboard", DashboardHandler),
            (r"/dashboard/(.*)", DashboardHandler),
            (r"/flow_meta", FlowMetaHandler),
            (r"/start_fuzz", FuzzHandler),
            (r"/progress", ScanProgress),
            (r"/report/(.*)", FuzzReportHandler),
        ]
        app_settings = {
            "template_path": os.path.join(settings.BASE_PATH, "web/assets/templates/"),
            "static_path": os.path.join(settings.BASE_PATH, "web/assets/static/"),
            "debug": True
        }
        tornado.web.Application.__init__(self, handlers, **app_settings)


class MainHandler(tornado.web.RequestHandler):

    def get(self):
        self.write("ok")
