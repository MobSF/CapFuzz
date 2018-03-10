from mitmproxy import (
    master,
    options,
    addons
)

from mitmproxy.addons import (
    keepserving,
    termlog,
    termstatus,
    dumper
)


from core.capture import Capture
from core.interceptor import Interceptor
from fuzzer.response_analyzer import FuzzResponseAnalyzer

import settings

class ProxyHandler(master.Master):

    def __init__(
        self,
        options: options.Options,
        mode,
        flow_name,
    ) -> None:
        super().__init__(options)
        self.addons.add(termlog.TermLog())
        self.addons.add(termstatus.TermStatus())
        self.addons.add(keepserving.KeepServing())
        self.addons.add(*addons.default_addons())
        if mode == "fuzz":
            self.addons.add(dumper.Dumper())
            self.addons.add(FuzzResponseAnalyzer())
        if mode == "runfuzz":
            self.addons.add(FuzzResponseAnalyzer())
        if mode == "capture":
            self.addons.add(Capture(flow_name))
        if mode == "intercept":
            self.addons.add(Interceptor())
