"""
Main
"""
import os
import sys
import signal
import argparse
import tornado.ioloop

from argparse import RawTextHelpFormatter

from mitmproxy import (
    options,
    exceptions
)

from mitmproxy.proxy.config import ProxyConfig
from mitmproxy.proxy.server import ProxyServer

from capfuzz.fuzzer.fuzz_engine import run_fuzzer

from capfuzz.core.proxy import (
    ProxyHandler
)
from capfuzz.core.utils import (
    create_dir,
    get_flow_file
)
from capfuzz.web.controllers.fuzz_progress import ScanProgress
from capfuzz.web.controllers.main_controller import Application
import capfuzz.settings as settings


class CapFuzz:

    def __init__(self):
        self.app_server = None
        self.web_server = None
        self.iloop = tornado.ioloop.IOLoop()
        self.mitm_proxy_opts = options.Options()

    def stop_capfuzz(self, *args, **kwargs):
        try:
            self.app_server.shutdown()
        except:
            pass
        try:
            self.iloop.add_callback(self.ioloop.stop)
            self.iloop.current().stop()
        except:
            pass
        sys.exit(0)

    def start_proxy(self, port, mode, flow_file_name):
        """
        Start Proxy
        Capture / Intercept
        """
        self.mitm_proxy_opts.keepserving = True
        self.mitm_proxy_opts.listen_port = port
        self.mitm_proxy_opts.cadir = settings.CA_DIR
        if settings.UPSTREAM_PROXY:
            self.mitm_proxy_opts.mode = settings.UPSTREAM_PROXY_CONF
            self.mitm_proxy_opts.ssl_insecure = settings.UPSTREAM_PROXY_SSL_INSECURE
        self.app_server = ProxyHandler(
            self.mitm_proxy_opts, mode, flow_file_name)
        self.app_server.server = ProxyServer(ProxyConfig(self.mitm_proxy_opts))
        self.app_server.run()

    def run_fuzz_server(self, port):
        """
        Start Fuzz Server
        Configure and Fuzz
        """
        print("Running Web GUI at *:%d" % port)
        self.web_server = Application()
        self.web_server.listen(port)
        self.iloop.current().start()

    def run_fuzz_cmdline(self, mode, project):
        if project:
            flow_file = get_flow_file(project)
            if not flow_file:
                print("[ERROR] Flow File not found")
                return
        else:
            flow_file = get_flow_file("default")
        fuzz_options = {}
        fuzz_options["mode"] = mode
        fuzz_options["include_scope"] = []
        fuzz_options["exclude_scope"] = []
        fuzz_options["exclude_url_match"] = "on"
        fuzz_options["exclude_extensions"] = "on"
        fuzz_options["exclude_response_code"] = "on"
        fuzz_options["active_fuzzers"] = ["all"]
        fuzz_options["flow_file"] = flow_file
        fuzz_options["api_login"] = ""
        fuzz_options["api_pin"] = ""
        fuzz_options["api_register"] = ""
        fuzz_options["write"] = ScanProgress.write
        run_fuzzer(fuzz_options)


def main():

    PARSER = argparse.ArgumentParser(formatter_class=RawTextHelpFormatter)
    PARSER.add_argument(
        "-m", "--mode", help="Supported modes\n1. capture: Capture requests.\n2. fuzz: Run Fuzzing Server.\n3. runfuzz: Fuzz on captured requests with default configuration.\n4. intercept: Intercept and tamper the flow in live.")
    PARSER.add_argument("-p", "--port", help="Proxy Port",
                        default=settings.PORT, type=int)
    PARSER.add_argument("-n", "--name", help="Project Name",
                        default="default")
    ARGS = PARSER.parse_args()
    if ARGS.mode:
        try:
            capfuzz = CapFuzz()
            signal.signal(signal.SIGTERM, capfuzz.stop_capfuzz)
            signal.signal(signal.SIGINT, capfuzz.stop_capfuzz)
            create_dir([settings.FLOWS_DIR, settings.LOGS_DIR])
            if ARGS.mode == "capture" or ARGS.mode == "intercept":
                capfuzz.start_proxy(ARGS.port, ARGS.mode, ARGS.name)

            elif ARGS.mode == "fuzz":
                capfuzz.run_fuzz_server(ARGS.port)

            elif ARGS.mode == "runfuzz":
                capfuzz.run_fuzz_cmdline(ARGS.mode, ARGS.name)

            else:
                PARSER.print_help()
        except (KeyboardInterrupt, RuntimeError) as e:
            pass
        except exceptions.ServerException as exp:
            print(exp)
            sys.exit(0)
        except Exception as exp:
            print("[ERROR] " + str(exp))
    else:
        PARSER.print_help()

if __name__ == "__main__":
    main()
