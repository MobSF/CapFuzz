"""
Fuzzer module init
"""
import re
import sys
import os
import time
import collections
from threading import Thread
import threading
import queue

from mitmproxy import (
    options,
    io
)

from mitmproxy.proxy.server import DummyServer

from capfuzz.core.proxy import ProxyHandler
from capfuzz.fuzzer.plugins.passive.header_checks import HeaderChecks
from capfuzz.fuzzer.plugins.xss import xss
from capfuzz.fuzzer.plugins.xxe import xxe
from capfuzz.fuzzer.plugins.ssrf import ssrf
from capfuzz.fuzzer.plugins.path_traversal import path_traversal
from capfuzz.fuzzer.plugins.deserialization import deserialize
from capfuzz.fuzzer.plugins.api import api

import capfuzz.settings as settings


# Monkeypatch backup
import mitmproxy


def backup(self):
    return
mitmproxy.flow.Flow.backup = backup


class Fuzzer:

    def __init__(self, app, fuzzer_options):
        """
        Init Fuzzers
        """
        self.app = app
        self.flow_file = fuzzer_options["flow_file"]
        self.write = fuzzer_options["write"]
        self.flows = []
        self.fuzz_flows = collections.OrderedDict()
        self.fuzzer_options = fuzzer_options
        self.load_requests()
        self.header_checks = HeaderChecks(fuzzer_options)
        self.xss_fuzz = xss.XSS(fuzzer_options)
        self.xxe_fuzz = xxe.XXE(fuzzer_options)
        self.ssrf_fuzz = ssrf.SSRF(fuzzer_options)
        self.ptr = path_traversal.PathTraversal(fuzzer_options)
        self.dser = deserialize.Deserialization(fuzzer_options)
        self.api = api.ApiFuzz(fuzzer_options)
        self.write("Fuzzer Module Loaded")

    def generate(self):
        """
        Create Fuzz Flows
        Add Flows to Fuzz in order
        Do Passive Checks
        """
        self.write("\nGenerating Fuzz Flows...\n")
        self.fuzz_flows["XSS"] = self.xss_fuzz.xss_fuzzer(self.flows)
        self.fuzz_flows["SSRF"] = self.ssrf_fuzz.ssrf_fuzzer(self.flows)
        self.fuzz_flows[
            "Path Traversal"] = self.ptr.pathtraversal_fuzzer(self.flows)
        self.fuzz_flows[
            "Deserialize"] = self.dser.deserialize_fuzzer(self.flows)
        self.fuzz_flows["XXE"] = self.xxe_fuzz.xxe_fuzzer(self.flows)
        self.fuzz_flows["API"] = self.api.api_fuzzer(self.flows)
        self.write("\nPassive Checks\n")
        self.header_checks.header_checker(self.flows)

    def fuzz(self):
        """
        Invoke Fuzz Requests
        Async
        Always run SSRF Flows before XXE
        """
        reply_threads = []
        self.write("\nRunning Fuzz Flows...\n")
        for fuzz, fuzz_list in self.fuzz_flows.items():
            if fuzz_list:
                self.write("Running %s Fuzzer" % fuzz)
                self.write("[INFO] Total %s Fuzz flows %d" %
                           (fuzz, len(fuzz_list)))
                i = 0
                for i, flow in enumerate(fuzz_list):
                    print("Fuzzing %d/%d" %
                          (i + 1, len(fuzz_list)), end="\r")
                    flow.metadata["flow_file"] = self.flow_file
                    reply_threads.append(self.app.replay_request(flow))
                print("")
        self.write("\nAll Fuzz requests sent!\n")
        trd = Thread(target=self.check_scan_state, args=(reply_threads,))
        trd.setDaemon(True)
        trd.start()

    def load_requests(self):
        try:
            self.write("Loading Requests")
            with open(self.flow_file, "rb") as f:
                self.flows.extend(io.FlowReader(f).stream())
        except Exception as exp:
            self.write("[ERROR] ", str(exp))

    def stop_response_analyzer(self):
        # Kill the response analyzer thread
        kill_flow = self.flows[0].copy()
        kill_flow.metadata["flow_file"] = self.flow_file
        kill_flow.metadata["kill_flow"] = True
        self.app.replay_request(kill_flow, block=False)

    def check_scan_state(self, reply_threads):
        # Check if the last thread in the list has elapsed 25sec
        if reply_threads:
            thread = reply_threads[-1]
            while True:
                thread_run_sec = int(re.findall(r'\d+', thread._threadinfo())[0])
                if thread_run_sec > settings.FUZZ_TIMEOUT:
                    self.write("Fuzzing Completed!")
                    self.stop_response_analyzer()
                    return


def run_fuzzer(fuzzer_options):
    """Run Fuzzer"""
    rsp_server_opts = options.Options()
    rsp_server_opts.server = False
    if settings.UPSTREAM_PROXY:
        rsp_server_opts.mode = settings.UPSTREAM_PROXY_CONF
        rsp_server_opts.ssl_insecure = settings.UPSTREAM_PROXY_SSL_INSECURE
    reponse_server = ProxyHandler(
        rsp_server_opts, fuzzer_options["mode"], None)
    reponse_server.server = DummyServer()
    fuzzer = Fuzzer(reponse_server, fuzzer_options)
    fuzzer.generate()
    fuzzer.fuzz()
    reponse_server.run()
