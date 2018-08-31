"""
Capture Web Traffic
"""
import os
import sys
import errno
from mitmproxy import (
    io,
    flow,
    http,
    websocket
)
import capfuzz.settings as settings
from capfuzz.core.utils import (
    get_flow_file
)


class Capture:
    """
    Web Traffic Capture
    DISPLAY_OUT - False: logs to file
    DISPLAY_OUT - True: logs to file and print to stdout
    """

    def __init__(self, flow_name):
        print("Capture Module Loaded")
        if not get_flow_file(flow_name, True):
            print("[ERROR] Invalid Project Name")
            sys.exit(0)
        self.flow_file = get_flow_file(flow_name, True)
        self.http_dump_file = get_flow_file(flow_name, True) + ".txt"
        self.make_dir([self.flow_file, self.http_dump_file])
        self.display_out = settings.DISPLAY_OUT
        if self.flow_file:
            self.f = open(self.flow_file, "wb")  # type: typing.IO[bytes]
            self.w = io.FlowWriter(self.f)
        if self.http_dump_file:
            self.http_f = open(self.http_dump_file, "w")

    def make_dir(self, files):
        """
        make dirs if not exists
        """
        for filename in files:
            if not os.path.exists(os.path.dirname(filename)):
                try:
                    os.makedirs(os.path.dirname(filename))
                except OSError as exc:  # Guard against race condition
                    if exc.errno != errno.EEXIST:
                        raise

    def save_http(self, flow):
        """Save Given Request and Response"""
        self.http_f.write("========\n")
        self.http_f.write("درخواست\n")
        self.http_f.write("========\n")
        req = flow.request
        res = flow.response
        self.http_f.write("%s %s %s\n" %
                          (req.method, req.url, req.http_version))
        for key, val in req.headers.items():
            self.http_f.write("%s: %s\n" % (key, val))
        if req.content:
            self.http_f.write("\n\n%s\n" %
                              (req.content))

        self.http_f.write("=========\n")
        self.http_f.write("پاسخ\n")
        self.http_f.write("=========\n")
        self.http_f.write("%s %s %s\n" %
                          (res.http_version, res.status_code, res.reason))
        for key, val in res.headers.items():
            self.http_f.write("%s: %s\n" % (key, val))
        if res.content:
            self.http_f.write("\n\n%s\n" %
                              (res.content))

    def done(self):
        if self.f:
            self.f.close()
        if self.http_f:
            self.http_f.close()

    def request(self, flow: http.HTTPFlow) -> None:
        """Kill Proxy on Kll Request"""
        for key, val in flow.request.headers.items():
            if "capfuzz" in key and val == "kill":
                print("[INFO] CapFuzz recieved Kill Request!")
                sys.exit(0)

    def response(self, flow: http.HTTPFlow) -> None:
        if self.w:
            self.w.add(flow)
        if self.http_f:
            self.save_http(flow)

"""
    def websocket_handshake(self, flow: websocket.WebSocketFlow) -> None:

        self.http_dumper.dump("\n===================")
        self.http_dumper.dump("WebScoket Handshake")
        self.http_dumper.dump("===================")
        self.http_dumper.dump("Request ID: %s" % flow.id)
        self.http_dumper.dump("Client Address: %s:%s" %
                  (flow.client_conn.address[0], flow.client_conn.address[1]))
        self.http_dumper.dump("Client TLS version: %s" % flow.client_conn.tls_version)
        self.http_dumper.dump("Server Address: %s:%s" %
                  (flow.server_conn.address[0], flow.server_conn.address[1]))
        self.http_dumper.dump("Server IP: %s:%s" % (flow.server_conn.ip_address[
                  0], flow.server_conn.ip_address[1]))
        self.http_dumper.dump("Server Source Address: %s:%s" % (
            flow.server_conn.source_address[0], flow.server_conn.source_address[1]))

    def websocket_start(self, flow: websocket.WebSocketFlow) -> None:

        self.http_dumper.dump("\n===================")
        self.http_dumper.dump("WebScoket Start")
        self.http_dumper.dump("===================")
        self.http_dumper.dump("Request ID: %s" % flow.id)
        self.http_dumper.dump("Client Address: %s:%s" %
                  (flow.client_conn.address[0], flow.client_conn.address[1]))
        self.http_dumper.dump("Client TLS version: %s" % flow.client_conn.tls_version)
        self.http_dumper.dump("Client Extension: %s" % flow.client_extensions)
        self.http_dumper.dump("Client Key: %s" % flow.client_key)
        self.http_dumper.dump("Server Address: %s:%s" %
                  (flow.server_conn.address[0], flow.server_conn.address[1]))
        self.http_dumper.dump("Server IP: %s:%s" % (flow.server_conn.ip_address[
                  0], flow.server_conn.ip_address[1]))
        self.http_dumper.dump("Server Source Address: %s:%s" % (
            flow.server_conn.source_address[0], flow.server_conn.source_address[1]))
        self.http_dumper.dump("Server Accept: %s" % flow.server_accept)

    def websocket_message(self, flow: websocket.WebSocketFlow) -> None:
        if self.flow_file:
            self.w.add(flow.copy())
        self.http_dumper.dump("\n===================")
        self.http_dumper.dump("WebScoket Message")
        self.http_dumper.dump("===================")
        self.http_dumper.dump("Request ID: %s" % flow.id)
        self.http_dumper.dump("Client Address: %s:%s" %
                  (flow.client_conn.address[0], flow.client_conn.address[1]))
        self.http_dumper.dump("Client TLS version: %s" % flow.client_conn.tls_version)
        self.http_dumper.dump("Client Extension: %s" % flow.client_extensions)
        self.http_dumper.dump("Client Key: %s" % flow.client_key)
        self.http_dumper.dump("Server Address: %s:%s" %
                  (flow.server_conn.address[0], flow.server_conn.address[1]))
        self.http_dumper.dump("Server IP: %s:%s" % (flow.server_conn.ip_address[
                  0], flow.server_conn.ip_address[1]))
        self.http_dumper.dump("Server Source Address: %s:%s" % (
            flow.server_conn.source_address[0], flow.server_conn.source_address[1]))
        self.http_dumper.dump("Server Accept: %s" % flow.server_accept)
        self.http_dumper.dump("\nMessages: %s" % flow.messages[-1])

    def websocket_end(self, flow: websocket.WebSocketFlow) -> None:
        self.http_dumper.dump("\n===================")
        self.http_dumper.dump("WebScoket End")
        self.http_dumper.dump("===================")
        self.http_dumper.dump("Request ID: %s" % flow.id)
        self.http_dumper.dump("Client Address: %s:%s" %
                  (flow.client_conn.address[0], flow.client_conn.address[1]))
        self.http_dumper.dump("Client TLS version: %s" % flow.client_conn.tls_version)
        self.http_dumper.dump("Client Extension: %s" % flow.client_extensions)
        self.http_dumper.dump("Client Key: %s" % flow.client_key)
        self.http_dumper.dump("Server Address: %s:%s" %
                  (flow.server_conn.address[0], flow.server_conn.address[1]))
        self.http_dumper.dump("Server IP: %s:%s" % (flow.server_conn.ip_address[
                  0], flow.server_conn.ip_address[1]))
        self.http_dumper.dump("Server Source Address: %s:%s" % (
            flow.server_conn.source_address[0], flow.server_conn.source_address[1]))
        self.http_dumper.dump("Server Accept: %s" % flow.server_accept)
"""
