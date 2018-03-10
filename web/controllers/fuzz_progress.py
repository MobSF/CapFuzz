import tornado.websocket

from fuzzer.plugins.utils.helper import (
    danger_print
)


class ScanProgress(tornado.websocket.WebSocketHandler):
    client = None

    def open(self):
        ScanProgress.client = self

    def on_message(self, message):
        if message == "CONNECT":
            self.write_message(u"Fuzzer Ready!")

    def on_close(self):
        ScanProgress.client = None

    @classmethod
    def write(cls, msg, type="none"):
        if type == "danger":
            danger_print(msg)
        else:
            print(msg)
        if cls.client:
            cls.client.write_message(msg)
