'''
Perform path Deserialization checks
more trigger detections
test wth a java test app
'''
import os
import re
import time
import uuid
import base64
import urllib.parse
from fuzzer.plugins.utils.helper import (
    is_valid_flow,
    get_os_server,
    get_md5,
    encode_uri,
    encode_uri_component
)

import settings


class Deserialization:
    """
    Path Traversal Fuzzer
    """

    def __init__(self, fuzzer_options, scan_mode="fast", scope=["url", "body", "headers"]):
        """
        scan_mode: Fuzzing speed:  slow, fast <str>
        scope: What to Fuzz : url, body <list>
        """

        self.scan_mode = scan_mode
        self.scope = scope
        self.script_path = os.path.dirname(os.path.realpath(__file__))
        self.fuzzer_options = fuzzer_options
        self.write = fuzzer_options["write"]
        self.deserialize_fuzz_flows = []

    def deserialize_fuzzer(self, flows):
        """
        Deserialization Fuzzing Request
        """
        if not any(x in self.fuzzer_options["active_fuzzers"] for x in ["fuzz_deserialization_checks", "all"]):
            return
        self.write("Generating Deserialization Fuzz Flows")
        for flow in flows:
            if not is_valid_flow(flow, self.fuzzer_options):
                continue
            if flow.request.content:
                self.body_fuzz(flow)
            self.query_fuzz(flow)
        return self.deserialize_fuzz_flows

    def get_trigger_payloads(self):
        """
        Get Deserialization Trigger Payloads
        """
        payloads = os.path.join(self.script_path, 'req_triggers.txt')
        try:
            with open(payloads, "rb") as file_handler:
                while True:
                    yield next(file_handler).replace(b"\n", b"").split(b"|||")
        except (IOError, OSError):
            self.write("Error opening / processing file")
        except StopIteration:
            pass

    def get_lang_payload(self, lang):
        """
        Get Language Specific Payloads
        """
        payload_list = []
        if lang == b"java":
            payload_dir = os.path.join(self.script_path, 'java_payloads')
            payload_files = os.listdir(payload_dir)
        elif lang == b"python":
            payload_dir = os.path.join(self.script_path, 'python_payloads')
            payload_files = os.listdir(payload_dir)
        elif lang == b"ruby":
            payload_dir = os.path.join(self.script_path, 'ruby_payloads')
            payload_files = os.listdir(payload_dir)
        elif lang == b"php":
            payload_dir = os.path.join(self.script_path, 'php_payloads')
            payload_files = os.listdir(payload_dir)
        try:
            for pfile in payload_files:
                if pfile.endswith(".bin"):
                    payloads = os.path.join(payload_dir, pfile)
                    # Byte Like Payloads
                    with open(payloads, "rb") as file_handler:
                        payload_list.append(file_handler.read())
            return payload_list
        except (IOError, OSError):
            self.write("Error opening / processing file")

    def query_fuzz(self, flow):
        for _, value in flow.request.query.items():
            for trigger in self.get_trigger_payloads():
                trig = trigger[1]
                app_lang = trigger[0]
                # If query starts with a serialized payload
                # Fuzz Query if XML Like values are present
                if value.startswith(trig.decode("utf-8", "ignore")):
                    for payload in self.get_lang_payload(app_lang):
                        if b"[SERVER]" in payload:
                            md5, payload = self.get_final_payload(payload, b"[SERVER]")
                            meta = {"md5": md5, "fuzz_type": "query", "payload": payload}
                        elif b"[PS]" in payload:
                            md5, payload = self.get_final_payload(payload, b"[PS]")
                            meta = {"md5": md5, "fuzz_type": "query", "payload": payload}
                        elif b"sleep" or b"ping" in payload:
                            meta = {"blind": 10, "tms":time.time(), "fuzz_type": "query", "payload": payload}
                        else:
                            meta = {"fuzz_type": "query", "payload": payload}
                        tmp_flow = flow.copy()
                        tmp_flow.request.path = tmp_flow.request.path.replace(urllib.parse.quote(value), urllib.parse.quote(payload.decode("utf-8", "ignore")))
                        tmp_flow.request.path = tmp_flow.request.path.replace(encode_uri(value), encode_uri(payload.decode("utf-8", "ignore")))
                        tmp_flow.metadata["fuzz_deserialize"] = meta
                        self.deserialize_fuzz_flows.append(tmp_flow)

    def body_fuzz(self, flow):
        request = flow.request
        for trigger in self.get_trigger_payloads():
            trig = trigger[1]
            app_lang = trigger[0]
            # If body starts with a serialized payload
            if request.content.startswith(trig):
                for payload in self.get_lang_payload(app_lang):
                    if b"[SERVER]" in payload:
                        md5, payload = self.get_final_payload(payload, b"[SERVER]")
                        meta = {"md5": md5, "fuzz_type": "body", "payload": payload}
                    elif b"[PS]" in payload:
                        md5, payload = self.get_final_payload(payload, b"[PS]")
                        meta = {"md5": md5, "fuzz_type": "body", "payload": payload}
                    elif b"sleep" or b"ping" in payload:
                        meta = {"blind": 10, "tms":time.time(), "fuzz_type": "body", "payload": payload}
                    else:
                        meta = {"fuzz_type": "body", "payload": payload}
                    tmp_flow = flow.copy()
                    tmp_flow.request.content = payload
                    tmp_flow.metadata["fuzz_deserialize"] = meta
                    self.deserialize_fuzz_flows.append(tmp_flow)

    def get_final_payload(self, payload, typ):
        md5 = get_md5(uuid.uuid4().hex.encode('utf-8'))
        oob_url = settings.OUT_OF_BAND_SERVER + "/" + md5
        url = bytes(oob_url, "utf-8", "ignore")
        if typ == b"[SERVER]":
            payload = payload.replace(typ, url)
        elif typ == b"[PS]":
            ps_plain = b"[System.Net.WebRequest]::Creaete('" + url + b"').GetResponse();"
            ps_ecode = self.powershell_encode(ps_plain)
            payload = payload.replace(typ, ps_ecode)
        return md5, payload


    def powershell_encode(self, data):
        """
        credits: https://github.com/darkoperator/powershell_scripts/blob/master/ps_encoder.py
        b = b"[System.Net.WebRequest]::Create('http://127.0.0.1:3000').GetResponse();"
        print (powershell_encode(b))
        """
        # blank command will store our fixed unicode variable
        data = data.decode("utf-8", "ignore")
        blank_command = ""
        powershell_command = ""
        # Remove weird chars that could have been added by ISE
        n = re.compile(u'(\xef|\xbb|\xbf)')
        # loop through each character and insert null byte
        for char in (n.sub("", data)):
            # insert the nullbyte
            blank_command += char + "\x00"
        # assign powershell command as the new one
        powershell_command = blank_command
        # base64 encode the powershell command
        powershell_command = base64.b64encode(bytes(powershell_command, "utf-8"))
        return powershell_command
