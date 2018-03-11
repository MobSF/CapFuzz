import os

import capfuzz.settings as settings


class HTTPDumper:
    """
    Dump HTTP traffic in readable format
    """

    def __init__(self, dump_file, display_out=False):
        self.dump_file = dump_file
        self.display_out = display_out

    def dump(self, data):
        """Save Raw Readable Content"""
        if self.dump_file:
            with open(self.dump_file, "a") as flip:
                flip.write(data + "\n")
        if self.display_out:
            print(data)

    def save_http(self, flow):
        """Save Given Request and Response"""
        self.dump("========")
        self.dump("REQUEST")
        self.dump("========")
        req = flow.request
        res = flow.response
        self.dump("%s %s %s" % (req.method, req.url, req.http_version))
        for key, val in req.headers.items():
            self.dump("%s: %s" % (key, val))
        if req.content:
            self.dump("\n\n%s" % (req.content.decode("utf-8", "ignore")))

        self.dump("=========")
        self.dump("RESPONSE")
        self.dump("=========")
        self.dump("%s %s %s" % (res.http_version, res.status_code, res.reason))
        for key, val in res.headers.items():
            self.dump("%s: %s" % (key, val))
        if res.content:
            self.dump("\n\n%s" % (res.content.decode("utf-8", "ignore")))


def get_flow_file(flow_name, write=False):
    """Get Flow File Safetly"""
    flow_dir = settings.FLOWS_DIR
    requested_path = os.path.join(flow_dir, flow_name + ".flows")
    if write:
        if os.path.commonprefix((os.path.realpath(requested_path), flow_dir)) != flow_dir:
            return False
        return requested_path
    else:
        if os.path.commonprefix((os.path.realpath(requested_path), flow_dir)) == flow_dir and os.path.exists(requested_path):
            return requested_path
        return False

def get_report_file(flow_name):
    """Get Flow File Safetly"""
    report_dir = settings.LOGS_DIR
    requested_path = os.path.join(report_dir, flow_name + ".flows")
    if os.path.commonprefix((os.path.realpath(requested_path), report_dir)) == report_dir and os.path.exists(requested_path):
        return requested_path
    return False


def rreplace(strn, old, new, occurrence):
    lis = strn.rsplit(old, occurrence)
    return new.join(lis)

def create_dir(dirs):
    for folder in dirs:
        if not os.path.exists(folder):
            os.makedirs(folder)

