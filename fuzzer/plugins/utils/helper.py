import os
import re
import ntpath
import hashlib
import urllib.parse
import platform
import settings


class Color(object):
    GREEN = '\033[92m'
    ORANGE = '\033[33m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    END = '\033[0m'


def danger_print(msg):
    if platform.system() == "Windows":
        print(msg)
    else:
        print(Color.BOLD + Color.RED + msg + Color.END)


def get_content_type_lower(obj):
    if "content-type" in obj.headers:
        return obj.headers["content-type"].lower()
    else:
        # Debug
        #print("[DEBUG] No Content-Type header found")
        # print(obj.headers)
        return ""


def encode_uri(value):
    return urllib.parse.quote(value, safe="!#$&()*+,-./:;=?@_~")


def encode_uri_component(value):
    return urllib.parse.quote(value, safe='~()*!.\'')


def get_os_server(flow):
    """
    Get OS and App Server from Response Header
    """
    headers = flow.response.headers
    request = flow.request
    os_name = "Unknown"
    app_server = "Unknown"

    nix_headers = re.compile(
        r"nginx|ubuntu|suse|linux|unix|fedora|redhat|freebsd|debian|centos")
    win_headers = re.compile(r"windows|iis|microsoft")
    x_powered_win = re.compile(r"asp\.net|microsoft|iis|windows")
    java_server = re.compile(r"tomcat|jsp|jboss|java|servlet")
    php_server = re.compile(r"php|apache")
    node_server = re.compile(r"express")
    python_server = re.compile(r"python|wsgiserver|werkzeug")
    ruby_server = re.compile(r"thin")

    server_header = "Unknown"
    ex_pow = "Unknown"
    filename = ""
    if "server" in headers:
        server_header = headers["server"].lower()
    if "x-powered-by" in headers:
        ex_pow = headers["x-powered-by"].lower()
    # OS
    if re.findall(nix_headers, server_header):
        os_name = "Unix"
    elif re.findall(win_headers, server_header) or re.findall(x_powered_win, ex_pow):
        os_name = "Windows"
    # App Server
    if re.findall(java_server, ex_pow) or re.findall(java_server, server_header):
        app_server = "Java"
    elif re.findall(node_server, ex_pow) or re.findall(node_server, server_header):
        app_server = "Node"
    elif re.findall(python_server, ex_pow) or re.findall(python_server, server_header):
        app_server = "Python"
    elif re.findall(ruby_server, ex_pow) or re.findall(ruby_server, server_header):
        app_server = "Ruby"
    elif re.findall(x_powered_win, ex_pow) or re.findall(x_powered_win, server_header):
        app_server = "IIS"
    # Make PHP Check last
    elif re.findall(php_server, ex_pow) or re.findall(php_server, server_header):
        app_server = "PHP"
    # Extension based check
    if request.path_components:
        filename = request.path_components[0]
        if app_server == "Unknown":
            if filename.endswith(".php"):
                app_server = "PHP"
            if filename.endswith(".jsp") or filename.endswith(".do"):
                app_server = "Java"
            if filename.endswith(".asp") or filename.endswith(".aspx"):
                app_server = "IIS"
    return os_name, app_server


def get_content_type_header_name(obj):
    if "content-type" in obj.headers:
        return "content-type"
    else:
        return "Content-Type"


def get_md5(data):
    return hashlib.md5(data).hexdigest()


def is_no_scan_ext(flow):
    url = flow.request.url.lower()
    mime = ""
    if "content-type" in flow.response.headers:
        mime = flow.response.headers["content-type"].lower()
    skip_exts = settings.SKIP_FILE_EXTS
    file_url = url.split("?")[0]
    _, ext = os.path.splitext(file_url)
    for no_scan_ext, no_scan_mime in skip_exts.items():
        if no_scan_ext == ext or no_scan_mime in mime:
            return True
    return False


def is_valid_flow(flow, fuzzer_options):
    """
    exclude flow if any pattern matches
    include flow only if given pattern matches
    """

    if str(type(flow)) != "<class 'mitmproxy.http.HTTPFlow'>":
            # Currently support only HTTP request fuzzing
        return False

    if fuzzer_options["exclude_extensions"] == "on" and is_no_scan_ext(flow):
        """ Don't Fuzz these file extensions"""
        return False

    if fuzzer_options["exclude_response_code"] == "on" and str(flow.response.status_code)[0] in settings.EXCLUDE_RESP_CODE:
        """ We are not interested in 4XX"""
        return False

    skip_urls_match = '|'.join(settings.SKIP_URL_MATCH)
    if fuzzer_options["exclude_url_match"] == "on" and re.findall(skip_urls_match, flow.request.url):
        """Skip Flow if URL Match"""
        return False

    if fuzzer_options["exclude_scope"]:
        for x_item in fuzzer_options["exclude_scope"]:
            if x_item in flow.request.url:
                return False
    if fuzzer_options["include_scope"]:
        """Apply include filter only if include is defined, else allow rest of the flow """
        if any(i_item in flow.request.url for i_item in fuzzer_options["include_scope"]):
            return True
        else:
            return False
    return True

def get_filename(path):
    """Get Filename"""
    head, tail = ntpath.split(path)
    return tail or ntpath.basename(head)

def is_json_content_type(value):
    return re.findall(r"application/json|application/x-javascript|text/javascript|text/x-javascript|text/x-json", value)


def is_xml_content_type(value):
    return re.findall(r"text/xml|application/xml", value)


def is_email(value):
    return re.findall("%40|@", value)
