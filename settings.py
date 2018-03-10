import os
# Proxy and Web GUI
PORT = 1337
# OUTPUT
BASE_PATH = os.path.dirname(os.path.abspath(__file__))
FLOWS_DIR = os.path.join(BASE_PATH, "flows")
LOGS_DIR = os.path.join(BASE_PATH, "logs")
CA_DIR = os.path.join(BASE_PATH, "ca")
## Code to create dirs needed
DISPLAY_OUT = True
# Upstream Proxy
UPSTREAM_PROXY = False
UPSTREAM_PROXY_CONF = "upstream:http://127.0.0.1:8080"
UPSTREAM_PROXY_SSL_INSECURE = True
# Fuzzer Options
FUZZERS = ["XSS", "SSRF", "XXE", "Path Traversal",
           "Header Checks", "Deserialization Checks", "API"]
FUZZ_TIMEOUT = 25  # seconds
RATELIMIT_REQ_NOS = 30
SKIP_URL_MATCH = ["logout", "logoff", "signout", "exit"]
SKIP_FILE_EXTS = {".jpg": "image/jpeg", ".bmp": "image/bmp",
                  ".ico": "image/x-icon", ".png": "image/png",
                  ".gif": "image/gif", ".css": "text/css",
                  ".woff": "font/woff", ".woff2": "font/woff2",
                  ".eot": " application/vnd.ms-fontobject",
                  ".ttf": "application/font-sfnt",
                  ".otf": "application/font-sfnt",
                  ".js": "application/javascript"}
EXCLUDE_RESP_CODE = ["4"]
VALIDATE_STRING = "zz0zz0"
OUT_OF_BAND_SERVER = 'http://opensecurity.in:8080'
