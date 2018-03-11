import requests
import socket
from urllib.parse import urlparse


class OOBValidator:

    def __init__(self, oob_server):
        self.oob_server = oob_server

    def get_status_by_md5(self, md5):
        try:
            r = requests.get(self.oob_server + "/md5/" + md5)
            if r.json()["status"] == "yes":
                return True
            else:
                return False
        except Exception as exp:
            print("[ERROR] OOBValidator: %s" % exp)
        return False

    def get_status_by_ip(self, url):
        try:
            for ip in self.get_ip_list(url):
                r = requests.get(self.oob_server + "/ip/" + ip)
                if r.json()["count"] != 0:
                    # Clean IP state in Cloud Server
                    delete_by_ip(ip)
                    return True
            return False
        except Exception as exp:
            print(
                "[ERROR] OOBValidator - Checking IP status from Cloud Server: %s" % exp)
        return False

    def get_status_by_count(self, count):
        try:
            r = requests.get(self.oob_server + "/ip/ts")
            if r.json()["count"] >= count:
                return True
            else:
                return False
        except Exception as exp:
            print(
                "[ERROR] OOBValidator -  Checking Status by Request Count from Cloud Server: %s" % exp)
        return False

    def delete_by_ip(self, ip):
        try:
            r = requests.get(self.oob_server + "/delete/" + ip)
        except Exception as exp:
            print(
                "[ERROR] OOBValidator - Deleting entries by IP from Cloud Server: %s" % exp)

    def get_ip_list(self, url):
        ips = []
        hostname = ''
        port = '80'
        try:
            o = urlparse(url)
            hostname = o.hostname
            if o.port:
                port = o.port
            else:
                if o.scheme == "http":
                    port = 80
                elif o.scheme == "https":
                    port = 443
            result = socket.getaddrinfo(hostname, port, 0, socket.SOCK_STREAM)
            for item in result:
                ips.append(item[4][0])
            ips = list(set(ips))
        except Exception as exp:
            print("[ERROR] OOBValidator - Getting IP(s) from URL: %s" % exp)
        return ips
