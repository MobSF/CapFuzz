import re
import urllib.parse


def get_url_match(value):
    value = urllib.parse.unquote(value)
    p = re.compile(
        r'((?:https?://|s?ftps?://|file://|javascript:|www\d{0,3}[.])[\w().=/;,#:@?&~*+!$%\'{}-]+)', re.UNICODE)
    return re.findall(p, value)


def get_ip_match(value):
    ip = re.compile(r'[0-9]+(?:\.[0-9]+){3}', re.UNICODE)
    return re.findall(ip, value)


def get_ip_n_port_match(value):
    ip_port = re.compile(r'[0-9]+(?:\.[0-9]+){3}:[0-9]{1,5}', re.UNICODE)
    return re.findall(ip_port, value)


def get_ipport_match(value):
    final = []
    value = urllib.parse.unquote(value)
    ips = get_ip_match(value)
    ip_ports =get_ip_n_port_match(value)
    for ipv4 in ips:
        if not any(ipv4 in ipp for ipp in ip_ports):
            final.append(ipv4)
    final += ip_ports
    final = list(set(final))
    return final


def get_protocol_domain(url, trailing=True):
    try:
        parsed_uri = urllib.parse.urlparse(url)
        if trailing:
            return '{uri.scheme}://{uri.netloc}/'.format(uri=parsed_uri)
        return '{uri.scheme}://{uri.netloc}'.format(uri=parsed_uri)
    except Exception as exp:
        print("[ERROR] Parsing Protocol and Domain - %s" % exp)
