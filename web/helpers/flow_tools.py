from mitmproxy import (
    io
)

from fuzzer.plugins.utils.net import (
    get_protocol_domain
)


def load_flows(path):
    flows = []
    print("Loading Requests")
    with open(path, "rb") as f:
        flows.extend(io.FlowReader(f).stream())
    return flows


def get_headers(headers):
    """by default headers are folded by mitmproxy"""
    headers_dict = {}
    for key, val in headers.items():
        headers_dict[key] = val
    return headers_dict


def get_flow_meta(flow):
    flow_meta = {}
    flow_meta["id"] = flow.id
    content = flow.request.content.decode(
        "utf-8", "ignore") if flow.request.content else ""
    request_headers = get_headers(flow.request.headers)
    response_headers = get_headers(flow.response.headers)
    flow_meta["request"] = {"method": flow.request.method, "url": flow.request.url,
                            "http_version": flow.request.http_version, "headers": request_headers, "content": content}
    res_content = flow.response.content.decode(
        "utf-8", "ignore") if flow.response.content else ""
    flow_meta["response"] = {"http_version": flow.response.http_version, "status_code": flow.response.status_code,
                             "reason": flow.response.reason, "headers": response_headers, "content": res_content}
    return flow_meta


def get_sorted_flows(flows):
    # Add URL under domains
    sorted_flows = {}
    for flow in flows:
        domain = get_protocol_domain(flow.request.url, False)
        meta = {"id": flow.id, "method": flow.request.method,
                "relative": flow.request.url.replace(domain, "", 1),
                "url": flow.request.url}
        if domain in sorted_flows:
            sorted_flows[domain].append(meta)
        else:
            sorted_flows[domain] = [meta]
    return sorted_flows
