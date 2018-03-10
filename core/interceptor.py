"""
Modify Request/Response
"""
from mitmproxy import (
    flow,
    http,
    websocket,
)

class Interceptor:
    """Intercept Web Traffic"""
    def __init__(self):
        print ("Interceptor Module Loaded")

    # HTTP Hooks
    def http_connect(self, flow: http.HTTPFlow) -> None:
        """
        Called when we receive an HTTP CONNECT request. Setting a non 2xx response
        on the flow will return the response to the client abort the connection. 
        CONNECT requests and responses do not generate the usual HTTP handler events.
        CONNECT requests are only valid in regular and upstream proxy modes.
        """
        pass

    def request(self, flow: http.HTTPFlow) -> None:
        """
        Called when a client request has been received.
        """
        pass

    def requestheaders(self, flow: http.HTTPFlow) -> None:
        """
        Called when the headers of a client request have been received,
        but before the request body is read.
        """
        pass

    def responseheaders(self, flow: http.HTTPFlow) -> None:
        """
        Called when the headers of a server response have been received,
        but before the response body is read.
        """
        pass

    def response(self, flow: http.HTTPFlow) -> None:
        """
        Called when a server response has been received.
        """
        if b"<!DOCTYPE html>" in flow.response.content:
            flow.response.content = b"<svg onload=alert('Injected')>" + flow.response.content 
        pass

    def error(self, flow: http.HTTPFlow) -> None:
        """
        Called when a flow error has occurred, e.g. invalid server responses, or interrupted connections.
        This is distinct from a valid server HTTP error response, which is simply a response with an HTTP error code.
        """
        pass

    # Websocket Hooks
    def websocket_handshake(self, flow: websocket.WebSocketFlow) -> None:
        """
        Called when a client wants to establish a WebSocket connection.
        The WebSocket-specific headers can be manipulated to alter the handshake.
        The flow object is guaranteed to have a non-None request attribute.
        """
        pass

    def websocket_start(self, flow: websocket.WebSocketFlow) -> None:
        """
        Called when WebSocket connection is established after a successful handshake.
        """
        pass

    def websocket_message(self, flow: websocket.WebSocketFlow) -> None:
        """
        Called when a WebSocket message is received from the client or server.
        The sender and receiver are identifiable. The most recent message will be flow.messages[-1].
        The message is user-modifiable and is killable. A message is either of TEXT or BINARY type.
        """
        pass

    def websocket_end(self, flow: websocket.WebSocketFlow) -> None:
        """
        Called when WebSocket connection ends.
        """
        pass

    def websocket_error(self, flow: websocket.WebSocketFlow) -> None:
        """
        Called when a WebSocket error occurs - e.g. the connection closing unexpectedly.
        """
        pass
