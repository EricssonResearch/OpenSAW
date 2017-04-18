"""
    Open Security Analysis Workbench (OpenSAW) - A concolic security test tool
    Copyright (C) 2016 Ericsson AB

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; version 2 of the License.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
"""
from __future__ import absolute_import

import socket

try:
    from http.server import BaseHTTPRequestHandler, HTTPServer
    from http.client import HTTPConnection
except ImportError:
    # noinspection PyUnresolvedReferences
    from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
    # noinspection PyUnresolvedReferences
    from httplib import HTTPConnection

import json
from threading import Thread
from os.path import dirname, join, normpath
from opensaw.utils.json import from_builtin


class APIException(Exception):
    pass


class JSONRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        """Respond to a GET request."""
        if self.path == "/favicon.ico":
            self.send_response(404)
            self.end_headers()
            return

        # Normalize path and remove initial `/`
        path = normpath(self.path)[1:]
        mime_type = "text/plain"

        # `/` -> `/index.html`
        if path == "":
            path = "index.html"

        if path.endswith(".json"):
            mime_type = "application/json"
        elif path.endswith(".js"):
            mime_type = "application/javascript"
        elif path.endswith(".html"):
            mime_type = "text/html"
        elif path.endswith(".css"):
            mime_type = "text/css"

        try:
            # Take special care when delivering `api/*.json`
            if path.startswith("api/") and path.endswith(".json"):
                path = path[4:-5]

                if path in self.server.data:
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    json.dump(self.server.data[path], self.wfile,
                              default=from_builtin)
                else:
                    raise APIException()

            else:
                # Open and server the file from `<webserver>/static/`
                with open(join(dirname(__file__), "static", path), "rb") as file:
                    self.send_response(200)
                    self.send_header("Content-type", mime_type)
                    self.end_headers()
                    self.wfile.write(file.read())

        except APIException:
            self.send_error(404, "No such API: /api/{}.json".format(path))
        except IOError:
            self.send_error(404, "File Not Found: {}".format(path))

    def do_QUIT(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write("Bye!")

    def log_message(self, format, *args):
        pass


class StoppableHTTPServer(HTTPServer):
    def __init__(self, host_port, handler):
        HTTPServer.__init__(self, host_port, handler)
        self.keep_serving = True

    def serve_forever(self):
        while self.keep_serving:
            self.handle_request()

    def stop(self):
        # Don't do anything if it already is stopped.
        if not self.keep_serving:
            return

        conn = HTTPConnection("localhost:{}".format(self.server_port), timeout=2)

        self.keep_serving = False

        conn.request("QUIT", "/")
        try:
            conn.getresponse()
        except socket.timeout as e:
            pass
        self.socket.close()

class WebServer(Thread):
    """WebServer is a Thread running a HTTPServer.

    Given a dictionary it will serve the values as JSON.
    Built-in objects can also be served by `json.dump`-ing
    the result of the object's `to_json` method, if available.
    If no such method exists, the `__dict__` property will be used.

    In the example below, a new Thread is started,
    listening to port 8000.
    It responds to GET requests for `/api/example.json`,
    by sending the number `4711`.

        server = WebServer({ "example": 4711 }, port=8000)
        server.run()
    """

    def __init__(self, data=None, port=8080):
        Thread.__init__(self)
        if data is None:
            data = dict()
        self.server = StoppableHTTPServer(("", port), JSONRequestHandler)
        self.server.data = data

    def run(self):
        self.server.serve_forever()

    def stop(self):
        self.server.stop()

    def join(self):
        Thread.join(self)
