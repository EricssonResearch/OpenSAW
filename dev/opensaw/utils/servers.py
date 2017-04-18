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
"""
Module for server helper classes and functions.
"""

# ===============================================================================
# Imports
# ===============================================================================

import SocketServer


# ===============================================================================
# Server classes
# ===============================================================================

class RequestHandler(SocketServer.BaseRequestHandler):
    def __init__(self, callback, *args, **keys):
        self.callBack = callback
        SocketServer.BaseRequestHandler.__init__(self, *args, **keys)

    def handle(self):
        self.callBack(self.request)


def handlerFactory(callback):
    def createHandler(*args, **keys):
        return RequestHandler(callback, *args, **keys)

    return createHandler


class ThreadedTCPServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    pass
