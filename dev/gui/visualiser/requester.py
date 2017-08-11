"""
    Open Security Analysis Workbench (OpenSAW) - A concolic security test tool
    Copyright (C) 2016, 2017 Ericsson AB

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

import requests

"""
    The requester module handles fetching JSON data from the OpenSAW web interface.
    By default it assumes that OpenSAW is running on the same machine, but the
    url that requester looks for can be changed.
"""

mainurl = "http://localhost:8080"

#Map of the JSON data published by OpenSAW:

#/api/tracegraph.json
    #Keys
    #nodes
        #<list>
            #group          : int
            #id             : str
            #ins            : int -- instruction count
    #links
        #<list>
            #source         : str
            #target         : str
            #value          : int

#/api/statistics.json
    #Keys
    #performance
        #solver
            #average        : double
            #total          : double
            #measurements   : int
        #pin
            #average        : double
            #total          : double
            #measurements   : int
        #il_tool
            #average        : double
            #total          : double
            #measurements   : int
    #done                   : boolean
    #crashes                : list
        #<list>
            #file           : str
            #signal         : int
            #time           : double
            #trace          : list<str>
    #coverage
        #visited
            #timestamps     : list<double>
            #blocks         : list<int>
            #branches       : list<int>
        #updated            : double
        #found
            #blocks         : int
            #branches       : int
    #time                   : double

def get_json(url):
    j = None
    try:
        r = requests.get(url)
        j = r.json()
    except IOError:
        pass
    except ValueError:
        print "ValueError in get_json(): Invalid or missing JSON"
    return j

def get_local_json(localurl):
    global mainurl
    return get_json(mainurl+localurl)

def set_mainurl(newurl):
    global mainurl
    mainurl = newurl

def get_mainurl():
    global mainurl
    return mainurl

def get_tracegraph():
    return get_local_json("/api/tracegraph.json")

def get_statistics():
    return get_local_json("/api/statistics.json")
