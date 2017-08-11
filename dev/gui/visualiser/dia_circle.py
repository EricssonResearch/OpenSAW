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

try:
    from Tkinter import *
except ImportError:
    from tkinter import *

"""
    The Dia_Circle widget renders a circle diagram from input data.

    Create as a normal Tkinter canvas. The 'mode' input decides wether
    the graph legend should show input data as percentages when mode = 0,
    or integers when mode != 0.

    After creation, data can be set with set_data(). After data has been
    updated, a call to .paint() must be made for changes to be visible.
"""
class Dia_Circle(Canvas):

    def __init__(self, parent, mode=0, **kwd):
        Canvas.__init__(self, parent, kwd)
        self.data = {}      #Graph input data
        self.mode = mode    #Legend display mode. 0 = Percentages, 1 = Integers
        self.bind("<Visibility>", self.on_visibility)

    #Repaints the graph as it becomes visible
    def on_visibility(self, event):
        self.paint()

    def set_data(self, name, value, color="#FF0000"):
        self.data[name]={'value':value, 'color':color}

    def clear_data(self):
        self.data = {}

    def paint(self):
        #Establish geometry
        h = self.winfo_height()
        center_h = h/2
        w = self.winfo_width()
        center_w = w/2
        s = min(w, h)-20
        half_s = s/2
        arc_start = 0
        total = 0.0

        #Clear old canvas
        #TODO: This could be done without deletion, changing the arcs instead of deleting and creating new.
        self.delete(ALL)

        if len(self.data) < 1:
            self.create_text(20, 20, anchor=NW, text="No Data to Display.", width = 80, tag="LEGEND")
        else:
            #Calculate sum
            for name in self.data.keys():
                d = self.data[name]
                total += d['value']

            legendX = 20
            legendY = 20

            for name in self.data.keys():
                d = self.data[name]
                part = 0
                if d['value'] > 0:
                    part = d['value']/total
                    angle = 360*part
                    if(angle > 359.9): #Full circle
                        angle = 359.9
                        self.create_oval(center_w-half_s, center_h-half_s, center_w+half_s, center_h+half_s,
                                         fill=d['color'])
                    else:
                        #Create pieslice
                        self.create_arc(center_w-half_s, center_h-half_s, center_w+half_s, center_h+half_s,
                                        fill=d['color'], extent=angle, start=arc_start, style=PIESLICE)
                        arc_start += angle

                #Create a legend entry for the pieslice, even if it's 0
                self.create_rectangle(legendX-5, legendY-5, legendX+5, legendY+5,
                                      fill=d['color'], tag="LEGEND")
                if self.mode == 0:
                    s = "{:.1%}".format(part)
                else:
                    s = "{:d}".format(d['value'])
                self.create_text(legendX+10, legendY, anchor=W, text="["+s+"] "+name, tag="LEGEND")
                legendY+=15

        #Draw a box behind all legend items.
        lb = self.bbox("LEGEND")
        lb = (lb[0]-5, lb[1]-5, lb[2]+5, lb[3]+5)
        self.create_rectangle(lb, fill="#FFFFFF")
        self.tag_raise("LEGEND")
