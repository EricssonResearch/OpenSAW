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
    The Dia_Plot widget renders a plot with two curves from input data, one named Branches and
    one named Blocks. It also displays indicators for discovered errors on the
    plot's timeline.

    Create as a normal Tkinter canvas. The 'tracegraph' input is used for linking
    errors displayed on the plot with a Dia_Tree widget to follow node highlighting.

    After creation, data can be imported from OpenSAW JSON dumps with .import_plot().
    After data has been imported, a call to .paint_plot() must be made for changes to be visible.
"""

class Dia_Plot(Canvas):

    def __init__(self, parent, tracegraph=None, **kwd):
        Canvas.__init__(self, parent, kwd)
        self.branch = []                #Visited branches at times from self.times
        self.block = []                 #Visited blocks at times from self.times
        self.times = []                 #The times for input data
        self.lasttime = 1               #The program run-time last time paint_plot was called. Used in case no time was provided.
        self.crashes = []               #All crashes to display
        self.crashgraphics = {}         #<canvas id> to <self.crashes index> for each crash
        self.tracegraph = tracegraph    #Dia_Tree object to synchronise crash highlighting
        self.highlight = -1             #The current highlight. -1 works as a None
        self.fnd_branch = 0             #The number of found branches
        self.fnd_block = 0              #The number of found blocks
        self.clr_branch = "#00FF00"     #Color used for the branch curve
        self.clr_block = "#0000FF"      #Color used for the block curve
        self.bind("<Visibility>", self.on_visibility)
        self.bind("<ButtonPress-1>", self.on_click)

    #Draws the plot when it becomes visible
    def on_visibility(self, event):
        self.paint_plot(self.lasttime)

    #Looks for clicks on errors, for highlighting
    def on_click(self, event):
        x = self.canvasx(event.x)
        y = self.canvasy(event.y)

        r = self.find_overlapping(x-1,y-1,x+1,y+1)

        if len(r)==0:
            self.highlight = -1
        elif len(r)>0:
            for g in r:
                if g in self.crashgraphics: #This shows we clicked on one of the crash bubbles
                    self.highlight = self.crashgraphics[g] #This gets the index of the crash
                    if self.tracegraph:
                        self.tracegraph.pick_highlight(self.crashes[self.highlight]['node'])
                    break #Stop after one. They shouldn't overlap.
        self.paint_plot(self.lasttime)

    #Expects inputs in the following format:
    #vis = {'branches':[0,X,Y,Z...],  -- The number of visited branches at different times
    #       'blocks':[0,I,J,K...],    -- The number of visited blocks at different times
    #       'timestamps':[0,A,B,C...]}-- The different times
    #fnd = {'branches':A,             -- The number of found branches
    #       'blocks':B}               -- The number of found blocks  
    def import_plot(self, vis, fnd):
        self.fnd_branch = fnd['branches']
        self.fnd_block = fnd['blocks']
        self.branch = vis['branches']
        self.block = vis['blocks']
        self.times = vis['timestamps']

    def mark_crash(self, signal, color, filename, time, node):
        self.crashes.append({'signal':signal,       #Crashing signal
                             'color':color,         #Color of crash node
                             'filename':filename,   #The filename of the input file that generated the error
                             'time':time,           #The time of discovery, in the same unit as the input data
                             'node':node})          #The Tree_Node where the crash originated

    def clear_crash(self):
        self.crashes = []

    def paint_plot(self, time):
        #Establish geometry
        self.lasttime = time #Save the time for later, if the time wouldn't be available
        h = self.winfo_height()-60
        w = self.winfo_width()-40

        th = 20
        bh = 20+h
        lw = 20
        rw = 20+w

        #Clear the canvas.
        #TODO: The could be done without clearing everything.
        #Not clearing the axes for example
        self.delete(ALL)

        #Draw axes
        self.create_line(lw, bh, rw, bh, tag="AXIS", width=2, arrow=LAST)
        self.create_text(rw-10, bh-2, tag="AXIS", anchor=SE, text="Time [s]")
        
        self.create_line(lw, bh, lw, th, tag="AXIS", width=2, arrow=LAST)
        self.create_text(lw+5, th, tag="AXIS", anchor=W, text="Coverage")

        #Only draw the curves if they have at least two points of data.
        if len(self.times)>1:
            #Establish plot scale
            #The number of visited branches should never be higher than the number of found ones
            #So use the number of found to establish the scale.
            maxval = max(self.fnd_branch, self.fnd_block)*1.05
            maxtime = time*1.05

            if maxval == 0:
                maxval = 1
            
            hscale = h/maxval
            wscale = w/maxtime

            #Draw lines for found branches/blocks.
            self.create_line(lw, bh-hscale*self.fnd_branch, rw, bh-hscale*self.fnd_branch,
                             tag="BRANCH", width=2, dash=[10,5], fill=self.clr_branch)
            self.create_line(lw, bh-hscale*self.fnd_block, rw, bh-hscale*self.fnd_block,
                             tag="BLOCK", width=2, dash=[10,5], fill=self.clr_block)

            
            last_time_w = 0 #The X position where the last timestamp was placed
            for i in xrange(1,len(self.times)):
                # Draw curves
                lastw = lw+wscale*self.times[i-1]
                neww = lw+wscale*self.times[i]

                lasth = bh-hscale*self.branch[i-1]
                newh = bh-hscale*self.branch[i]

                self.create_line(lastw, lasth, neww, newh,
                                 tag="BRANCH", width=2, fill= self.clr_branch)
                if(i == len(self.times)-1): #Continue with a horizontal line to the current time
                    self.create_line(neww,newh,lw+time*wscale, newh,
                                     tag="BRANCH", width=2, fill= self.clr_branch)

                lasth = bh-hscale*self.block[i-1]
                newh = bh-hscale*self.block[i]

                self.create_line(lastw, lasth, neww, newh,
                                 tag="BLOCK", width=2, fill= self.clr_block)
                if(i == len(self.times)-1): #Continue with a horizontal line to the current time
                    self.create_line(neww,newh,lw+time*wscale, newh,
                                     tag="BLOCK", width=2, fill= self.clr_block)

                # Draw Timestamp
                # Don't draw timestamp if too clumped together
                if neww-last_time_w > 60 and (lw+wscale*time)-neww > 60:
                    last_time_w = neww
                    self.create_line(neww, bh, neww, bh+10, width=2, tag="AXIS")
                    txt = "{:.1f}".format(self.times[i])
                    self.create_text(neww, bh+12, anchor=N, tag="AXIS",
                                     text=txt, width=60, justify=CENTER)

            #Draw a final timestamp for the current time
            self.create_line(lw+wscale*time, bh, lw+wscale*time, bh+10, width=2, tag="AXIS")
            txt = "{:.1f}".format(time)
            self.create_text(lw+wscale*time, bh+12, anchor=N, tag="AXIS",
                             text=txt, width=60, justify=CENTER)

            #Draw coverage labels
            txt_h=bh-hscale*self.branch[-1]
            txt_w=lw+wscale*time
            txt_s="Branch Coverage: {:.1%}".format(float(self.branch[-1])/self.fnd_branch)
            self.create_text(txt_w, txt_h, anchor=SE, tag="BRANCH", text=txt_s)

            txt_h=bh-hscale*self.block[-1]
            txt_s="Block Coverage: {:.1%}".format(float(self.block[-1])/self.fnd_block)
            self.create_text(txt_w, txt_h, anchor=SE, tag="BLOCK", text=txt_s)

            #Draw crash bubbles
            self.crashgraphics = {}
            last_crash_w = -600
            last_crash_n = 0
            for i,crash in enumerate(self.crashes):
                ch = bh-80
                cw = lw+wscale*crash['time']

                if cw - last_crash_w > 15:  #Good spacing
                    last_crash_w = cw
                    last_crash_n = 0
                else:                       #Overlap! Stack them higher instead.
                    last_crash_w = cw
                    last_crash_n += 1
                    ch -= last_crash_n*15

                if self.highlight == i:     #Highlight clicked nodes
                    color = "#5DA5DA"
                    self.create_oval(cw-8, ch-8, cw+8, ch+8, tags="CRASH",
                                     outline=color, fill=color)

                gid = self.create_oval(cw-5, ch-5, cw+5, ch+5, tags="CRASH",
                                 fill=crash['color'], outline="#FF0000")

                self.crashgraphics[gid] = i #Save the index of the crash with the id of the oval
                                            #So that we can find the crash from which oval was clicked

        #Fix the object ordering
        self.tag_lower("CRASH")
        self.tag_raise("AXIS")

