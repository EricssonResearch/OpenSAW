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

import sys

try:
    from Tkinter import *
except ImportError:
    from tkinter import *

try:
    import ttk
    py3 = 0
except ImportError:
    import tkinter.ttk as ttk
    py3 = 1

import tkSimpleDialog as tsd
import requester
from dia_circle import *
from dia_tree import *
from dia_plot import *

"""
    The OpenSAW_Visualiser class is responsible for setting up and maintaining the main
    window for the visualiser.

    start_gui() creates the main window can calls its main loop. It can be given a task
    that is called repeatedly at a set interval for as long as the program runs.

    stop_gui() kills the program gracefully.
"""

w = None
root = None
repeating_interval = 200
def start_gui(task=None):
    global w, root
    root = Tk()
    top = OpenSAW_Visualiser(root)
    w = top
    if task:
        root.after(0, repeating_task, task)
    root.mainloop()

def repeating_task(task):
    global root, repeating_interval, w
    if not w.pause.get():
        task()
    else:
        w.update_status("Visualiser is Paused.")
    root.after(repeating_interval, repeating_task, task)

def stop_gui():
    global root
    root.destroy()
    root = None

def askurl():
    new_url = tsd.askstring("OpenSAW URL", "OpenSAW server URL:", initialvalue=requester.get_mainurl())
    if new_url == None:
        return
    print "New URL: "+new_url
    requester.set_mainurl(new_url)

def get_root():
    global root
    return root

def get_w():
    global w
    return w

class OpenSAW_Visualiser:
    def __init__(self, top=None):
        #Initials
        _bgcolor = '#d9d9d9'  # X11 color: 'gray85'
        _fgcolor = '#000000'  # X11 color: 'black'
        _compcolor = '#d9d9d9' # X11 color: 'gray85'
        _ana1color = '#d9d9d9' # X11 color: 'gray85' 
        _ana2color = '#d9d9d9' # X11 color: 'gray85' 
        self.style = ttk.Style()
        self.style.theme_use('alt')
        if sys.platform == "win32":     #Special case for windows
            self.style.theme_use('winnative')
        self.style.configure('.',background=_bgcolor)
        self.style.configure('.',foreground=_fgcolor)
        self.style.configure('.',font="TkDefaultFont")
        self.style.map('.',background=
            [('selected', _compcolor), ('active',_ana2color)])

        #Main Window
        top.geometry("1024x768+100+100")
        top.title("OpenSAW Visualiser")
        top.configure(highlightcolor="black")

        #Menu Bar
        self.menubar = Menu(top,font="TkMenuFont",bg=_bgcolor,fg=_fgcolor, relief=RAISED)
        top.configure(menu = self.menubar)

        #Menu Bar Commands

        self.menubar.add_command(
                activebackground=_bgcolor,
                activeforeground="#000000",
                background=_bgcolor,
                command=stop_gui,
                font="TkMenuFont",
                foreground="#000000",
                label="Quit")
        self.menubar.add_command(
                activebackground=_bgcolor,
                activeforeground="#000000",
                background=_bgcolor,
                command=askurl,
                font="TkMenuFont",
                foreground="#000000",
                label="Change Server URL")
        
        self.menubar.add_separator()
        self.pause=BooleanVar()
        self.menubar.add_checkbutton(variable=self.pause,
                activebackground=_bgcolor,
                activeforeground="#000000",
                background=_bgcolor,
                font="TkMenuFont",
                foreground="#000000",
                label="Pause Updating")

        #Main View Setup
        top.columnconfigure(0, weight=0)
        top.columnconfigure(1, weight=2)
        top.rowconfigure(0, weight=0)
        top.rowconfigure(1, weight=2)
        top.rowconfigure(2, weight=0)

        #Left Side Statistics
        self.dia_overview_time = Dia_Circle(top, mode=0, bg='#FFFFFF')
        self.dia_overview_time.grid(sticky=W+E+N+S)

        self.lbl_overview_stat_text = StringVar()
        self.lbl_overview_stat = Label(top, justify=LEFT, relief=SUNKEN,
                                       textvariable=self.lbl_overview_stat_text,
                                       anchor=N, pady=10)
        self.lbl_overview_stat.grid(sticky=W+E+N+S)
        
        #Bottom Status Label
        self.lbl_status_text = StringVar()
        self.lbl_status = Label(top, anchor=W, relief=SUNKEN, bd=1, padx=10,
                                textvariable=self.lbl_status_text)
        self.update_status("Initializing")
        self.lbl_status.grid(row=2, column=0, columnspan=2, ipadx=20, ipady=5, sticky=W+E)

        #Main Notebook
        self.style.configure('TNotebook.Tab', background=_bgcolor)
        self.style.configure('TNotebook.Tab', foreground=_fgcolor)
        self.style.map('TNotebook.Tab', background=
            [('selected', _compcolor), ('active',_ana2color)])
        self.not_main = ttk.Notebook(top)
        self.not_main.grid(row=0,column=1,rowspan=2,sticky=W+E+N+S)
        self.not_main.configure(takefocus="")
        
        self.tab_tracegraph = ttk.Frame(self.not_main)
        self.not_main.add(self.tab_tracegraph, padding=3)
        self.not_main.tab(0, text="Trace Graph",underline="-1",)
        
        self.tab_coverage = ttk.Frame(self.not_main)
        self.not_main.add(self.tab_coverage, padding=3)
        self.not_main.tab(1, text="Coverage",underline="-1",)
        
        self.tab_crash = ttk.Frame(self.not_main)
        self.not_main.add(self.tab_crash, padding=3)
        self.not_main.tab(2, text="Crash Statistics",underline="-1",)

        #Trace Graph View
        self.tab_tracegraph.columnconfigure(0, weight=1)
        self.tab_tracegraph.columnconfigure(1, weight=0)
        self.tab_tracegraph.rowconfigure(0,weight=1)
        
        self.dia_tracegraph = Dia_Tree(self.tab_tracegraph, relief=SUNKEN,
                                       background="#FFFFFF")
        self.dia_tracegraph.grid(row=0, column=0, sticky=W+E+N+S)

        self.dia_tracegraph_legend = Dia_Tree_Legend(self.tab_tracegraph, relief=SUNKEN,
                                                     background="#FFFFFF")
        self.dia_tracegraph_legend.grid(row=0, column=1, sticky=N+S)

        #Code Coverage Graph View
        self.tab_coverage.columnconfigure(0, weight=1)
        self.tab_coverage.rowconfigure(0,weight=1)

        self.dia_covplot = Dia_Plot(self.tab_coverage, self.dia_tracegraph, relief=SUNKEN,
                                    background="#FFFFFF")
        self.dia_covplot.grid(sticky=W+E+N+S)

        #Crash Statistics View
        self.tab_crash.columnconfigure(0, weight=1)
        self.tab_crash.rowconfigure(0, weight=1)
        self.dia_crash = Dia_Circle(self.tab_crash, mode=1, bg="#FFFFFF")
        self.dia_crash.grid(sticky=W+E+N+S)

    #Puts the input string into the statistics label directly
    def update_statistics(self, n ):
        self.lbl_overview_stat_text.set(n)

    #Formats statistics label nicely with data from OpenSAW JSON statistics
    def update_statistics_formatted(self, d):
        ret = "Finished:\t\t\t"+str(d['done'])+"\n"
        ret += "Crashes:\t\t\t%d\n" % len(d['crashes'])
        ret += "Working Time:\t\t%.2fs\n" % d['time']
        ret += "Time since new data:\t%.2fs\n" % d['time_last_thread']
        ret += "\n"
        cov = (max(d['coverage']['visited']['blocks'][-1],0.0)/(2*max(float(d['coverage']['found']['blocks']),1.0)) +
                max(d['coverage']['visited']['branches'][-1],0.0)/(2*max(float(d['coverage']['found']['branches']),1.0)))
        ret += "Total Coverage:\t\t%.1f" % (cov*100) + "% \n"
        ret += "Found Blocks:\t\t%d\n" % d['coverage']['found']['blocks']
        ret += "Visited Blocks:\t\t%d\n" % d['coverage']['visited']['blocks'][-1]
        ret += "Found Branches:\t\t%d\n" % d['coverage']['found']['branches']
        ret += "Visited Branches:\t\t%d\n" % d['coverage']['visited']['branches'][-1]
        ret += "\n"
        ret += "Time Spent in Subsystems:\n"
        ret += "IL Tool:\n"
        ret += " - Measurements:\t\t%d\n" % d['performance']['il_tool']['measurements']
        ret += " - Average:\t\t%.2fs\n" % d['performance']['il_tool']['average']
        ret += " - Total:\t\t\t%.2fs\n" % d['performance']['il_tool']['total']
        ret += "Pin:\n"
        ret += " - Measurements:\t\t%d\n" % d['performance']['pin']['measurements']
        ret += " - Average:\t\t%.2fs\n" % d['performance']['pin']['average']
        ret += " - Total:\t\t\t%.2fs\n" % d['performance']['pin']['total']
        ret += "Solver:\n"
        ret += " - Measurements:\t\t%d\n" % d['performance']['solver']['measurements']
        ret += " - Average:\t\t%.2fs\n" % d['performance']['solver']['average']
        ret += " - Total:\t\t\t%.2fs\n" % d['performance']['solver']['total']

        self.update_statistics(ret)        

    #Paints the tracegraph anew
    def paint_tracegraph(self):
        self.dia_tracegraph.paint_tree()

    #Adds data to the tracegraph
    def set_data_tracegraph(self, nodes, links):
        self.dia_tracegraph.import_tree(nodes, links)

    #Marks crashes on both the tracegraph and the coverage chart
    def mark_crash(self, name, color, filename, time, block, trace):
        nodes = self.dia_tracegraph.find_node(block, trace)
        for n in nodes:
            self.dia_tracegraph.mark_crash(name, color, filename, time, n)
        if len(nodes)>0:
            self.dia_covplot.mark_crash(name, color, filename, time, nodes[0])

    #Updates the status ticker
    def update_status(self, n):
        self.lbl_status_text.set("Status: "+n)

    #Paints the time chart
    def paint_timechart(self):
        self.dia_overview_time.paint()

    #Adds data to the time chart
    def set_data_timechart(self, name, value, color="#FF0000"):
        self.dia_overview_time.set_data(name, value, color)

    #Paints the coverage chart
    def paint_covplot(self, time):
        self.dia_covplot.paint_plot(time)

    #Adds data to the coverage chart
    def set_data_covplot(self, vis, fnd):
        self.dia_covplot.import_plot(vis, fnd)

    #Paints the crash chart
    def paint_crash(self):
        self.dia_crash.paint()

    #Adds data to the crash chart
    def set_data_crash(self, name, value, color="#FF0000"):
        self.dia_crash.set_data(name, value, color)

    #Clears the crash chart data
    def clear_data_crash(self):
        self.dia_crash.clear_data()
        self.dia_covplot.clear_crash()
