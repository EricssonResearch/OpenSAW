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

import requester as req

import win_main as win

from dia_tree import *

"""
    The Visualiser module is responsible for starting the main window and then
    fetching and updating data for the widgets in the main window.

    start_visualiser() starts the entire program.
"""

counter = 1
last_len = -1
def task_update():
    global counter, last_len
    w = win.get_w()
    counter = counter + 1

    s = req.get_statistics()
    if s == None:
        w.update_status("Visualiser is Disconnected.")
        return
    else:
        w.update_statistics_formatted(s)
        if s['done']:
            w.update_status("OpenSAW has finished running.")
        else:
            w.update_status("OpenSAW is running.")
        update_timechart(w, s['performance'])
        w.set_data_covplot(s['coverage']['visited'], s['coverage']['found'])
        w.paint_covplot(s['time'])
        update_crash(w, s['crashes'])


    if counter%10==0: #The tracegraph updates are infrequent, so no need to check as often.
        t = req.get_tracegraph()
        if t == None:
            pass
        else:
            new_len = len(t['links'])
            if new_len == last_len:
                #Updating the tracegraph is costly, so only do it if the data has changed
                pass
            else:
                print new_len
                w.set_data_tracegraph(t['nodes'], t['links'])
                last_len = new_len
                w.paint_tracegraph()

time_colors = {'solver':"#00FF00",
          'pin':'#00FFFF',
          'il_tool':'#0000FF'}

def update_timechart(w, s):
    for name in s.keys():
        w.set_data_timechart(name, s[name]['total'], time_colors.get(name, "#FF0000"))
        #Paints elements as red if they are unknown.
    w.paint_timechart()

crash_colors = {1:('SIGHUP',"#5d5d5d"),
                2:('SIGINT',"#5da5da"),
                3:('SIGQUIT',"#faa43a"),
                4:('SIGILL',"#603d68"),
                5:('SIGTRAP',"#f17cb0"),
                6:('SIGABRT',"#b2912f"),
                7:('SIGEMT',"#b276b2"),
                8:('SIGFPE',"#ae5f3f"),
                9:('SIGKILL',"#f15854"),
                10:('SIGBUS',"#161616"),
                11:('SIGSEGV',"#afafaf")}

def update_crash(w, c):
    ret = {}
    w.clear_data_crash()
    for crash in c: #Counts all the signals and tries to mark them on the charts
        signal = crash['signal']
        trace = crash['trace']
        time = float(crash['time'])
        filename = crash['file']
        block = trace[-1]
        name, color = crash_colors.get(signal, ("Unknown Signal", "#FF0000"))
        w.mark_crash(name, color, filename, time, block, trace)
        if not signal in ret.keys():
            ret[signal] = (1,[filename],[time])
        else:
            ret[signal] = (ret[signal][0]+1, ret[signal][1]+[filename], ret[signal][2]+[time])

    #After counting, puts all the data on the crash chart
    for signal in crash_colors:
        name,color = crash_colors.get(signal, ("Unknown Signal", "#FF0000"))
        
        w.set_data_crash(name, ret.get(signal, [0])[0], color)

    w.paint_crash()
    return ret

def start_visualiser():
    win.start_gui(task_update)

if __name__ == "__main__":
    start_visualiser()
