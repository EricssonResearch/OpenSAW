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

import time

"""
    The Dia_Tree widget renders an interactive tree view of the tracegraph published by
    OpenSAW through JSON.

    Create as a normal Tkinter Canvas.

    After creation, data can be imported from OpenSAW JSON dumps with .import_tree().
    After data has been imported, a call to .paint_tree() must be made for changes to be visible.
"""

class Dia_Tree(Canvas):

    def __init__(self, parent, **kwd):
        Canvas.__init__(self, parent, kwd)
        self.root = None            #The root node of the tree
        self.highlight = None       #A node chosen to be highlighted and have info shown.
        self.graphics = {}          #A <canvas graphics id>:<Tree_Node> mapping to find which
                                    #Node has been clicked.
        self.bind("<ButtonPress-1>", self.on_click)
        self.bind("<B1-Motion>", self.scroll_move)
        #Linux Scrollwheel Bind
        self.bind("<Button-4>", self.zoomerI)
        self.bind("<Button-5>", self.zoomerO)
        #Windows Scrollwheel Bind
        self.bind("<MouseWheel>",self.zoomer)

    def on_click(self,event):
        #Handle dragging the canvas
        self.scroll_start(event)
        
        #Handle clicking tree nodes
        x = self.canvasx(event.x)
        y = self.canvasy(event.y)

        r = self.find_overlapping(x-1,y-1,x+1,y+1)
        if len(r)>0:
            for g in r:
                if g in self.graphics:
                    self.graphics[g].on_click(self)
                    break

        self.paint_infobox()

    def scroll_start(self, event):
        self.scan_mark(event.x, event.y)

    def scroll_move(self, event):
        self.scan_dragto(event.x, event.y, gain=1)

    #Windows zooming
    def zoomer(self,event):
        if (event.delta > 0):
            self.scale("all", self.canvasx(event.x), self.canvasy(event.y), 1.1, 1.1)
        elif (event.delta < 0):
            self.scale("all", self.canvasx(event.x), self.canvasy(event.y), 0.9, 0.9)
        
        self.paint_infobox()
        self.update_scrollregion()

    #Linux zooming
    def zoomerI(self,event):
        self.scale("all", self.canvasx(event.x), self.canvasy(event.y), 1.1, 1.1)
        self.paint_infobox()
        self.update_scrollregion()
        
    def zoomerO(self,event):
        self.scale("all", self.canvasx(event.x), self.canvasy(event.y), 0.9, 0.9)
        self.paint_infobox()
        self.update_scrollregion()

    #Recursively search for a node based on its id.
    #If a trace (a list of ids) is supplied, it will try to follow it as a path through
    #the tree, but return nothing if the path isn't valid.
    def find_node(self, name, trace=None):
        if self.root:
            ret = self.root.find_node(name, trace)
            return ret
        else:
            return []

    def mark_crash(self, name, color, filename, time, node):
        for crash in node.crashes: 
            if crash['filename'] == filename: #Crash already existed, just return.
                return

        node.crashes.append({'name':name, 'filename':filename, 'time':time})

        if len(node.crashes)>1:
            #Multiple crashes at the same node. Mark it as special.
            node.color = "#FF0000"
        else:
            node.color = color
        #Update the graphics immediatly, since painting the entire tree again is costly
        self.itemconfig(node.graphic_id, fill=node.color, width=2, outline="#FF0000")

    def update_scrollregion(self):
        b = self.bbox(ALL)
        if b == None:
            return
        b = (b[0]-20,b[1]-20,b[2]+20,b[3]+20)
        self.configure(scrollregion = b)

    #Expects inputs in the following format:
    #nodes_in = [{'id':'9999999_0',     -- An id string. Ending in a _0 or _1
    #             'group':X,            -- An integer group id
    #             'ins':Y}, ...]        -- An integer instruction count
    #
    #links_in = [{'source':'9999999_0', -- The id string of the source node
    #             'target':'1111111_1', -- The id string of the target node
    #             'value':X},...]       -- An unused value
    def import_tree(self, nodes_in, links_in):
        root_info = nodes_in[0]
        root_info['id'] = root_info['id'][0:-2] #Trim off the '_0' or '_1'.
                                                #This is to make it easier to find nodes
                                                #that have caused crashes.
                                                #TODO: Change find_node so it can ignore this tag instead
        self.root = make_node(root_info)

        #TODO: This starts from scratch every time.
        #Could try making it only update for new nodes

        #Reformat the node list
        nodes = {}
        for n in nodes_in:
            n['id'] = n['id'][0:-2]             #Trims off the '_0' or '_1'. See above.
            nodes[n['id']] = n

        #Reformat the link list
        links = {}
        for l in links_in:
            l['source'] = l['source'][0:-2]     #Trims off the '_0' or '_1'. See above.
            l['target'] = l['target'][0:-2]
            link_list = links.get(l['source'], [])
            links[l['source']] = link_list+[l]  #Create a new data structure indexed by source,
                                                #which has all the source's outbound links in a list

        #Start the recursive import process
        self.root.import_node(nodes, links, -1, {})

        #Calculate Locations
        self.root.paint_initial_x(0,0)
        self.root.paint_final_positions()

    #Print a text view of the tree to console.
    def print_tree(self):
        if self.root == None:
            print "-+Empty Tree+-"
        else:
            self.root.print_tree()

    #Paints the tree
    def paint_tree(self):
        #Clear the canvas
        self.delete(ALL)
        self.graphics = {}

        #TODO: This could be done without clearing the canvas.
        
        if self.root:
            ret = self.root.paint_tree(self)
            self.tag_lower("LINE") #Move all lines to the bottom.
            self.update_scrollregion()
            #Roughly center the view.
            self.xview_moveto(0.4)
            self.yview_moveto(0.0)

    def pick_highlight(self, node):
        self.highlight = node
        self.paint_infobox()

    #Paints a box of information about a highlighted node.
    #Also clears away the box if no node is highlighted.
    def paint_infobox(self):
        self.delete("INFOBOX")
        self.delete("HIGHLIGHT")
        if(self.highlight == None):
            return

        #Establish geometry
        node = self.highlight
        coords = self.coords(node.graphic_id)
        if coords == []:
            #The tree might have been rebuilt while this was called, if so, we stop.
            return
        nx, ny, nxm, nym = coords
        half_size = (nxm-nx)/2
        x = nxm+5   #Place the box southeast of the node.
        y = nym+15
        color = "#EEDF3F"
        
        txt = "Block ID: "+node.id
        self.create_text(x,y, anchor = W, text = txt, tags="INFOBOX")

        y += 14
        txt = "Instructions: "+str(node.ins)
        self.create_text(x,y, anchor = W, text = txt, tags="INFOBOX")

        y += 14
        txt = "Group: "+str(node.group)
        self.create_text(x,y, anchor = W, text = txt, tags="INFOBOX")

        #Highlight the node and its path back to root
        self.paint_highlight(node)
        self.tag_lower("HIGHLIGHT")

        #Special message for root.
        if node == self.root:
            y+= 24
            txt = "This block is the root block!"
            self.create_text(x,y, anchor = W, text = txt, tags="INFOBOX")

        #Special message and arrow for linkbacks.
        if node.is_linkback():
            y+= 24
            txt = "This block links back to an earlier block!"
            self.create_text(x,y, anchor = W, text = txt, tags="INFOBOX")

            tx, ty, _, _ = self.coords(node.real.graphic_id)
            
            self.create_line(nx+half_size, ny+half_size, tx+half_size, ty+half_size,
                             tags="HIGHLIGHT", arrow="last", arrowshape="16 20 6",
                             width = 3, fill="#FAA41A")

        #Special message if the node contains crashes.
        if len(node.crashes)>0:
            color = "#F15854"
            y += 24
            if len(node.crashes)==1:
                txt = "There was a crash at this block!"
            else:
                txt = "There were multiple crashes at this block!"
            self.create_text(x,y, anchor = W, text = txt, tags="INFOBOX")

            for crash in node.crashes:
                y += 24
                txt = "Crash Type: "+crash['name']
                self.create_text(x,y, anchor = W, text = txt, tags="INFOBOX")
                y += 14
                txt = "Input File: "+crash['filename']
                self.create_text(x,y, anchor = W, text = txt, tags="INFOBOX")
                y += 14
                txt = "Time Discovered: {:.1f}".format(crash['time'])
                self.create_text(x,y, anchor = W, text = txt, tags="INFOBOX")

        #Draw a box behind all the information.
        lb = self.bbox("INFOBOX")
        lb = (lb[0]-5, lb[1]-5, lb[2]+5, lb[3]+5)
        temp = self.create_rectangle(lb, fill=color)
        self.tag_raise("INFOBOX")
        self.addtag_withtag("INFOBOX", temp) #Tag the box so it gets removed properly.
        self.update_scrollregion()

    #Paint a path from a node to root through its parents.
    def paint_highlight(self, node):
        x,y,mx,my = self.coords(node.graphic_id)
        half_size = (mx-x)/2
        color = "#5DA5DA"

        self.create_oval(x-3, y-3, mx+3, my+3, tags="HIGHLIGHT",
                         outline=color, fill=color)

        if node.parent:
            tx, ty, txm, tym = self.coords(node.parent.graphic_id)
            self.create_line(x+half_size, y, tx+half_size, tym, tags="HIGHLIGHT",
                             fill=color, width=5)
            self.paint_highlight(node.parent)

#Helper function for making nodes.
def make_node(d):
    return Tree_Node(d['id'], d['ins'], d['group'])

#A node in the tree and all its support methods.
class Tree_Node():

    def __init__(self, i, ins, group):
        self.id = i
        self.ins = ins
        self.group = group
        self.parent = None
        self.children = {}
        self.color = "#00FF00"
        self.x = 0.0            #Logical coordinates for calculating placement
        self.y = 0.0
        self.mod = 0.0          #Modifier to the X position of all children
        self.canvas_x = 0.0     #Canvas coordinates calculated from logical coordinates
        self.canvas_y = 0.0     #Only correct before panning or zooming the canvas view
        self.graphic_id = 0     #The canvas graphic id of this node's oval
        self.crashes = []       #A list of crashes that have been traced to this node

    def set_parent(self, parent):
        self.parent = parent

    def set_child(self, child):
        self.children[child.id] = child

    def remove_child(self, child):
        del self.children[child.id]

    def is_linkback(self):
        return False

    #Recursively creates the tree from input data.
    #maxDepth can be used to limit the recursion, or set to -1 to go to any depth.
    #parents should be initialized to an empty dictionary when starting this recursion.
    def import_node(self, nodes, links, maxDepth, parents):
        l = links.get(self.id, [])
        for link in l:
            n = make_node(nodes[link['target']])

            if n.id in parents:
                #This node exists in the line of parents back to root.
                #Drawing it as normal would create an infinite loop
                #Instead, mark it as a special linkback node to show it loops back.
                n = Tree_Linkback(parents[n.id])
                n.set_parent(self)
                self.set_child(n)
            else:
                n.set_parent(self)
                self.set_child(n)
                if maxDepth != 0: #Check if maxdepth has been rached.
                    p = dict(parents)
                    p[self.id] = self
                    n.import_node(nodes, links, maxDepth-1, p)
                else:
                    return #MaxDepth was reached

    def __str__(self):
        return "<id: "+self.id+">"

    def find_node(self, name, trace):
        ret = []

        if trace == None: #No trace to follow, perform a complete depth-first search of the tree
            for child in self.children.values():
                ret += child.find_node(name, trace)

            if name == self.id:
                ret += [self]

            return ret
        else:   #There is a trace to follow, where each element should be the ID of a node in the chain.
            if len(trace)>0:
                target = trace.pop(0)
                if target in self.children:
                    return self.children[target].find_node(name,trace)
                else:
                    return [] #Couldn't follow the trace
            else:
                if self.id == name:
                    return [self]
                else:
                    return [] #Followed the trace, but the last node wasn't a match
                


    #Recursively prints the tree.
    def print_tree(self, depth=0):
        print " |"*depth+"-+ "+self.id+" X: "+str(self.x)+"+"+str(self.mod) + " Y: "+str(self.y)
        for v in self.children.values():
            v.print_tree(depth+1)

    #Recursively paints the tree. Depth First
    def paint_tree(self, canvas):
        ret = 1

        #Draw lines to children.
        for child in self.children.values():
            canvas.create_line(self.canvas_x, self.canvas_y+5, child.canvas_x, child.canvas_y-5, tags="LINE")
            ret += child.paint_tree(canvas)

        #Draw this node.
        self.graphic_id = canvas.create_oval(self.canvas_x-5,self.canvas_y-5,self.canvas_x+5,self.canvas_y+5,
                                             fill=self.color, tags="NODE")
        canvas.graphics[self.graphic_id] = self        
        return ret #Return the number of nodes painted, 

    #When clicked, toggle whether this is the highlight node.
    def on_click(self, canvas):
        if canvas.highlight == self:
            canvas.highlight = None
        else:
            canvas.highlight = self

    def paint_initial_x(self, child_nr, depth):
        #Initialize Children
        index = 0
        for child in self.children.values():
            child.paint_initial_x(index, depth+1)
            index += 1

        self.y = depth
        
        #If No Children, place self one step to the right of the previous child, if any
        if len(self.children)==0:
            if child_nr == 0:
                self.x = 0.0
            else:
                self.x = self.parent.children.values()[child_nr-1].x +1
        #If one child
        elif len(self.children)==1: #One child, place self over child
            if child_nr == 0:
                self.x = self.children.values()[0].x
            else:
                self.x = self.parent.children.values()[child_nr-1].x +1
                self.mod = self.x - self.children.values()[0].x
        else:                       #Multiple children, place self in center
            children = self.children.values()
            mid = (children[0].x + children[-1].x)/2.0
            if child_nr == 0:
                self.x = mid
            else:
                self.x = self.parent.children.values()[child_nr-1].x +1
                self.mod = self.x - mid
        
        if len(self.children) > 0 and child_nr > 0:
            #There could be conflicts with siblings, check.
            self.paint_check_conflicts(child_nr)

    #Checks conflicts between the self and all siblings to its left
    def paint_check_conflicts(self, child_nr):
        shift = 0.0
        mindist = 1.0 #Minimum horizontal distance between nodes, in node-widths.

        nodeContour = self.paint_get_left_contour(0, 0, {})
        
        for i in xrange(0, child_nr): #Check all lower indexed siblings
            sibling = self.parent.children.values()[i]
            if sibling == None:
                continue #Sibling was Null? Just keep going.

            siblingContour = sibling.paint_get_right_contour(0, 0, {})
            
            #Compare the right contour of the sibling and the left contour of this node
            for j in xrange(0, min(len(nodeContour), len(siblingContour))):
                dist = nodeContour[j] - siblingContour[j]
                if (dist + shift) < mindist: #Too close. Calculate a proper shift
                    shift = max(mindist - dist, shift)

        if shift > 0: #A collision was detected, move this node and subtree to the right.
            self.x += shift
            self.mod += shift

    def paint_get_left_contour(self, depth, modSum, ret):
        
        for child in self.children.values():
            ret = child.paint_get_left_contour(depth+1, modSum+self.mod, ret)

        val = ret.get(depth)
        if val == None:
            ret[depth] = self.x + modSum
        else:
            ret[depth] = min(ret[depth], self.x + modSum)

        return ret

    def paint_get_right_contour(self, depth, modSum, ret):
        
        for child in self.children.values():
            ret = child.paint_get_right_contour(depth+1, modSum+self.mod, ret)

        val = ret.get(depth)
        if val == None:
            ret[depth] = self.x + modSum
        else:
            ret[depth] = max(ret[depth], self.x + modSum)

        return ret

    #Apply calculated mod values to the children of each node, and set canvas coordinates
    def paint_final_positions(self, modSum = 0):
        self.x += modSum
        modSum += self.mod

        self.canvas_x = self.x*15 #Translate from logical coordinates to canvas pixel coordinates
        self.canvas_y = self.y*15

        for child in self.children.values():
            child.paint_final_positions(modSum)

#Special Tree_Node for nodes that loop back to an earlier position in the tree.
#These nodes never have children, but track which is the 'real' node that they link back to
class Tree_Linkback(Tree_Node):

    def __init__(self, real):
        Tree_Node.__init__(self, real.id, real.ins, real.group)
        self.real = real
        self.color = "#FFFF00"

    def is_linkback(self):
        return True

    def print_tree(self, depth=0):
        print " |"*depth+"-< "+self.id+" ::- Linkback"

    def paint_tree(self, canvas):
        self.graphic_id = canvas.create_oval(self.canvas_x-5,self.canvas_y-5,self.canvas_x+5,self.canvas_y+5,
                                             fill=self.color, tags="NODE")
        canvas.graphics[self.graphic_id] = self
        return 1

#Widget which draws a legend for the tree view.
class Dia_Tree_Legend(Canvas):

    def __init__(self, parent, **kwd):
        Canvas.__init__(self, parent, kwd)
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

        x = 20
        y = 30

        color = "#00FF00"
        txt = "Code Block"
        self.create_oval(x-5,y-5,x+5,y+5, fill=color)
        temp = self.create_text(x+10, y-10, anchor=NW, text=txt, width=105)
        _, ty, _, by = self.bbox(temp)
        y += max(15, by-ty+5)

        color = "#FFFF00"
        txt = "Code Block which forms a loop to an earlier block"
        self.create_oval(x-5,y-5,x+5,y+5, fill=color)
        temp = self.create_text(x+10, y-10, anchor=NW, text=txt, width=105)
        _, ty, _, by = self.bbox(temp)
        y += max(15, by-ty+5)
        
        color = "#FF0000"
        txt = "Code Block with multiple crashes"
        self.create_oval(x-5,y-5,x+5,y+5, fill=color, outline="#FF0000", width=2)
        temp = self.create_text(x+10, y-10, anchor=NW, text=txt, width=105)
        _, ty, _, by = self.bbox(temp)

        for name, color in crash_colors.values():
            y += max(15, by-ty+5)
            txt = "Code Block with a "+name+" crash"
            self.create_oval(x-5,y-5,x+5,y+5, fill=color, outline="#FF0000", width=2)
            temp = self.create_text(x+10, y-10, anchor=NW, text=txt, width=105)
            _, ty, _, by = self.bbox(temp)

        _, _, w, _ = self.bbox(ALL)
        self.config(width=w+10)

