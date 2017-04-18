<!---
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
--->
Using and building search Strategies
====================================
OpenSAW comes with multiple search strategies that can be combined and extended. 
You can also develop your own search strategy that uses parts of existing strategies. 

## What is a strategy
In its simplest form a strategy is a script that selects branches that are of interest to explore.

Additionally a search strategy can decide if a newly generated input should be executed at all or override the `--ranking` parameter and decide what priority it should have in the work queue.
A search strategy can do the same for newly generated traces. That is, given a new trace it can decide if the trace should be analyzed and what priority it should have.

## Existing Strategies
We provide multiple strategies to give users an idea of what one may do. Here are descriptions of some of our strategies.
All strategies can be found under [`dev/opensaw/strategy/strategies`](../dev/opensaw/strategy/strategies)
### Identity Strategy
This is the most simple strategy that analyzes all branches in all traces
### New Nodes First Strategy
This strategy analyzes all branches in all traces but prioritizes nodes that have not been seen
before. This can be useful in combination with the `--limitTrace` flag that limits the number of
 analyzed branches per trace.
### Generational Strategy
This is an implementation of the search heuristic and ranking method described in the paper
"Automated Whitebox Fuzz Testing" by Patrice Godefroid, Michael Y. Levin and David Molnar

##Using Strategies
Strategies are used by supplying the `-s` or `--strategy` command line parameter to OpenSAW.
Currently the supported values and which strategy they run is:

    b: Explored Node Removal,
    d: Analyzed Node Removal,
    i: Identity Strategy 
    e: Analyzed Edge, Node pair Removal,
    f: New Nodes First,
    g: Generational,
    h: Redundant Node Removal,
    
One can supply multiple strategies such as `-s fb` to run strategies in serial order. 
It is also possible to run strategies in parallel  by using `-s f|b`

##Building your own strategy

### Small example
In this example we create a strategy that only analyzes (edge,node) tuples 
from a trace if the node only has a single exit edge in our trace graph.

We start by creating a new file in `opensaw/strategy/strategies` lets call this `singleedges.py`.
The file should contain a single class that extends the Base class. Thus we start the file with
```py
from opensaw.strategy.strategies.base import Base
class SingleEdges(Base):
```
To query the strategy about which branches to analyze OpenSAW calls the `getNodes` function.
 this takes two arguments, a list of (edge,node) tuples [a trace], and a trace graph. 
 What we want to do is iterate through the trace and check if the node has more than one exit edge.
 So intuitively we want to write.
```py
    def getNodes(self, tracegraph, trace_path):
        ret = []
        for (edge,node) in trace_path:
            if ????:
                ret.append((edge,node))
        return ret
```

To check what we can do with the tracegraph we look at [`dev/opensaw/utils/graph.py`](../dev/opensaw/utils/graph.py)
In this file we find the function `getSuccessors` that takes a single node as argument and returns a dictionary where the keys are
successor nodes and the values are the edge between the nodes. Thus for each entry in the dictionary there is one exit edge, and we can use the length of the returned value to see how many
exit edges a specific node has.

This mean sthat we end up with the final code for our strategy:
```py
from opensaw.strategy.strategies.base import Base
class SingleEdges(Base):
    def getNodes(self, tracegraph, trace_path):
        ret = []
        for (edge,node) in trace_path:
            if len(tracegraph.getSuccessors(node)) < 2:
                ret.append((edge,node))
        return ret
```

To be able use our strategy we need to make one more thing. And this is to define some way for OpenSAW to launch the strategy.
This is done by modifying the `dev/opensaw/strategy/creation.py` file.
In this file there is a function called `get_catalogue()` which we need to modify.
This function is trivial and returns a dictionary of the available strategies and their identifiers.
All we need to do is add the line
```py
    'q': strats.singleedges.SingleEdges,
```
and we are done!

Now we can use our strategy by running OpenSAW with the argument `-s q`

### Example strategy for usage in serial with others
Above we saw an example of how to create a strategy that only analyses branches where we only know of a single exit edge.
It's easy to realize that if there are branches that only have one possible exit edge, the strategy will analyze them each
time they are found in a trace.

In this example we build a strategy that only analyzes branches that have at most been analyzed an arbitrary number of times
(in our case five). 
This strategy can be combined with other strategies using the serial meta strategy described earlier.

The first thing we need to do is track how many times a branch has been analyzed. 
There are at least two choices on where to track this, either when a node is chosen
for analysis or after a node has been analysed. 
If it is done when a node is chosen for analysis, then we may never analyze the node.
This is because we may mark the node as chosen five times, while a following
serial strategy ignores the node for some reason.

If the choice is made after the branch has been analyzed, then we may analyze the branch
many times more than desired, as the getNodes function may run multiple times in different threads before
the returned branches are analyzed.

In our case we have chosen to increase the counter after analyzing a branch.
To do this we use the
    
    def handleBAPNewInput(self, trace_job, tracegraph, tracegraph_edge, tracegraph_node, input_job)
    
callback. This function is called each time a edge,node tuple selected for analysis has been processed.
As edge and node objects behave like dictionaries, we can add an arbitrary key (in this case `EXMOD2_COUNTER`)
to the node and use it later to filter out edge,node tuples from traces.

    def handleBAPNewInput(self, trace_job, tracegraph, tracegraph_edge, tracegraph_node, input_job):
        if 'EXMOD2_COUNTER' not in tracegraph_node:
            tracegraph_node['EXMOD2_COUNTER'] = 0
        tracegraph_node['EXMOD2_COUNTER'] += 1

One issue with this code is that handleBAPNewInput may be called from multiple threads simultaneously, causing the counter
not to increment correctly. Even though the race error causes no serious problems in this case, we'll use a lock to avoid the issue. 
First we create the lock in our constructor, and use the lock in handleBAPNewInput, resulting in the code
    
    import threading
    def __init__(self):
        Base.__init__(self)
        self.lock = threading.lock()
        
    def handleBAPNewInput(self, trace_job, tracegraph, tracegraph_edge, tracegraph_node, input_job):
        with self.lock:
            if 'EXMOD2_COUNTER' not in tracegraph_node:
                tracegraph_node['EXMOD2_COUNTER'] = 0
            tracegraph_node['EXMOD2_COUNTER'] += 1
In terms of locking, this is not optimal - we could have a global lock for counter initialization and local locks
for each counter, but for simplicity lets keep it as above.

Now we continue with filtering out branches that have been analyzed too many times.
From the previous example we know that we need to make getNodes filter out the branches, and we have a template for how to do this.
As you saw previously the template is:
```py
    def getNodes(self, tracegraph, trace_path):
        ret = []
        for (edge,node) in trace_path:
            if ????:
                ret.append((edge,node))
        return ret
```
In our case we need to check the added counter to our node. Note that if the branch has not been analyzed before,
then the node does not have our counter yet. Thus the condition we need to add is:

    if 'EXMOD2_COUNTER' not in node or node['EXMOD2_COUNTER'] < 5:
    
The final code for our strategy becomes:
```py
import threading

class MaxFiveTimes(Base):
    def __init__(self):
        Base.__init__(self)
        self.lock = threading.Lock()
        
    def handleBAPNewInput(self, trace_job, tracegraph, tracegraph_edge, tracegraph_node, input_job):
        with self.lock:
            if 'EXMOD2_COUNTER' not in tracegraph_node:
                tracegraph_node['EXMOD2_COUNTER'] = 0
            tracegraph_node['EXMOD2_COUNTER'] += 1
        
    def getNodes(self, tracegraph, trace_path):
        for (edge,node) in trace_path:
            if 'EXMOD2_COUNTER' not in node or node['EXMOD2_COUNTER'] < 5:
                yield (edge,node)
```
Note that we changed the use of a ret list and instead made getNodes use `yield`. This gives
our counter at least a chance to increment while iterating a single trace.


Remember to add it to `dev/opensaw/strategy/creation.py` file as mentioned above.
```py
    'm': strats.maxfivetimes.MaxFiveTimes,
```

Now to combine this strategy with the single-edge-nodes strategy above, we launch OpenSAW with the parameter
`-s qm`
the result is that only nodes returned by the single-edge-nodes strategy are passed in the `trace_path` to `getNodes()` of MaxFiveTimes,
letting the strategy filter out nodes that have been tested too many times.


### More generally
Nodes in our trace graph represent code blocks, and edges represent branches. A trace is a list of
the nodes that were visited during execution. 

The base class to work off can be found at [`dev/opensaw/strategy/strategies/base.py`](../dev/opensaw/strategy/strategies/base.py)

A strategy is given a trace in the form of a list of (edge,node) tuples and a trace graph and is 
expected to return a list (or generator) of (edge,node) tuples that should be analyzed. 
<!--- 
(This is not true anymore due to issues with keeping the whole history of all executed traces if supported)
Note that a strategy may return edges and nodes from the trace graph that were not included in the
trace that it was given. --->

The trace graph is built as described in the paper TODO: Reference paper
and the available functions can be seen in mainly [`dev/opensaw/utils/graph.py`](../dev/opensaw/utils/graph.py), but also in [`dev/opensaw/tracegraph/graph.py`](../dev/opensaw/tracegraph/graph.py)

Multiple callbacks are defined in OpenSAW to make it possible for strategies to decide which inputs, branches and traces are of interest.
Look at the base class to get descriptions of all of the possible callbacks.

One thing to note is that Edges, Nodes, Trace jobs and Input jobs all act as dictionaries. 
Strategies can modify and add values to these. For example the New nodes first marks seen nodes so that it can sort traces in an order where the new nodes actually are first.

To make a strategy recognizable by the `-s` argument you need to modify the [`dev/opensaw/strategy/creation.py`](../dev/opensaw/strategy/creation.py)
and add a identifier for your strategy and a link to the class that defines it.
This is done in the get_catalogue function at the start of the file. Make sure not to take an existing identifier.

To set the priority of a trace job or an input job, simply give the job.priority variable an integer
value. Jobs with higher values will be handled first.
 
