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
Module for strategy API and related functions
"""

# ===============================================================================
#    Strategy API class
# ===============================================================================


class Base(object):
    """
    Strategy API class. Base class for all strategies
    """
    def __init__(self):
        pass

    # PIN wrapper callbacks
    def handlePINInitInput(self, input_job):
        """
        Handle initial input job C{input_job}.
        This callback is to be used by the PIN wrapper in case the framework is
        run with an initial input. May be called multiple times if multiple
        initial inputs are supplied.

        @param input_job: initial input job
        @type input_job: utils.jobs.InputJob
        """
        pass

    def handlePINNewInput(self, input_job):
        """
        Handle the new input job C{input_job} obtained from the input
        job queue.
        This callback is to be used by the PIN wrapper upon receiving a new
        input job from the BAP wrapper.

        @param input_job: received input job
        @type input_job: utils.jobs.InputJob
        """
        pass

    def handlePINNewTrace(self, input_job, trace_job):
        """
        Handle the new trace job C{trace_job} obtained by running the target
        program on the given input job C{input_job}.
        This callback is to be used by the PIN wrapper upon generation of
        a new IL trace corresponding to a run with a specific input.
        The default behaviour is to copy all the data attributes.
        Must return False if the trace_job should not be sent to BAP.

        @param input_job: input job
        @type input_job: utils.jobs.InputJob

        @param trace_job: trace job
        @type trace_job: utils.jobs.TraceJob

        @returns False if the trace should be ignored
        and not handled by BAP
        """
        for k in input_job:
            trace_job[k] = input_job[k]

    # BAP wrapper callbacks
    def handleBAPNewTrace(self, trace_job):
        """
        Handle the new trace job C{trace_job} obtained from the trace
        job queue.
        This callback is to be used by the BAP wrapper upon receiving a new
        trace job from the PIN wrapper.

        @param trace_job: received trace job
        @type trace_job: utils.jobs.TraceJob
        """
        pass

    def getNodes(self, tracegraph, trace_path):
        """
        Compute a list of pairs tracegraph (edges, nodes) from the given graph C{tracegraph}.
        The optional C{trace_path} parameter represents the path in the
        tracegraph corresponding to the last trace used to update the tracegraph.

        @param tracegraph: the current tracegraph
        @type tracegraph: tracegraph.Graph

        @param trace_path: the list of pairs (edge, node) in the given tracegraph
        corresponding to the last trace used for update
        @type trace_path: [(tracegraph.Edge, tracegraph.Node)]

        @rtype: [(tracegraph.Edge, tracegraph.Node)]

        @post: Each pair (e, n) in the return list is such that
        the bbl n can be obtained from the trace of e at the
        position of e
        """
        raise NotImplementedError()

    def handleBAPNewInput(self, trace_job, tracegraph, tracegraph_edge, tracegraph_node, input_job=None):
        """
        Handle the new input job C{input_job} (if not None) obtained
        by running BAP and STP on the given trace job C{trace_job} and
        for triggering the unexplored branch of the tracegraph node C{tracegraph_node}
        given the tracegraph edge C{tracegraph_edge}.
        This callback is to be used by the BAP wrapper upon generation of
        a new input following the analysis of a given trace and for a given
        tracegraph_node.
        A value None on the input_job should be regarded as a failure (for
        example when the constraint solver is unable to provide an answer).
        The default behaviour is to copy all the data attributes.
        This function is only called once for each unique input.
        Must return False if the input job should be discarded.

        @param trace_job: trace job
        @type trace_job: utils.jobs.TraceJob

        @param tracegraph: the current tracegraph
        @type tracegraph: tracegraph.Graph

        @param tracegraph_edge: one of the chosen tracegraph edges
        @type tracegraph_edge: tracegraph.Edge

        @param tracegraph_node: one of the chosen tracegraph nodes
        @type tracegraph_node: tracegraph.Node

        @param input_job: input job
        @type input_job: utils.jobs.InputJob

        @pre: C{tracegraph_node} represent a BBL that can be obtained from the
        trace of C{tracegraph_edge} at the position of C{tracegraph_edge}

        @returns False if the input should be ignored
        and not handled by PIN
        """
        pass
