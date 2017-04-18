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
Strategy Creation
=================

Instead of constructing Strategies manually they can be
generated from a string, which is useful when reading them
as command-line arguments.
"""

# Locals
# We import all strategies from the [[strategies]] module.
from strategies import identity, xnr, anr, aenr, nnf, generational, rnr, parallel, serial

# Strategy catalogue
# Each strategy gets its own identifier, which is used when looking
# it up in the catalogue.

def get_catalogue():
    return {
    'i': identity.Identity,
    'b': xnr.XNR,
    'd': anr.ANR,
    'e': aenr.AENR,
    'f': nnf.NNF,
    'g': generational.Generational,
    'h': rnr.RNR,
    }


# These two functions below were nearly identical.
# The `compositional_strategy` function is used
# to derive them.
def compositional_strategy(Strategy):
    def composition_func(strat_list):
        strat_list = filter(None, strat_list)

        if not strat_list:
            return None
        elif len(strat_list) == 1:
            return strat_list[0]
        else:
            return Strategy(strat_list)

    return composition_func




def from_string(string):
    """
    Creates a strategy from a string.

        "g" -> Generational()
        "i" -> Identity()

        "gi" -> Serial([Generational(), Identity()])
        "g|i" -> Parallel([Generational(), Identity()])
    """
    from_serial_comp = compositional_strategy(serial.Serial)
    from_parallel_comp = compositional_strategy(parallel.Parallel)
    parallel_strategies = []

    for sub_strategies in string.split("|"):
        serial_strategies = []

        for strategy_id in sub_strategies:
            if strategy_id not in get_catalogue():
                return None
            else:
                serial_strategies.append(get_catalogue()[strategy_id]())

        parallel_strategies.append(from_serial_comp(serial_strategies))

    return from_parallel_comp(parallel_strategies)
