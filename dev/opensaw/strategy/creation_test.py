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
# Just grab a few Strategies
import opensaw.strategy.strategies as strats
from opensaw.strategy.creation import from_string


def test_from_string():
    # Empty or invalid Strategies
    assert from_string("") is None
    assert from_string("_") is None

    # Plain Strategies
    assert isinstance(from_string("i"), strats.identity.Identity)

    # Parallel and Serial Strategies
    assert isinstance(from_string("i|i"), strats.parallel.Parallel)
    assert isinstance(from_string("ii"), strats.serial.Serial)
    assert isinstance(from_string("ii|i"), strats.parallel.Parallel)

    # Error handling
    assert isinstance(from_string("|||i|"), strats.identity.Identity)
