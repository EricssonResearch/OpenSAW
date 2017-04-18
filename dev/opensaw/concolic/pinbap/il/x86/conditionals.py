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
BAP IL conditionals and combinators.
"""

# Imports
from operator import __and__, __eq__, __not__, __or__, __xor__


class Condition(object):
    """An IL Condition."""
    def is_sat(self, register, other): raise NotImplementedError()

    def __str__(self): raise NotImplementedError()

    def __and__(self, other):
        """
        A Condition and another becomes a stricter Condition.

            >>> a, b = Bit("a", 1), Bit("b", 2)
            >>> print a & b
            (a & b)
        """
        if isinstance(self, Not):
            if isinstance(other, Not):
                return Not(Or(self.cond, other.cond))

            if isinstance(other, Eq):
                return ~(self.cond | (other.a != other.b))

        return And(self, other)

    def __or__(self, other):
        """
            >>> print Bit("a", 1) | Bit("b", 2)
            (a | b)
        """
        return Or(self, other)

    def __eq__(self, other):
        """
            >>> print Bit("a", 1) == Bit("b", 2)
            (a == b)
        """
        return Eq(self, other)

    def __ne__(self, other):
        """
            >>> print Bit("a", 1) != Bit("b", 2)
            (a ^ b)
        """
        return Xor(self, other)

    def __invert__(self):
        """
            >>> a = Bit("a", 1)
            >>> print ~a
            ~a
            >>> print ~~a
            a
        """
        if isinstance(self, Not):
            return self.cond

        return Not(self)


class Bit(Condition):
    """A Bit of a register."""
    def __init__(self, name, bit):
        self.name = name
        self.bit = 1 << bit

    def __str__(self): return self.name

    def is_sat(self, register, _other):
        """
            >>> a = Bit("a", 1)
            >>> a.is_sat(3, 0), a.is_sat(1, 0)
            (True, False)
        """
        return (self.bit & register) is not 0


def unary(fmt, check_sat):
    """
    Class creation utility function.
    Creates a unary condition combinator from
    a format string `fmt` and a unary `check_sat` function.
    """
    class Unary(Condition):
        def __init__(self, cond):
            self.cond = cond

        def __str__(self): return fmt.format(self.cond)

        def is_sat(self, register, _other):
            return check_sat(self.cond.is_sat(register, _other))

    return Unary


def binary(fmt, check_sat):
    """
    Class creation utility function.
    Creates a binary condition combinator from
    a format string `fmt` and a binary `check_sat` function.
    """
    class Binary(Condition):
        def __init__(self, a, b):
            self.a = a
            self.b = b

        def __str__(self): return fmt.format(self.a, self.b)

        def is_sat(self, register, _other):
            return check_sat(
                self.a.is_sat(register, _other),
                self.b.is_sat(register, _other))

    return Binary


# TODO: Check if the Eq class is valid.
# Should Eq(a, b) be implemented as Not(Xor(a, b))?
Not = unary("~{}",         __not__)
Eq  = binary("({} == {})", __eq__)
Xor = binary("({} ^ {})",  __xor__)
Or  = binary("({} | {})",  __or__)
And = binary("({} & {})",  __and__)
