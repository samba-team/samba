#! /usr/bin/python

# Comfychair test cases for Samba string functions.

# Copyright (C) 2003 by Martin Pool <mbp@samba.org>
# 
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; either version 2 of the
# License, or (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
# USA

import sys, re, comfychair

def signum(a):
    if a < 0:
        return -1
    elif a > 0:
        return +1
    else:
        return 0
    

class StrCaseCmp_Ascii_Tests(comfychair.TestCase):
    """String comparisons in simple ASCII""" 
    def run_strcmp(self, a, b, expect):
        out = self.runcmd('t_strcmp \"%s\" \"%s\"' % (a, b))
        if signum(int(out)) != expect:
            self.fail("comparison failed:\n"
                      "  a=%s\n"
                      "  b=%s\n"
                      "  expected=%s\n"
                      "  result=%s\n" % (`a`, `b`, `expect`, `out`))

    def runtest(self):
        cases = [('hello', 'hello', 0),
                 ('hello', 'goodbye', +1),
                 ('goodbye', 'hello', -1),
                 ('hell', 'hello', -1)]
        for a, b, expect in cases:
            self.run_strcmp(a, b, expect)
        

tests = [StrCaseCmp_Ascii_Tests]

if __name__ == '__main__':
    comfychair.main(tests)

