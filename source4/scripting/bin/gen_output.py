#!/usr/bin/env python3

# Copyright (C) Catalyst IT Ltd. 2017
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

"""
A data generator to help tests.

Generate large output to stdout by repeating input data.
Usage:

    python gen_output.py --data @ --repeat 1024 --retcode 1

The above command will output @ x 1024 (1K) and exit with 1.
"""

import sys
import argparse

parser = argparse.ArgumentParser(description='Generate output data')

parser.add_argument(
    '--data', type=str, default='$',
    help='Characters used to generate data by repeating them'
)

parser.add_argument(
    '--repeat', type=int, default=1024 * 1024,
    help='How many times to repeat the data'
)

parser.add_argument(
    '--retcode', type=int, default=0,
    help='Specify the exit code for this script'
)

args = parser.parse_args()

sys.stdout.write(args.data * args.repeat)

sys.exit(args.retcode)
