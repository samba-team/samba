# Create schema.ldif from Github markdown
#
# Each LDF section in the markdown file then gets written to a corresponding
# .LDF output file.
#
# Copyright (C) Andrew Bartlett 2017
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

from __future__ import print_function
"""Generate LDIF from Github documentation."""

import re
import os
import markdown
import xml.etree.ElementTree as ET


def innertext(tag):
    return (tag.text or '') + \
            ''.join(innertext(e) for e in tag) + \
            (tag.tail or '')


def read_ms_markdown(in_file, out_folder):
    """Read Github documentation-derived schema files."""

    with open(in_file) as update_file:
        # Remove any comments from the raw LDF files
        html = markdown.markdown(re.sub(r'(?m)^# .*\n?', '', update_file.read()),
                                 output_format='xhtml')

    tree = ET.fromstring('<root>' + html + '</root>')

    ldf = None
    try:
        for node in tree:
            if node.tag == 'h3':
                if ldf is not None:
                    ldf.close()

                out_path = os.path.join(out_folder, innertext(node).strip())
                ldf = open(out_path, 'w')
            elif node.tag == 'p' and ldf is not None:
                ldf.write(innertext(node).replace('```', '') + '\n')
    finally:
        if ldf is not None:
            ldf.close()


if __name__ == '__main__':
    import sys

    out_folder = ''

    if len(sys.argv) == 0:
        print("Usage: %s <Schema-Update.md> [<output folder>]" % (sys.argv[0]), file=sys.stderr)
        sys.exit(1)

    in_file = sys.argv[1]
    if len(sys.argv) > 2:
        out_folder = sys.argv[2]

    read_ms_markdown(in_file, out_folder)
