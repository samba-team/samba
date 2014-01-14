# Unix SMB/CIFS implementation.
# Copyright (C) 2014 Catalyst.Net Ltd
#
# Auto generate param_functions.c
#
#   ** NOTE! The following LGPL license applies to the ldb
#   ** library. This does NOT imply that all of Samba is released
#   ** under the LGPL
#
#  This library is free software; you can redistribute it and/or
#  modify it under the terms of the GNU Lesser General Public
#  License as published by the Free Software Foundation; either
#  version 3 of the License, or (at your option) any later version.
#
#  This library is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#  Lesser General Public License for more details.
#
#  You should have received a copy of the GNU Lesser General Public
#  License along with this library; if not, see <http://www.gnu.org/licenses/>.
#

import errno
import os
import re
import subprocess
import xml.etree.ElementTree as ET
import sys
import optparse

# parse command line arguments
parser = optparse.OptionParser()
parser.add_option("-f", "--file", dest="filename",
                  help="input file", metavar="FILE")
parser.add_option("-o", "--output", dest="output",
                  help='output file', metavar="FILE")
parser.add_option("--mode", type="choice", metavar="<FUNCTIONS>",
                 choices=["FUNCTIONS"], default="FUNCTIONS")

(options, args) = parser.parse_args()

if options.filename is None:
    parser.error("No input file specified")
if options.output is None:
    parser.error("No output file specified")

def iterate_all(path):
    """Iterate and yield all the parameters. 

    :param path: path to parameters xml file
    """

    try:
        p = open(path, 'r')
    except IOError, e:
        raise Exception("Error opening parameters file")
    out = p.read()

    # parse the parameters xml file
    root = ET.fromstring(out)
    for parameter in root:
        name = parameter.attrib.get("name")
        param_type = parameter.attrib.get("type")
        context = parameter.attrib.get("context")
        func = parameter.attrib.get("function")
        synonym = parameter.attrib.get("synonym")
        removed = parameter.attrib.get("removed")
        generated = parameter.attrib.get("generated_function")
        if synonym == "1" or removed == "1" or generated == "0":
            continue
        constant = parameter.attrib.get("constant")
        parm = parameter.attrib.get("parm")
        if name is None or param_type is None or context is None:
            raise Exception("Error parsing parameter: " + name)
        if func is None:
            func = name.replace(" ", "_").lower()
        yield {'name': name,
               'type': param_type,
               'context': context,
               'function': func,
               'constant': (constant == '1'),
               'parm': (parm == '1')}

# map doc attributes to a section of the generated function
context_dict = {"G": "_GLOBAL", "S": "_LOCAL"}
param_type_dict = {"boolean": "_BOOL", "list": "_LIST", "string": "_STRING",
                   "integer": "_INTEGER", "enum": "_INTEGER", "char" : "_CHAR",
                   "boolean-auto": "_INTEGER"}

f = open(options.output, 'w')

try:
    for parameter in iterate_all(options.filename):
        # filter out parameteric options
        if ':' in parameter['name']:
            continue
        output_string = "FN"
        temp = context_dict.get(parameter['context'])
        if temp is None: 
            raise Exception(parameter['name'] + " has an invalid context " + parameter['context'])
        output_string += temp
        if parameter['constant']:
            output_string += "_CONST"
        if parameter['parm']: 
            output_string += "_PARM"
        temp = param_type_dict.get(parameter['type'])
        if temp is None:
            raise Exception(parameter['name'] + " has an invalid param type " + parameter['type'])
        output_string += temp
        f.write(output_string + "(" + parameter['function'] +", " + parameter['function'] + ')\n')
finally:
    f.close()
