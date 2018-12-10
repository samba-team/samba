#!/usr/bin/env python3

#
# Unix SMB/CIFS implementation.
#
# Utility methods for generating error codes from a file.
#
# Copyright (C) Noel Power <noel.power@suse.com> 2014
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
#

# error data model
class ErrorDef:
    def __init__(self):
        self.err_code = None
        self.err_define = None
        self.err_string = ""
        self.linenum = ""

def escapeString( input ):
    output = input.replace('"','\\"')
    output = output.replace("\\<","\\\\<")
    output = output.replace('\t',"")
    return output

# Parse error descriptions from a file which is the content
# of an HTML table.
# The file must be formatted as:
# [error code hex]
# [error name short]
# [error description]
# Blank lines are allowed and errors do not have to have a
# description.
# Returns a list of ErrorDef objects.
def parseErrorDescriptions( file_contents, isWinError, transformErrorFunction ):
    errors = []
    count = 0
    for line in file_contents:
        if line == None or line == '\t' or line == "" or line == '\n':
            continue
        content = line.strip().split(None,1)
        # start new error definition ?
        if line.startswith("0x"):
            newError = ErrorDef()
            newError.err_code = int(content[0],0)
            # escape the usual suspects
            if len(content) > 1:
                newError.err_string = escapeString(content[1])
            newError.linenum = count
            newError.isWinError = isWinError
            errors.append(newError)
        else:
            if len(errors) == 0:
                continue
            err = errors[-1]
            if err.err_define == None:
                err.err_define = transformErrorFunction(content[0])
            else:
                if len(content) > 0:
                    desc =  escapeString(line.strip())
                    if len(desc):
                        if err.err_string == "":
                            err.err_string = desc
                        else:
                            err.err_string = err.err_string + " " + desc
            count = count + 1
    print("parsed %d lines generated %d error definitions"%(count,len(errors)))
    return errors

