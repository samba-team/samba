#!/usr/bin/env python

#
# Unix SMB/CIFS implementation.
#
# HRESULT Error definitions
#
# Copyright (C) Noel Power <noel.power@suse.com> 2014
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

import sys, os.path, io, string

# parsed error data
Errors = []
# error definitions to output
ErrorsToUse = []
ErrorsToCreatDescFor = []

# some lookup dictionaries
DefineToErrCode = {};
ErrCodeToDefine = {};

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

def transformErrorName( error_name ):
    new_name = error_name
    if error_name.startswith("STATUS_"):
        error_name = error_name.replace("STATUS_","",1)
    elif error_name.startswith("RPC_NT_"):
        error_name = error_name.replace("RPC_NT_","RPC_",1)
    elif error_name.startswith("EPT_NT_"):
        error_name = error_name.replace("EPT_NT_","EPT_",1)
    new_name = "NT_STATUS_" + error_name
    return new_name

def parseErrorDescriptions( file_contents, isWinError ):
    count = 0
    for line in file_contents:
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
            Errors.append(newError)
        else:
            if len(Errors) == 0:
                print "Error parsing file as line %d"%count
                sys.exit()
            err = Errors[-1]
            if err.err_define == None:    
                err.err_define = transformErrorName(content[0])
        else:
            if len(content) > 0:
                desc =  escapeString(line.strip())
                if len(desc):
                    if err.err_string == "":
                        err.err_string = desc
                    else:
                        err.err_string = err.err_string + " " + desc
        count = count + 1
    print "parsed %d lines generated %d error definitions"%(count,len(Errors))

def parseErrCodeString(error_code_string):
    # we could develop this more and *really* parse it but realistically 
    # we are only interested in NT_STATUS( mask | code ) or NT_STATUS( code )
    parts = error_code_string.split('|',1)
    code = None
    try:
        if len(parts) > 1:
            if len(parts) > 2: #something weird, better warn
                print "warning something weird unexpected errorcode format ->%s<-"%error_code_string
            code = int(parts[0],0) | int(parts[1],0)
        else:
            code = int(error_code_string,0)
    except:
        pass
    return code

def parseHeaderFile(file_contents):
    count = 0
    for line in file_contents:
        contents = line.strip().split(None,2)
        err_code_string = None
        err_code = None

        if len(contents) > 2:
            if contents[0] == "#define" and contents[2].startswith("NT_STATUS("):
                # hairy parsing of lines like
                # "#define SOMETHING NT_STATUS( num1 | num2 )" etc...
                err_code_string = contents[2].split('(')[1].split(')')[0]
                err_code = parseErrCodeString( err_code_string ) 
                if  err_code != None:
                    const_define = contents[1]
#                    print "%s 0x%x"%(const_define, err_code)
                    DefineToErrCode[const_define] = err_code
                    ErrCodeToDefine[err_code] = const_define
                else:
                    print "warning: failed to process line[%d] ->%s<-"%(count,line)
        count = count + 1
    print "read %d error declarations from header file"%len(ErrCodeToDefine)

def generateHeaderFile(out_file):
    out_file.write("\n\n")
    out_file.write("/*\n")
    out_file.write(" * New descriptions for new errors generated from\n")
    out_file.write(" * [MS-ERREF] http://msdn.microsoft.com/en-us/library/cc704588.aspx\n")
    out_file.write(" */\n\n")
    for err in ErrorsToUse:
        line = "#define {0:49} NT_STATUS(0x{1:08X})\n".format(err.err_define ,err.err_code)
        out_file.write(line)


def generateSourceFile(out_file):
    out_file.write("/*\n")
    out_file.write(" * New descriptions for existing errors generated from\n")
    out_file.write(" * [MS-ERREF] http://msdn.microsoft.com/en-us/library/cc704588.aspx\n")
    out_file.write(" */\n")
    for err in ErrorsToCreatDescFor:
	out_file.write("	{ N_(\"%s\"), %s },\n"%(err.err_string, err.err_define))
    out_file.write("\n\n")
    out_file.write("/*\n")
    out_file.write(" * New descriptions for new errors generated from\n")
    out_file.write(" * [MS-ERREF] http://msdn.microsoft.com/en-us/library/cc704588.aspx\n")
    out_file.write(" */\n")
    for err in ErrorsToUse:
	out_file.write("	{ N_(\"%s\"), %s },\n"%(err.err_string, err.err_define))
    out_file.write("\n\n");
    out_file.write("/*\n")
    out_file.write(" * New descriptions for new errors generated from\n")
    out_file.write(" * [MS-ERREF] http://msdn.microsoft.com/en-us/library/cc704588.aspx\n")
    out_file.write(" */\n")
    for err in ErrorsToUse:
	out_file.write("	{ \"%s\", %s },\n"%(err.err_define, err.err_define))

def def_in_list(define, err_def_with_desc):
    for item in err_def_with_desc:
        if item.strip() == define:
            return True
    return False

def processErrorDescription(err_def_with_desc):
    print "processing error descriptions...."
    count = 0 
    for err in Errors:
        # do we have an error with this error code  already ?
        if ErrCodeToDefine.has_key(err.err_code):
            already_has_desc = def_in_list(ErrCodeToDefine[err.err_code], err_def_with_desc)
            # no 'full' error description for this error code so create a new
            # one
            if already_has_desc == False:
                # synthesise a new Error object to create desc from
                new_error = ErrorDef()
                new_error.err_define =  ErrCodeToDefine[err.err_code]
                new_error.err_code = err.err_code
                new_error.err_string = err.err_string
                new_error.linenum = err.linenum
                ErrorsToCreatDescFor.append(new_error)
            count = count + 1
        else:
           ErrorsToUse.append(err) 
    if count > 0:
        print "skipped %d existing definitions"%count
    print "imported %d new error definitions"%(len(ErrorsToUse))
    print "created %d new error descriptions for existing errors"%(len(ErrorsToCreatDescFor))

# Very simple script to generate files ntstatus.c & ntstatus.h, these
# files contain generated content used to add to the existing content
# of files nterr.c & ntstatus.h. 
# The script takes 3 inputs
# 1. location of the existing ntstatus.h (which is used to build a list of
#     existing error defines
# 2. a text file, format which is very simple and is just the content of a 
#    html table ( such as that found in
#    http://msdn.microsoft.com/en-us/library/cc231200.aspx ) copied and
#    pasted into a text file
# 3. finally a text file containing names of the error defines (1 per line)
#    that already are in ntstatus.h/nterr.c but that only have the 'short'
#    error description ( short error description is where the description is
#    the name of the error itself e.g. "NT_STATUS_SUCCESS" etc.

def main ():
    input_file1 = None;
    input_file2 = None;
    filename = "ntstatus"
    headerfile_name = filename + ".h"
    sourcefile_name = filename + ".c"
    if len(sys.argv) > 3:
        input_file1 =  sys.argv[1]
        input_file2 =  sys.argv[2]
        input_file3 =  sys.argv[3]
    else:
        print "usage: %s headerfile winerrorfile existing_short_descs"%(sys.argv[0])
        sys.exit()

    # read in the data
    file_contents = open(input_file1,"r")
    parseHeaderFile(file_contents)
    file_contents = open(input_file2,"r")
    parseErrorDescriptions(file_contents, False)
    file_contents = open(input_file3,"r")
    has_already_desc = file_contents.readlines()
    processErrorDescription(has_already_desc)
    out_file = open(headerfile_name,"w")
    generateHeaderFile(out_file)
    out_file.close()
    out_file = open(sourcefile_name,"w")
    generateSourceFile(out_file)
    out_file.close()

if __name__ == '__main__':

    main()
