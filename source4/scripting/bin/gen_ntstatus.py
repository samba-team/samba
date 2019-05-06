#!/usr/bin/env python3

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
from __future__ import unicode_literals
# this file is a bin script and was not imported by any other modules
# so it should be fine to enable unicode string for python2

import sys, os.path, io, string
from gen_error_common import parseErrorDescriptions, ErrorDef

def generateHeaderFile(out_file, errors):
    out_file.write("/*\n")
    out_file.write(" * Descriptions for errors generated from\n")
    out_file.write(" * [MS-ERREF] http://msdn.microsoft.com/en-us/library/cc704588.aspx\n")
    out_file.write(" */\n\n")
    out_file.write("#ifndef _NTSTATUS_GEN_H\n")
    out_file.write("#define _NTSTATUS_GEN_H\n")
    for err in errors:
        line = "#define %s NT_STATUS(%#x)\n" % (err.err_define, err.err_code)
        out_file.write(line)
    out_file.write("\n#endif /* _NTSTATUS_GEN_H */\n")

def generateSourceFile(out_file, errors):
    out_file.write("/*\n")
    out_file.write(" * Names for errors generated from\n")
    out_file.write(" * [MS-ERREF] http://msdn.microsoft.com/en-us/library/cc704588.aspx\n")
    out_file.write(" */\n")

    out_file.write("static const nt_err_code_struct nt_errs[] = \n")
    out_file.write("{\n")
    for err in errors:
        out_file.write("\t{ \"%s\", %s },\n" % (err.err_define, err.err_define))
    out_file.write("{ 0, NT_STATUS(0) }\n")
    out_file.write("};\n")

    out_file.write("\n/*\n")
    out_file.write(" * Descriptions for errors generated from\n")
    out_file.write(" * [MS-ERREF] http://msdn.microsoft.com/en-us/library/cc704588.aspx\n")
    out_file.write(" */\n")

    out_file.write("static const nt_err_code_struct nt_err_desc[] = \n")
    out_file.write("{\n")
    for err in errors:
        # Account for the possibility that some errors may not have descriptions
        if err.err_string == "":
            continue
        out_file.write("\t{ N_(\"%s\"), %s },\n"%(err.err_string, err.err_define))
    out_file.write("{ 0, NT_STATUS(0) }\n")
    out_file.write("};")

def generatePythonFile(out_file, errors):
    out_file.write("/*\n")
    out_file.write(" * New descriptions for existing errors generated from\n")
    out_file.write(" * [MS-ERREF] http://msdn.microsoft.com/en-us/library/cc704588.aspx\n")
    out_file.write(" */\n")
    out_file.write("#include <Python.h>\n")
    out_file.write("#include \"python/py3compat.h\"\n")
    out_file.write("#include \"includes.h\"\n\n")
    # This is needed to avoid a missing prototype error from the C
    # compiler. There is never a prototype for this function, it is a
    # module loaded by python with dlopen() and found with dlsym().
    out_file.write("static struct PyModuleDef moduledef = {\n")
    out_file.write("\tPyModuleDef_HEAD_INIT,\n")
    out_file.write("\t.m_name = \"ntstatus\",\n")
    out_file.write("\t.m_doc = \"NTSTATUS error defines\",\n")
    out_file.write("\t.m_size = -1,\n")
    out_file.write("};\n\n")
    out_file.write("MODULE_INIT_FUNC(ntstatus)\n")
    out_file.write("{\n")
    out_file.write("\tPyObject *m;\n\n")
    out_file.write("\tm = PyModule_Create(&moduledef);\n");
    out_file.write("\tif (m == NULL)\n");
    out_file.write("\t\treturn NULL;\n\n");
    for err in errors:
        line = """\tPyModule_AddObject(m, \"%s\", 
                  \t\tPyLong_FromUnsignedLongLong(NT_STATUS_V(%s)));\n""" % (err.err_define, err.err_define)
        out_file.write(line)
    out_file.write("\n");
    out_file.write("\treturn m;\n");
    out_file.write("}\n");

def transformErrorName( error_name ):
    if error_name.startswith("STATUS_"):
        error_name = error_name.replace("STATUS_", "", 1)
    elif error_name.startswith("RPC_NT_"):
        error_name = error_name.replace("RPC_NT_", "RPC_", 1)
    elif error_name.startswith("EPT_NT_"):
        error_name = error_name.replace("EPT_NT_", "EPT_", 1)
    return "NT_STATUS_" + error_name

# Very simple script to generate files nterr_gen.c & ntstatus_gen.h.
# These files contain generated definitions.
# This script takes four inputs:
# [1]: The name of the text file which is the content of an HTML table
#      (e.g. the one found at http://msdn.microsoft.com/en-us/library/cc231200.aspx)
#      copied and pasted.
# [2]: The name of the output generated header file with NTStatus #defines
# [3]: The name of the output generated source file with C arrays
# [4]: The name of the output generated python file
def main ():
    input_file = None;

    if len(sys.argv) == 5:
        input_file =  sys.argv[1]
        gen_headerfile_name = sys.argv[2]
        gen_sourcefile_name = sys.argv[3]
        gen_pythonfile_name = sys.argv[4]
    else:
        print("usage: %s winerrorfile headerfile sourcefile pythonfile" % (sys.argv[0]))
        sys.exit()

    # read in the data
    file_contents = io.open(input_file, "rt", encoding='utf8')

    errors = parseErrorDescriptions(file_contents, False, transformErrorName)

    print("writing new header file: %s" % gen_headerfile_name)
    out_file = io.open(gen_headerfile_name, "wt", encoding='utf8')
    generateHeaderFile(out_file, errors)
    out_file.close()
    print("writing new source file: %s" % gen_sourcefile_name)
    out_file = io.open(gen_sourcefile_name, "wt", encoding='utf8')
    generateSourceFile(out_file, errors)
    out_file.close()
    print("writing new python file: %s" % gen_pythonfile_name)
    out_file = io.open(gen_pythonfile_name, "wt", encoding='utf8')
    generatePythonFile(out_file, errors)
    out_file.close()

if __name__ == '__main__':

    main()
